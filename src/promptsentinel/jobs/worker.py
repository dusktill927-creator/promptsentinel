"""The scan worker: one scan, start to finish.

This is the only place where persistence, target construction, the engine, and
webhooks meet. Keeping that composition in one class means the engine stays testable
without a database and the API stays testable without an engine.
"""

from __future__ import annotations

import asyncio
import logging

from promptsentinel.config import Settings
from promptsentinel.core.authorization import Authorization
from promptsentinel.db.models import ScanRow
from promptsentinel.db.repository import ScanRepository
from promptsentinel.db.session import Database
from promptsentinel.engine.runner import ScanEngine, ScanPlan
from promptsentinel.jobs import webhooks
from promptsentinel.probes.registry import REGISTRY, ProbeRegistry
from promptsentinel.targets.factory import build_target
from promptsentinel.targets.spec import TargetSpec

logger = logging.getLogger(__name__)


class ScanWorker:
    """Executes a persisted scan."""

    def __init__(
        self,
        database: Database,
        settings: Settings,
        *,
        registry: ProbeRegistry = REGISTRY,
    ):
        self._db = database
        self._settings = settings
        self._registry = registry

    async def execute(self, scan_id: str, target_spec: TargetSpec) -> None:
        """Run the scan and persist its outcome.

        Never raises for an expected failure: a scan that cannot run is a FAILED scan
        row with a reason, because a caller polling for status deserves an answer.
        """
        target = None
        try:
            async with self._db.session() as session:
                await ScanRepository(session).mark_running(scan_id)

            async with self._db.session() as session:
                scan = await ScanRepository(session).get(scan_id)
                if scan is None:
                    logger.error("scan=%s vanished before execution", scan_id)
                    return
                plan = self._build_plan(scan)

            target = build_target(target_spec, allow_mock=self._settings.allow_mock_targets)
            engine = ScanEngine(
                max_concurrent_probes=self._settings.max_concurrent_probes,
                probe_timeout_s=self._settings.probe_timeout_s,
            )
            async with asyncio.timeout(self._settings.scan_timeout_s):
                outcome = await engine.run(plan, target)

            async with self._db.session() as session:
                await ScanRepository(session).save_results(
                    scan_id, outcome.results, outcome.canaries
                )
            logger.info(
                "scan=%s completed probes=%d findings=%d",
                scan_id,
                len(outcome.results),
                outcome.findings_count,
            )
        except Exception as exc:
            # Includes PromptSentinelError (bad config, unreachable target, revoked
            # authorization) and TimeoutError from the scan budget. All of them are
            # recorded against the scan rather than re-raised into the task.
            await self._fail(scan_id, exc)
        finally:
            if target is not None:
                await target.aclose()

        await self._notify(scan_id)

    def _build_plan(self, scan: ScanRow) -> ScanPlan:
        """Rebuild the domain plan from the stored row.

        The attestation is reconstructed through :class:`Authorization`, so a scan row
        edited in the database to remove its authorization fails validation here and
        the scan refuses to run.
        """
        authorization = Authorization(
            confirmed=scan.authorization_confirmed,
            attested_by=scan.authorized_by,
            statement=scan.authorization_statement,
            reference=scan.authorization_reference,
            attested_at=scan.authorized_at,
        )
        probes = self._registry.select(probe_ids=list(scan.requested_probe_ids) or None)
        return ScanPlan(
            scan_id=scan.id,
            authorization=authorization,
            probes=probes,
            options=dict(scan.options),
        )

    async def _fail(self, scan_id: str, exc: BaseException) -> None:
        message = f"{type(exc).__name__}: {exc}"
        logger.warning("scan=%s failed: %s", scan_id, message)
        try:
            async with self._db.session() as session:
                await ScanRepository(session).mark_failed(scan_id, message)
        except Exception:
            logger.exception("scan=%s could not be marked failed", scan_id)

    async def _notify(self, scan_id: str) -> None:
        """Fire the completion webhook, if one was registered."""
        async with self._db.session() as session:
            scan = await ScanRepository(session).get(scan_id)
            if scan is None or not scan.webhook_url:
                return
            payload = {
                "event": "scan.completed",
                "scan_id": scan.id,
                "status": scan.status,
                "findings": {
                    "total": len(scan.findings),
                    "confirmed": sum(1 for f in scan.findings if f.confidence == "confirmed"),
                    "suspicious": sum(1 for f in scan.findings if f.confidence == "suspicious"),
                },
                "report_url": f"/v1/scans/{scan.id}/report",
            }
            url = scan.webhook_url

        status = await webhooks.deliver(
            url,
            payload,
            timeout_s=self._settings.webhook_timeout_s,
            max_attempts=self._settings.webhook_max_attempts,
        )
        async with self._db.session() as session:
            await ScanRepository(session).set_webhook_status(scan_id, status)
