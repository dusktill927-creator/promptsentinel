"""Repository: the only module that knows both the ORM and the domain.

Probes and the engine speak in :mod:`promptsentinel.core.models` types. The database
speaks in rows. Everything that translates between the two lives here, so swapping
SQLite for Postgres, or SQLAlchemy for something else, touches one file.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from promptsentinel.core.authorization import Authorization
from promptsentinel.core.canary import Canary
from promptsentinel.core.models import (
    Confidence,
    Evidence,
    Finding,
    ProbeCategory,
    ProbeResult,
    ProbeStatus,
    Proof,
    ScanStatus,
    Severity,
    utcnow,
)
from promptsentinel.db.models import FindingRow, ProbeRunRow, ScanRow
from promptsentinel.targets.spec import TargetSpec


class ScanRepository:
    """Data access for scans and their results."""

    def __init__(self, session: AsyncSession):
        self._session = session

    async def create_scan(
        self,
        *,
        target_spec: TargetSpec,
        target_description: str,
        authorization: Authorization,
        requested_probe_ids: Sequence[str],
        options: dict[str, Any],
        webhook_url: str | None,
    ) -> ScanRow:
        """Persist a new PENDING scan.

        ``model_dump(mode="json")`` is what redacts credentials: Pydantic renders
        ``SecretStr`` as ``'**********'`` in JSON mode, so an API key can never reach
        the database through this path even if someone adds a new secret field later.
        """
        scan = ScanRow(
            status=ScanStatus.PENDING.value,
            target_kind=target_spec.kind,
            target_description=target_description,
            target_spec_redacted=target_spec.model_dump(mode="json"),
            requested_probe_ids=list(requested_probe_ids),
            options=options,
            authorization_confirmed=authorization.confirmed,
            authorized_by=authorization.attested_by,
            authorization_statement=authorization.statement,
            authorization_reference=authorization.reference,
            authorized_at=authorization.attested_at,
            webhook_url=webhook_url,
        )
        self._session.add(scan)
        await self._session.flush()
        return scan

    async def get(self, scan_id: str) -> ScanRow | None:
        return await self._session.get(ScanRow, scan_id)

    async def list_recent(self, *, limit: int = 50, offset: int = 0) -> Sequence[ScanRow]:
        result = await self._session.execute(
            select(ScanRow).order_by(ScanRow.created_at.desc()).limit(limit).offset(offset)
        )
        return result.scalars().all()

    async def mark_running(self, scan_id: str, *, at: datetime | None = None) -> None:
        scan = await self._require(scan_id)
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = at or utcnow()

    async def mark_failed(self, scan_id: str, error: str) -> None:
        """Record a scan that could not complete.

        A failed scan is never given results. An empty finding list on a FAILED scan
        means "we do not know", and the report renders it that way.
        """
        scan = await self._require(scan_id)
        scan.status = ScanStatus.FAILED.value
        scan.error = error[:4000]
        scan.finished_at = utcnow()

    async def save_results(
        self,
        scan_id: str,
        results: Sequence[ProbeResult],
        canaries: Sequence[Canary],
    ) -> None:
        """Write probe runs and findings, then mark the scan COMPLETED."""
        scan = await self._require(scan_id)
        for result in results:
            self._session.add(
                ProbeRunRow(
                    scan_id=scan_id,
                    probe_id=result.probe_id,
                    status=result.status.value,
                    attempts=result.attempts,
                    duration_ms=result.duration_ms,
                    error=result.error,
                    detail=result.detail,
                    last_response=result.last_response,
                )
            )
            for finding in result.findings:
                self._session.add(_finding_row(scan_id, finding))

        scan.canaries_seeded = [
            {"id": c.id, "label": c.label, "placement": c.placement, "value": c.redacted}
            for c in canaries
        ]
        scan.status = ScanStatus.COMPLETED.value
        scan.finished_at = utcnow()

    async def set_webhook_status(self, scan_id: str, status: str) -> None:
        scan = await self._require(scan_id)
        scan.webhook_status = status[:50]

    async def _require(self, scan_id: str) -> ScanRow:
        scan = await self._session.get(ScanRow, scan_id)
        if scan is None:
            raise LookupError(f"scan {scan_id} not found")
        return scan


def finding_from_row(row: FindingRow) -> Finding:
    """Row -> domain finding.

    Reconstruction runs the domain validators, so a stored row that violates the
    confidence invariant -- ``confirmed`` with a null proof, say, written by a direct
    database edit -- raises here instead of being exported as a proven finding. The
    integrity rule is enforced on the way out as well as on the way in.
    """
    return Finding(
        id=row.id,
        probe_id=row.probe_id,
        category=ProbeCategory(row.category),
        title=row.title,
        description=row.description,
        severity=Severity(row.severity),
        confidence=Confidence(row.confidence),
        evidence=Evidence.model_validate(row.evidence),
        proof=Proof.model_validate(row.proof) if row.proof else None,
        signals=[str(signal) for signal in row.signals],
        created_at=row.created_at,
    )


def probe_result_from_row(row: ProbeRunRow, findings: Sequence[Finding]) -> ProbeResult:
    """Row -> domain probe result, carrying the findings that belong to it."""
    status = ProbeStatus(row.status)
    return ProbeResult(
        probe_id=row.probe_id,
        status=status,
        findings=list(findings) if status is ProbeStatus.COMPLETED else [],
        attempts=row.attempts,
        duration_ms=row.duration_ms,
        error=row.error,
        detail=row.detail,
        last_response=row.last_response,
    )


def _finding_row(scan_id: str, finding: Finding) -> FindingRow:
    """Domain finding -> row.

    ``proof`` is stored as JSON or NULL with no default. A NULL proof column and a
    ``confidence`` of ``confirmed`` is a state the domain model refuses to construct,
    so it can only appear if someone writes to this table by hand.
    """
    return FindingRow(
        id=finding.id,
        scan_id=scan_id,
        probe_id=finding.probe_id,
        category=finding.category.value,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        evidence=finding.evidence.model_dump(mode="json"),
        proof=finding.proof.model_dump(mode="json") if finding.proof else None,
        signals=list(finding.signals),
        created_at=finding.created_at,
    )
