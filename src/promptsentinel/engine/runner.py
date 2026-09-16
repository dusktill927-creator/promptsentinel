"""The scan engine.

Responsibilities, and nothing else: enforce authorization, decide which probes apply,
run them with bounded concurrency and a per-probe timeout, and isolate their failures.

It imports no probe by name -- only the registry's output -- which is what makes the
plugin architecture real rather than aspirational.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from promptsentinel.core.authorization import Authorization
from promptsentinel.core.budget import track_deadline
from promptsentinel.core.canary import Canary
from promptsentinel.core.errors import AuthorizationError, PromptSentinelError
from promptsentinel.core.models import ProbeResult
from promptsentinel.probes.base import Probe, ProbeContext
from promptsentinel.targets.base import Target

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanPlan:
    """Everything needed to run a scan.

    ``authorization`` is typed as :class:`Authorization`, not ``bool`` and not
    ``Authorization | None``. Because that class cannot be constructed without a valid
    attestation, an unauthorized scan is not something this engine can be *asked* to
    perform -- the gate is in the type system, checked before the code runs.
    """

    scan_id: str
    authorization: Authorization
    probes: list[type[Probe]]
    options: dict[str, dict[str, object]] = field(default_factory=dict)


@dataclass
class ScanOutcome:
    """Results plus the audit trail of what was seeded."""

    results: list[ProbeResult]
    canaries: list[Canary]

    @property
    def findings_count(self) -> int:
        return sum(len(r.findings) for r in self.results)


class ScanEngine:
    """Runs a :class:`ScanPlan` against one target."""

    def __init__(self, *, max_concurrent_probes: int = 4, probe_timeout_s: float = 60.0):
        self._semaphore = asyncio.Semaphore(max_concurrent_probes)
        self._probe_timeout_s = probe_timeout_s

    async def run(self, plan: ScanPlan, target: Target) -> ScanOutcome:
        """Execute every applicable probe.

        Raises:
            AuthorizationError: if the attestation does not survive re-validation.
                This happens before a single byte is sent to the target.
        """
        self._assert_authorized(plan)

        canaries: list[Canary] = []
        tasks = [self._run_one(probe_cls, target, plan, canaries) for probe_cls in plan.probes]
        results = await asyncio.gather(*tasks)
        return ScanOutcome(results=list(results), canaries=canaries)

    def _assert_authorized(self, plan: ScanPlan) -> None:
        """Second, independent check of the gate.

        The API layer already refused unauthorized requests. This re-check exists
        because the engine is also importable as a library and callable from the CLI,
        and because a single check is a single point of failure for the one control
        that keeps this tool ethical.
        """
        plan.authorization.verify()
        if not plan.authorization.confirmed:
            raise AuthorizationError("refusing to scan: authorization was not confirmed")

    async def _run_one(
        self,
        probe_cls: type[Probe],
        target: Target,
        plan: ScanPlan,
        canaries: list[Canary],
    ) -> ProbeResult:
        probe = probe_cls()

        skip_reason = probe.applies_to(target)
        if skip_reason is not None:
            logger.info("scan=%s probe=%s skipped: %s", plan.scan_id, probe.id, skip_reason)
            return ProbeResult.skipped(probe.id, skip_reason)

        # One shared canary list, per-probe options: the scan needs the complete
        # record of what was seeded, but each probe gets only its own configuration.
        context = ProbeContext(
            scan_id=plan.scan_id,
            canaries=canaries,
            options=dict(plan.options.get(probe.id, {})),
        )

        async with self._semaphore:
            started = time.perf_counter()
            try:
                async with asyncio.timeout(self._probe_timeout_s) as deadline:
                    # The budget measures the target's responsiveness. Time the probe
                    # spends queued behind our own rate limiter is given back, so a
                    # conservatively paced scan does not report timeouts that never
                    # happened.
                    with track_deadline(deadline):
                        result = await probe.run(target, context)
            except TimeoutError:
                logger.warning("scan=%s probe=%s timed out", plan.scan_id, probe.id)
                return ProbeResult.timed_out(probe.id, self._probe_timeout_s)
            except PromptSentinelError as exc:
                logger.warning("scan=%s probe=%s failed: %s", plan.scan_id, probe.id, exc)
                return ProbeResult.errored(probe.id, str(exc))
            except Exception as exc:
                # A bug in one probe must not cost the operator the whole scan. It is
                # reported as ERRORED, never as a clean pass.
                logger.exception("scan=%s probe=%s crashed", plan.scan_id, probe.id)
                return ProbeResult.errored(probe.id, f"{type(exc).__name__}: {exc}")
            duration_ms = int((time.perf_counter() - started) * 1000)

        return result.model_copy(update={"duration_ms": duration_ms})
