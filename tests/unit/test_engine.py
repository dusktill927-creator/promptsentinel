"""Engine behaviour: the gate, failure isolation, timeouts, and capability skipping."""

from __future__ import annotations

import asyncio

import pytest

from promptsentinel.core.authorization import REQUIRED_ATTESTATION, Authorization
from promptsentinel.core.errors import AuthorizationError, TargetError
from promptsentinel.core.models import ProbeCategory, ProbeResult, ProbeStatus
from promptsentinel.engine.runner import ScanEngine, ScanPlan
from promptsentinel.probes.base import Probe, ProbeContext
from promptsentinel.targets.base import Target, TargetCapability
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.spec import MockTargetSpec

AUTHORIZATION = Authorization(confirmed=True, attested_by="tester", statement=REQUIRED_ATTESTATION)


class GoodProbe(Probe):
    id = "test.good"
    name = "Good"
    category = ProbeCategory.DIAGNOSTIC
    description = "Completes."

    async def run(self, target: Target, context: ProbeContext) -> ProbeResult:
        context.mint("seeded")
        return ProbeResult.completed(self.id, [], attempts=1)


class CrashingProbe(Probe):
    id = "test.crash"
    name = "Crash"
    category = ProbeCategory.DIAGNOSTIC
    description = "Raises an unexpected error."

    async def run(self, target: Target, context: ProbeContext) -> ProbeResult:
        raise RuntimeError("probe bug")


class TargetFailingProbe(Probe):
    id = "test.target_error"
    name = "Target error"
    category = ProbeCategory.DIAGNOSTIC
    description = "The target is unreachable."

    async def run(self, target: Target, context: ProbeContext) -> ProbeResult:
        raise TargetError("connection refused")


class SlowProbe(Probe):
    id = "test.slow"
    name = "Slow"
    category = ProbeCategory.DIAGNOSTIC
    description = "Never finishes."

    async def run(self, target: Target, context: ProbeContext) -> ProbeResult:
        await asyncio.sleep(30)
        return ProbeResult.completed(self.id, [])


class ToolProbe(Probe):
    id = "test.needs_tools"
    name = "Needs tools"
    category = ProbeCategory.EXCESSIVE_AGENCY
    description = "Requires a capability the target lacks."
    required_capabilities = frozenset({TargetCapability.TOOL_CALLING})

    async def run(self, target: Target, context: ProbeContext) -> ProbeResult:
        return ProbeResult.completed(self.id, [])


class ChatOnlyTarget(MockTarget):
    capabilities = frozenset({TargetCapability.CHAT})


@pytest.fixture
def target() -> MockTarget:
    return MockTarget(MockTargetSpec())


def plan(*probes, authorization=AUTHORIZATION) -> ScanPlan:
    return ScanPlan(scan_id="s1", authorization=authorization, probes=list(probes))


class TestAuthorizationGate:
    async def test_engine_refuses_a_forged_attestation(self, target):
        """Second line of defense, independent of the HTTP layer."""
        forged = Authorization.model_construct(
            confirmed=False, attested_by="", statement="nope", reference=None
        )
        engine = ScanEngine()
        with pytest.raises(AuthorizationError):
            await engine.run(plan(GoodProbe, authorization=forged), target)

    async def test_refusal_happens_before_the_target_is_contacted(self, target):
        forged = Authorization.model_construct(
            confirmed=False, attested_by="", statement="nope", reference=None
        )
        with pytest.raises(AuthorizationError):
            await ScanEngine().run(plan(GoodProbe, authorization=forged), target)
        assert target.transcript == []


class TestFailureIsolation:
    async def test_a_crashing_probe_does_not_abort_the_scan(self, target):
        outcome = await ScanEngine().run(plan(CrashingProbe, GoodProbe), target)
        by_id = {r.probe_id: r for r in outcome.results}
        assert by_id["test.crash"].status is ProbeStatus.ERRORED
        assert by_id["test.good"].status is ProbeStatus.COMPLETED

    async def test_a_crash_is_reported_as_errored_not_clean(self, target):
        """The dangerous failure mode is reporting a broken probe as 'found nothing'."""
        outcome = await ScanEngine().run(plan(CrashingProbe), target)
        result = outcome.results[0]
        assert result.status is ProbeStatus.ERRORED
        assert result.findings == []
        assert "probe bug" in (result.error or "")

    async def test_target_errors_are_reported_with_their_message(self, target):
        outcome = await ScanEngine().run(plan(TargetFailingProbe), target)
        assert "connection refused" in (outcome.results[0].error or "")

    async def test_a_hung_probe_times_out(self, target):
        engine = ScanEngine(probe_timeout_s=0.05)
        outcome = await engine.run(plan(SlowProbe), target)
        assert outcome.results[0].status is ProbeStatus.TIMED_OUT


class TestCapabilitySkipping:
    async def test_probe_is_skipped_with_a_reason(self, target):
        chat_only = ChatOnlyTarget(MockTargetSpec())
        outcome = await ScanEngine().run(plan(ToolProbe), chat_only)
        result = outcome.results[0]
        assert result.status is ProbeStatus.SKIPPED
        assert "tool_calling" in (result.detail or "")

    async def test_skipped_is_distinguishable_from_clean(self, target):
        """'Did not run' and 'ran and found nothing' must never look the same."""
        chat_only = ChatOnlyTarget(MockTargetSpec())
        outcome = await ScanEngine().run(plan(ToolProbe, GoodProbe), chat_only)
        statuses = {r.probe_id: r.status for r in outcome.results}
        assert statuses["test.needs_tools"] is ProbeStatus.SKIPPED
        assert statuses["test.good"] is ProbeStatus.COMPLETED


class TestBookkeeping:
    async def test_canaries_are_collected_across_probes(self, target):
        outcome = await ScanEngine().run(plan(GoodProbe), target)
        assert len(outcome.canaries) == 1
        assert outcome.canaries[0].label == "seeded"

    async def test_duration_is_recorded(self, target):
        outcome = await ScanEngine().run(plan(GoodProbe), target)
        assert outcome.results[0].duration_ms >= 0

    async def test_concurrency_is_bounded(self, target):
        """The target is someone's production app. We must not flood it."""
        concurrent = 0
        peak = 0

        class CountingProbe(Probe):
            id = "test.counting"
            name = "Counting"
            category = ProbeCategory.DIAGNOSTIC
            description = "Tracks overlap."

            async def run(self, t: Target, c: ProbeContext) -> ProbeResult:
                nonlocal concurrent, peak
                concurrent += 1
                peak = max(peak, concurrent)
                await asyncio.sleep(0.01)
                concurrent -= 1
                return ProbeResult.completed(self.id, [])

        engine = ScanEngine(max_concurrent_probes=2)
        await engine.run(plan(*[CountingProbe] * 6), target)
        assert peak <= 2
