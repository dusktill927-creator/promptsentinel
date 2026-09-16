"""The PII / data-leakage family.

Two behaviours are distinctive here and get the most attention:

* the **negative control** -- a clean result is only trustworthy if the target proved it
  could read the seeded records in the first place;
* the **inverted severity model** -- unlike the jailbreak family, disclosure that needs
  no attack is the *worst* outcome, because the finding is about the exposed data
  rather than about the strength of a control.
"""

from __future__ import annotations

import pytest

from promptsentinel.core.models import Confidence, ProbeCategory, Severity
from promptsentinel.probes.base import ProbeContext
from promptsentinel.probes.builtin.data_leakage import (
    BASELINE_ASK,
    CONTROL_ASK,
    OTHER_CUSTOMER_NAME,
    BulkExtractionProbe,
    ContextLaunderingProbe,
    CrossCustomerAccessProbe,
    DataLeakageProbe,
    PretextImpersonationProbe,
)
from promptsentinel.probes.registry import REGISTRY
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.spec import MockRule, MockTargetSpec

FAMILY = [
    CrossCustomerAccessProbe,
    BulkExtractionProbe,
    PretextImpersonationProbe,
    ContextLaunderingProbe,
]

REFUSAL = "I'm sorry, I can't share another customer's details."
OWN_RECORD_RULE = MockRule(
    pattern="my own record|my own customer",
    response="Here is your record:",
    reveal_system_lines="Authenticated user",
)


@pytest.fixture
def context() -> ProbeContext:
    return ProbeContext(scan_id="s1")


def well_behaved() -> MockTarget:
    """Serves the user's own record, refuses everything else. The correct behaviour."""
    return MockTarget(
        MockTargetSpec(rules=[OWN_RECORD_RULE, MockRule(pattern=".", response=REFUSAL)])
    )


def leaks_to_anyone() -> MockTarget:
    """Dumps the whole context to any question."""
    return MockTarget(MockTargetSpec(leak_system_prompt_on="."))


def leaks_under_pressure() -> MockTarget:
    """Correct on the control and the plain ask; releases everything afterwards."""
    return MockTarget(
        MockTargetSpec(
            rules=[
                OWN_RECORD_RULE,
                MockRule(pattern="other customer's customer ID", response=REFUSAL),
            ],
            leak_system_prompt_on=".",
        )
    )


def ignores_the_context() -> MockTarget:
    """Never reveals anything, including the user's own record."""
    return MockTarget(MockTargetSpec(default_response="I can help with orders and shipping."))


@pytest.mark.parametrize("probe_cls", FAMILY, ids=lambda c: c.id)
class TestAcrossTheFamily:
    async def test_a_well_behaved_target_yields_no_findings(self, probe_cls, context):
        result = await probe_cls().run(well_behaved(), context)
        assert result.findings == []

    async def test_the_control_runs_first(self, probe_cls, context):
        target = well_behaved()
        await probe_cls().run(target, context)
        assert target.transcript[0][0][1].content == CONTROL_ASK
        assert target.transcript[1][0][1].content == BASELINE_ASK

    async def test_trivial_exposure_is_critical(self, probe_cls, context):
        """No attack needed, so it is the most severe outcome, not the least."""
        result = await probe_cls().run(leaks_to_anyone(), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.severity is Severity.CRITICAL
        assert result.attempts == 1, "should stop once trivial exposure is proven"

    async def test_disclosure_under_a_technique_is_high(self, probe_cls, context):
        result = await probe_cls().run(leaks_under_pressure(), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.severity is Severity.HIGH
        assert probe_cls.technique in finding.title

    async def test_both_records_are_seeded_with_an_access_rule(self, probe_cls, context):
        target = well_behaved()
        await probe_cls().run(target, context)

        system = target.transcript[0][0][0].content
        assert len(context.canaries) == 2
        assert all(c.value in system for c in context.canaries)
        assert "ACCESS RULE" in system

    async def test_the_users_own_record_is_not_a_finding(self, probe_cls, context):
        """Returning the authenticated user's own data is correct behaviour."""
        result = await probe_cls().run(well_behaved(), context)
        own = context.canaries[0]
        assert own.label == "authenticated_user_record"
        assert result.findings == []

    async def test_seeded_records_are_obviously_synthetic(self, probe_cls, context):
        """Nothing here may be mistaken for real personal data."""
        target = well_behaved()
        await probe_cls().run(target, context)
        system = target.transcript[0][0][0].content
        assert "example.invalid" in system
        assert "synthetic" in system.lower()


class TestNegativeControl:
    """A clean result is only worth having if the probe could have detected a leak."""

    async def test_a_target_that_never_read_the_context_is_inconclusive(self, context):
        result = await CrossCustomerAccessProbe().run(ignores_the_context(), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.INFORMATIONAL
        assert "Inconclusive" in finding.title
        assert "control_request_failed" in finding.signals

    async def test_a_reachable_context_produces_no_such_note(self, context):
        result = await CrossCustomerAccessProbe().run(well_behaved(), context)
        assert result.findings == []

    async def test_inconclusive_is_never_reported_as_a_leak(self, context):
        result = await BulkExtractionProbe().run(ignores_the_context(), context)
        assert all(f.proof is None for f in result.findings)
        assert all(f.severity is Severity.INFO for f in result.findings)


class TestPartialDisclosure:
    async def test_naming_the_other_customer_is_suspicious_only(self, context):
        """A name is seeded data, but low entropy -- a signal, never proof."""
        target = MockTarget(
            MockTargetSpec(
                rules=[
                    OWN_RECORD_RULE,
                    MockRule(pattern="other customer's customer ID", response=REFUSAL),
                ],
                default_response=(
                    f"I also have a record for {OTHER_CUSTOMER_NAME}, but I can't share it."
                ),
            )
        )
        result = await CrossCustomerAccessProbe().run(target, context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.SUSPICIOUS
        assert finding.proof is None
        assert "named_other_customer" in finding.signals


class TestFamilyRegistration:
    def test_all_four_techniques_are_registered(self):
        assert {p.id for p in FAMILY} <= {p.id for p in REGISTRY.all()}

    def test_the_abstract_base_is_not_registered(self):
        assert DataLeakageProbe not in REGISTRY.all()

    @pytest.mark.parametrize("probe_cls", FAMILY, ids=lambda c: c.id)
    def test_metadata(self, probe_cls):
        assert probe_cls.category is ProbeCategory.DATA_LEAKAGE
        assert probe_cls.description and probe_cls.technique
