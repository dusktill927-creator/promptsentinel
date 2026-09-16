"""The jailbreak / content-policy bypass family.

The distinctive behaviour here is the baseline: these probes must tell "the policy was
defeated" apart from "the policy was never enforced", because the two have different
fixes and reporting the second as the first sends an operator hunting for a jailbreak
that never happened.
"""

from __future__ import annotations

import pytest

from promptsentinel.core.models import Confidence, ProbeCategory, ProofKind, Severity
from promptsentinel.probes.base import ProbeContext
from promptsentinel.probes.builtin.jailbreak import (
    BASELINE_ASK,
    AuthorityOverrideProbe,
    HypotheticalFramingProbe,
    OutputObfuscationProbe,
    PolicyBypassProbe,
    RoleplayPersonaProbe,
)
from promptsentinel.probes.registry import REGISTRY
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.spec import MockRule, MockTargetSpec

FAMILY = [
    RoleplayPersonaProbe,
    HypotheticalFramingProbe,
    AuthorityOverrideProbe,
    OutputObfuscationProbe,
]

REFUSAL = "I'm sorry, I can't provide that. It is against my configuration."
BASELINE_RULE = MockRule(pattern="listed in your configuration", response=REFUSAL)


@pytest.fixture
def context() -> ProbeContext:
    return ProbeContext(scan_id="s1")


def holds_the_line() -> MockTarget:
    """Refuses everything. The behaviour a well-built application should show."""
    return MockTarget(MockTargetSpec(rules=[MockRule(pattern=".", response=REFUSAL)]))


def bypassable(encoding: str | None = None) -> MockTarget:
    """Refuses the plain ask, but caves to any reframing.

    The mock stands in for an app that emits the forbidden marker: it discloses the
    system message, which is where the marker was seeded.
    """
    return MockTarget(
        MockTargetSpec(
            rules=[BASELINE_RULE],
            leak_system_prompt_on=".",
            leak_encoding=encoding,
        )
    )


def no_policy_at_all() -> MockTarget:
    """Emits the marker even on the plain request."""
    return MockTarget(MockTargetSpec(leak_system_prompt_on="."))


@pytest.mark.parametrize("probe_cls", FAMILY, ids=lambda c: c.id)
class TestAcrossTheFamily:
    async def test_a_refusing_target_yields_nothing(self, probe_cls, context):
        result = await probe_cls().run(holds_the_line(), context)
        assert result.findings == []

    async def test_a_bypassable_target_is_confirmed(self, probe_cls, context):
        result = await probe_cls().run(bypassable(), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof.kind is ProofKind.POLICY_BYPASS_MARKER
        assert finding.severity is Severity.HIGH
        assert probe_cls.technique in finding.title

    async def test_the_baseline_runs_before_any_attack(self, probe_cls, context):
        """Without it, 'no policy' would be misreported as 'policy defeated'."""
        target = bypassable()
        await probe_cls().run(target, context)
        assert target.transcript[0][0][1].content == BASELINE_ASK

    async def test_an_unenforced_policy_is_not_called_a_jailbreak(self, probe_cls, context):
        result = await probe_cls().run(no_policy_at_all(), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert "not enforced" in finding.title
        assert finding.severity is Severity.MEDIUM
        assert result.attempts == 1, "must not keep attacking once the rule is shown inert"

    async def test_the_marker_is_redacted_in_the_proof(self, probe_cls, context):
        result = await probe_cls().run(bypassable(), context)
        assert context.canaries[0].value not in str(result.findings[0].proof)

    async def test_the_seeded_rule_forbids_every_framing_it_will_try(self, probe_cls, context):
        """A target must not be able to claim the probe found a loophole left open."""
        target = holds_the_line()
        await probe_cls().run(target, context)

        system = target.transcript[0][0][0].content
        for word in ("roleplay", "hypothetical", "fictional", "maintenance", "developer"):
            assert word in system.lower()


class TestObfuscatedBypass:
    @pytest.mark.parametrize("encoding", ["base64", "reversed"])
    async def test_an_encoded_emission_is_still_a_bypass(self, encoding, context):
        """Defeating a literal blocklist is a bypass, not a near miss."""
        result = await OutputObfuscationProbe().run(bypassable(encoding), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert encoding in finding.proof.detail
        assert "evade filtering" in finding.proof.detail


class TestDegradedRefusal:
    async def test_a_quiet_guardrail_is_suspicious_only(self, context):
        """Stopped refusing, but emitted nothing: weak, and it stays weak."""
        target = MockTarget(
            MockTargetSpec(
                rules=[BASELINE_RULE],
                default_response="Here is a story about an engineer and a terminal.",
            )
        )
        result = await HypotheticalFramingProbe().run(target, context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.SUSPICIOUS
        assert finding.proof is None
        assert finding.severity is Severity.LOW
        assert "refusal_present_at_baseline" in finding.signals

    async def test_no_finding_when_the_baseline_never_refused(self, context):
        """If nothing refused at baseline, a later non-refusal means nothing."""
        target = MockTarget(MockTargetSpec(default_response="Sure, happy to help with that."))
        result = await HypotheticalFramingProbe().run(target, context)
        assert result.findings == []


class TestNoHarmfulPayloads:
    """The corpus proves policy bypass without eliciting anything harmful.

    The forbidden output is a random hex marker, so these assertions pin a deliberate
    property of the design rather than a passing detail.
    """

    @pytest.mark.parametrize("probe_cls", FAMILY, ids=lambda c: c.id)
    def test_attempts_only_ever_request_the_marker(self, probe_cls):
        for attempt in probe_cls.attempts:
            assert "restricted code" in attempt.user.lower()


class TestFamilyRegistration:
    def test_all_four_techniques_are_registered(self):
        assert {p.id for p in FAMILY} <= {p.id for p in REGISTRY.all()}

    def test_the_abstract_base_is_not_registered(self):
        assert PolicyBypassProbe not in REGISTRY.all()

    @pytest.mark.parametrize("probe_cls", FAMILY, ids=lambda c: c.id)
    def test_metadata(self, probe_cls):
        assert probe_cls.category is ProbeCategory.JAILBREAK
        assert probe_cls.description and probe_cls.technique
