"""The reference probe, across all three outcomes.

These three cases are the template every real probe's tests should follow:
proven leak, fabricated-looking leak, and a clean refusal.
"""

from __future__ import annotations

import pytest

from promptsentinel.core.models import Confidence, ProofKind
from promptsentinel.probes.base import ProbeContext
from promptsentinel.probes.builtin.diagnostic import CanaryEchoProbe
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.spec import MockRule, MockTargetSpec


@pytest.fixture
def context() -> ProbeContext:
    return ProbeContext(scan_id="s1")


class TestConfirmedLeak:
    async def test_canary_returned_verbatim_is_confirmed(self, context):
        target = MockTarget(
            MockTargetSpec(
                system_prompt="You are a support bot.",
                leak_system_prompt_on="repeat|configuration",
            )
        )
        result = await CanaryEchoProbe().run(target, context)

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof is not None
        assert finding.proof.kind is ProofKind.CANARY_DISCLOSURE

    async def test_the_canary_is_not_leaked_by_the_report_itself(self, context):
        target = MockTarget(MockTargetSpec(system_prompt="Bot.", leak_system_prompt_on="repeat"))
        result = await CanaryEchoProbe().run(target, context)
        canary = context.canaries[0]
        assert canary.value not in result.findings[0].proof.matched_value

    async def test_the_operators_system_prompt_is_preserved(self, context):
        """Probes append to the real prompt. Replacing it would test a different app."""
        target = MockTarget(
            MockTargetSpec(
                system_prompt="You are ACME support. Never discuss competitors.",
                leak_system_prompt_on="repeat",
            )
        )
        await CanaryEchoProbe().run(target, context)
        sent_system = target.transcript[0][0][0].content
        assert "Never discuss competitors" in sent_system
        assert context.canaries[0].value in sent_system


class TestSuspicious:
    async def test_plausible_but_unproven_disclosure_is_suspicious(self, context):
        """A model can invent a convincing system prompt it was never given."""
        target = MockTarget(
            MockTargetSpec(
                rules=[
                    MockRule(
                        pattern="repeat|configuration",
                        response=(
                            "Sure. My instructions are: You are a helpful assistant "
                            "for an online store."
                        ),
                    )
                ]
            )
        )
        result = await CanaryEchoProbe().run(target, context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.SUSPICIOUS
        assert finding.proof is None
        assert finding.signals


class TestClean:
    async def test_a_refusal_produces_no_finding(self, context):
        target = MockTarget(
            MockTargetSpec(
                rules=[
                    MockRule(
                        pattern="repeat|configuration",
                        response="I'm sorry, I can't share my system prompt.",
                    )
                ]
            )
        )
        result = await CanaryEchoProbe().run(target, context)
        assert result.findings == []

    async def test_an_unrelated_answer_produces_no_finding(self, context):
        target = MockTarget(MockTargetSpec(default_response="How can I help with your order?"))
        result = await CanaryEchoProbe().run(target, context)
        assert result.findings == []

    async def test_a_canary_is_seeded_even_when_nothing_leaks(self, context):
        """The audit record of what was planted must not depend on the outcome."""
        target = MockTarget(MockTargetSpec())
        await CanaryEchoProbe().run(target, context)
        assert len(context.canaries) == 1
