"""Multi-turn probes and the conversation machinery they need.

The property that matters is accumulation: each turn must carry the whole exchange,
including the target's own replies, because that is what the technique exploits. A
probe that resent only the latest question would be four single-shot probes wearing a
trench coat.
"""

from __future__ import annotations

import pytest

from promptsentinel.core.models import Confidence, ProbeCategory, ProofKind, Severity
from promptsentinel.probes.base import Conversation, ProbeContext
from promptsentinel.probes.builtin.jailbreak import BASELINE_ASK, PersonaCommitmentProbe
from promptsentinel.probes.builtin.system_prompt import CrescendoProbe
from promptsentinel.probes.registry import REGISTRY
from promptsentinel.targets.base import ChatMessage
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.spec import MockRule, MockTargetSpec

REFUSAL = "I'm sorry, I can't share that. It is against my configuration."


@pytest.fixture
def context() -> ProbeContext:
    return ProbeContext(scan_id="s1")


def holds_out(turns: int) -> MockTarget:
    """Refuses at first, discloses once enough turns have accumulated."""
    return MockTarget(MockTargetSpec(system_prompt="You are ACME support.", leak_after_turns=turns))


def never_yields() -> MockTarget:
    return MockTarget(MockTargetSpec(rules=[MockRule(pattern=".", response=REFUSAL)]))


class TestConversation:
    async def test_each_turn_carries_the_whole_history(self):
        """The mechanism. Without it there is no escalation, only repetition."""
        target = MockTarget(MockTargetSpec(default_response="sure"))
        conversation = Conversation(target, ChatMessage.system("You are a bot."))

        await conversation.say("first")
        await conversation.say("second")

        sent_on_second_turn = target.transcript[1][0]
        roles = [m.role for m in sent_on_second_turn]
        assert roles == ["system", "user", "assistant", "user"]
        assert sent_on_second_turn[1].content == "first"
        assert sent_on_second_turn[-1].content == "second"

    async def test_the_targets_own_replies_are_replayed_to_it(self):
        """A model can only be held to a position it can see itself having taken."""
        target = MockTarget(MockTargetSpec(default_response="I agree to the premise."))
        conversation = Conversation(target, ChatMessage.system("s"))

        await conversation.say("one")
        await conversation.say("two")

        assistant_turns = [m.content for m in target.transcript[1][0] if m.role == "assistant"]
        assert assistant_turns == ["I agree to the premise."]

    async def test_turns_are_counted(self):
        target = MockTarget(MockTargetSpec())
        conversation = Conversation(target, ChatMessage.system("s"))
        assert conversation.turns == 0
        await conversation.say("a")
        await conversation.say("b")
        assert conversation.turns == 2

    async def test_the_transcript_reads_as_a_conversation(self):
        target = MockTarget(MockTargetSpec(default_response="a reply"))
        conversation = Conversation(target, ChatMessage.system("secret system prompt"))
        await conversation.say("a question")

        transcript = conversation.transcript()
        assert "[user] a question" in transcript
        assert "[assistant] a reply" in transcript
        assert "secret system prompt" not in transcript, "system turn is not the exchange"


class TestCrescendo:
    async def test_a_target_that_caves_late_is_confirmed(self, context):
        result = await CrescendoProbe().run(holds_out(3), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof.kind is ProofKind.CANARY_DISCLOSURE
        assert "after 4 turns" in finding.title

    async def test_a_single_shot_probe_would_have_missed_it(self, context):
        """The point of the whole feature, asserted directly."""
        from promptsentinel.probes.builtin.system_prompt import DirectRequestProbe

        single = await DirectRequestProbe().run(holds_out(3), ProbeContext(scan_id="s"))
        multi = await CrescendoProbe().run(holds_out(3), context)

        assert single.findings == []
        assert multi.findings[0].confidence is Confidence.CONFIRMED

    async def test_it_stops_as_soon_as_the_target_gives_way(self, context):
        result = await CrescendoProbe().run(holds_out(1), context)
        assert result.attempts == 2
        assert len(CrescendoProbe.turns) > 2, "there were later turns it chose not to send"

    async def test_a_resistant_target_yields_nothing(self, context):
        result = await CrescendoProbe().run(never_yields(), context)
        assert result.findings == []

    async def test_the_evidence_is_the_whole_exchange(self, context):
        """A final question shown alone is unreadable; the setup is the finding."""
        result = await CrescendoProbe().run(holds_out(2), context)
        prompt = result.findings[0].evidence.prompt
        assert prompt.count("[user]") >= 3
        assert "[assistant]" in prompt

    async def test_the_turn_budget_is_respected(self, context):
        context.max_turns = 2
        result = await CrescendoProbe().run(never_yields(), context)
        assert result.attempts == 2

    def test_turns_escalate_rather_than_repeat(self):
        """Each turn is distinct, and the last leans on what was already conceded.

        That reference back is the mechanic: refusing it means contradicting a position
        the model visibly took. A final turn that stood alone would just be a direct
        request with extra steps.
        """
        assert len(set(CrescendoProbe.turns)) == len(CrescendoProbe.turns)
        assert "already" in CrescendoProbe.turns[-1].lower()


class TestPersonaCommitment:
    async def test_a_target_that_caves_in_persona_is_confirmed(self, context):
        """Baseline turn first, so the mock must hold out past it."""
        result = await PersonaCommitmentProbe().run(holds_out(3), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof.kind is ProofKind.POLICY_BYPASS_MARKER
        assert finding.severity is Severity.HIGH

    async def test_the_baseline_runs_before_the_persona(self, context):
        target = holds_out(99)
        await PersonaCommitmentProbe().run(target, context)
        assert target.transcript[0][0][-1].content == BASELINE_ASK

    async def test_an_unenforced_policy_is_not_called_a_bypass(self, context):
        leaks_immediately = MockTarget(MockTargetSpec(system_prompt="s", leak_system_prompt_on="."))
        result = await PersonaCommitmentProbe().run(leaks_immediately, context)
        finding = result.findings[0]
        assert "not enforced" in finding.title
        assert finding.severity is Severity.MEDIUM

    async def test_a_resistant_target_yields_nothing(self, context):
        result = await PersonaCommitmentProbe().run(never_yields(), context)
        assert result.findings == []

    async def test_the_baseline_conversation_is_separate_from_the_attack(self, context):
        """A persona must not be built on top of the baseline refusal."""
        target = holds_out(99)
        await PersonaCommitmentProbe().run(target, context)

        first_attack_turn = target.transcript[1][0]
        assert BASELINE_ASK not in [m.content for m in first_attack_turn]


class TestRegistration:
    @pytest.mark.parametrize(
        ("probe_cls", "category"),
        [
            (CrescendoProbe, ProbeCategory.SYSTEM_PROMPT_EXTRACTION),
            (PersonaCommitmentProbe, ProbeCategory.JAILBREAK),
        ],
        ids=lambda v: getattr(v, "id", str(v)),
    )
    def test_registered_in_the_right_category(self, probe_cls, category):
        assert probe_cls.id in {p.id for p in REGISTRY.all()}
        assert probe_cls.category is category
