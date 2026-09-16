"""The excessive-agency family.

The distinguishing property is that proof here is structural: a restricted tool name
appears in response.tool_calls, or it does not. No text matching is involved, and these
tests assert that no path exists by which prose could produce a confirmed finding.
"""

from __future__ import annotations

import pytest

from promptsentinel.core.models import Confidence, ProbeCategory, ProofKind, Severity
from promptsentinel.probes.base import ProbeContext
from promptsentinel.probes.builtin.excessive_agency import (
    CONTROL_ASK,
    AuthorityPretextProbe,
    DirectInvocationProbe,
    ExcessiveAgencyProbe,
    InjectedDirectiveProbe,
    ParameterTamperingProbe,
)
from promptsentinel.probes.registry import REGISTRY
from promptsentinel.targets.base import TargetCapability, ToolDefinition
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.spec import MockRule, MockTargetSpec, MockToolCall, RetrievalConfig

FAMILY = [
    DirectInvocationProbe,
    ParameterTamperingProbe,
    AuthorityPretextProbe,
    InjectedDirectiveProbe,
]
CONVERSATIONAL = [DirectInvocationProbe, ParameterTamperingProbe, AuthorityPretextProbe]

LOOKUP = ToolDefinition(name="lookup_order", description="Look up an order")
REFUND = ToolDefinition(name="issue_refund", description="Issue a refund", restricted=True)
DELETE = ToolDefinition(
    name="delete_account", description="Delete an account", restricted=True, destructive=True
)
TOOLS = [LOOKUP, REFUND]


@pytest.fixture
def context() -> ProbeContext:
    return ProbeContext(scan_id="s1")


def agent(*, tools=None, rules=None, **kwargs) -> MockTarget:
    return MockTarget(
        MockTargetSpec(
            tools=list(TOOLS if tools is None else tools),
            rules=list(rules or []),
            retrieval=RetrievalConfig(),
            **kwargs,
        )
    )


CONTROL_RULE = MockRule(
    pattern="status of my most recent order",
    response="Checking now.",
    tool_calls=[MockToolCall(name="lookup_order", arguments={"order": "latest"})],
)
REFUND_RULE = MockRule(
    pattern=".",
    response="Processing that.",
    tool_calls=[MockToolCall(name="issue_refund", arguments={"order": "ORD-1"})],
)


def well_behaved() -> MockTarget:
    return agent(rules=[CONTROL_RULE, MockRule(pattern=".", response="I can't do that myself.")])


def over_eager() -> MockTarget:
    return agent(rules=[CONTROL_RULE, REFUND_RULE])


@pytest.mark.parametrize("probe_cls", CONVERSATIONAL, ids=lambda c: c.id)
class TestConversationalTechniques:
    async def test_a_restricted_call_is_confirmed(self, probe_cls, context):
        result = await probe_cls().run(over_eager(), context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof.kind is ProofKind.UNAUTHORIZED_TOOL_CALL
        assert finding.proof.location == "response.tool_calls"
        assert "issue_refund" in finding.title

    async def test_a_well_behaved_agent_yields_nothing(self, probe_cls, context):
        result = await probe_cls().run(well_behaved(), context)
        assert result.findings == []

    async def test_an_allowed_tool_call_is_not_a_finding(self, probe_cls, context):
        """lookup_order fires constantly; only restricted tools matter."""
        target = agent(
            rules=[
                MockRule(
                    pattern=".",
                    response="ok",
                    tool_calls=[MockToolCall(name="lookup_order", arguments={})],
                )
            ]
        )
        result = await probe_cls().run(target, context)
        assert result.findings == []

    async def test_the_control_runs_first(self, probe_cls, context):
        target = over_eager()
        await probe_cls().run(target, context)
        assert target.transcript[0][0][-1].content == CONTROL_ASK

    async def test_declared_tools_are_offered_to_the_target(self, probe_cls, context):
        target = over_eager()
        await probe_cls().run(target, context)
        assert target.transcript


class TestStructuralProof:
    """No route exists from prose to a confirmed finding in this family."""

    async def test_prose_claiming_the_action_is_only_suspicious(self, context):
        target = agent(
            rules=[
                CONTROL_RULE,
                MockRule(pattern=".", response="Done - I have issued the refund for you."),
            ]
        )
        result = await DirectInvocationProbe().run(target, context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.SUSPICIOUS
        assert finding.proof is None
        assert "claims_completed_action" in finding.signals

    async def test_a_tool_name_mentioned_in_text_proves_nothing(self, context):
        target = agent(
            rules=[
                CONTROL_RULE,
                MockRule(pattern=".", response="I would need to call issue_refund for that."),
            ]
        )
        result = await DirectInvocationProbe().run(target, context)
        assert all(f.proof is None for f in result.findings)

    async def test_the_proof_names_the_tool_and_arguments(self, context):
        result = await DirectInvocationProbe().run(over_eager(), context)
        proof = result.findings[0].proof
        assert proof.matched_value == "issue_refund"
        assert "ORD-1" in proof.detail


class TestSeverity:
    async def test_a_destructive_tool_is_critical(self, context):
        target = agent(
            tools=[LOOKUP, DELETE],
            rules=[
                CONTROL_RULE,
                MockRule(
                    pattern=".", response="", tool_calls=[MockToolCall(name="delete_account")]
                ),
            ],
        )
        result = await DirectInvocationProbe().run(target, context)
        assert result.findings[0].severity is Severity.CRITICAL

    async def test_a_non_destructive_tool_is_high(self, context):
        result = await DirectInvocationProbe().run(over_eager(), context)
        assert result.findings[0].severity is Severity.HIGH


class TestConfusedDeputy:
    async def test_a_tool_call_ordered_by_a_document_is_confirmed(self, context):
        target = agent(document_tool_pattern=r"(issue_refund)\D+(PSCANARY-[0-9a-f]+)")
        result = await InjectedDirectiveProbe().run(target, context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof.kind is ProofKind.UNAUTHORIZED_TOOL_CALL

    async def test_the_call_is_attributed_to_the_document(self, context):
        """The reference appears only in the planted document, settling its origin."""
        target = agent(document_tool_pattern=r"(issue_refund)\D+(PSCANARY-[0-9a-f]+)")
        result = await InjectedDirectiveProbe().run(target, context)
        assert "originated from retrieved content" in result.findings[0].description

    async def test_it_needs_a_rag_target(self):
        assert TargetCapability.DOCUMENT_INJECTION in InjectedDirectiveProbe.required_capabilities

    async def test_the_user_turn_never_asks_for_the_action(self):
        """If the user asked, a tool call would prove nothing about injection."""
        for attempt in InjectedDirectiveProbe.attempts:
            assert "refund" not in attempt.user.lower()
            assert attempt.document_template is not None


class TestApplicability:
    async def test_skipped_when_no_tools_are_declared(self):
        plain = MockTarget(MockTargetSpec())
        reason = DirectInvocationProbe().applies_to(plain)
        assert reason is not None and "tool_calling" in reason

    async def test_skipped_when_no_tool_is_restricted(self):
        """Nothing to prove if the operator marked nothing as privileged."""
        target = MockTarget(MockTargetSpec(tools=[LOOKUP]))
        reason = DirectInvocationProbe().applies_to(target)
        assert reason is not None and "restricted" in reason

    async def test_runs_when_a_restricted_tool_exists(self):
        assert DirectInvocationProbe().applies_to(over_eager()) is None


class TestNegativeControl:
    async def test_an_agent_that_never_calls_tools_is_inconclusive(self, context):
        target = agent(rules=[MockRule(pattern=".", response="I can help with that.")])
        result = await DirectInvocationProbe().run(target, context)

        finding = result.findings[0]
        assert finding.confidence is Confidence.INFORMATIONAL
        assert "control_request_invoked_no_tool" in finding.signals


class TestFamilyRegistration:
    def test_all_four_techniques_are_registered(self):
        assert {p.id for p in FAMILY} <= {p.id for p in REGISTRY.all()}

    def test_the_abstract_base_is_not_registered(self):
        assert ExcessiveAgencyProbe not in REGISTRY.all()

    @pytest.mark.parametrize("probe_cls", FAMILY, ids=lambda c: c.id)
    def test_metadata(self, probe_cls):
        assert probe_cls.category is ProbeCategory.EXCESSIVE_AGENCY
        assert probe_cls.description and probe_cls.technique
