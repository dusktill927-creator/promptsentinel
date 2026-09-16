"""Document injection: the target-side groundwork for indirect prompt injection.

Two things are being checked. That retrieved context is rendered the way the *operator*
described rather than the way we assume -- and that a target whose retrieval setup was
never described does not claim to be a RAG target, because a probe that silently skips
is safer than one that reports a clean result for an attack path it never exercised.
"""

from __future__ import annotations

import json

import httpx
import pytest

from promptsentinel.targets.base import ChatMessage, Document, TargetCapability
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.openai_compatible import OpenAICompatibleTarget
from promptsentinel.targets.spec import (
    MockTargetSpec,
    OpenAICompatibleTargetSpec,
    RetrievalConfig,
)

DOC = Document(
    id="d1", title="Shipping policy", content="Orders ship in 3 days.", source="kb://ship"
)
ASK = [ChatMessage.system("You are support."), ChatMessage.user("When does my order ship?")]


def openai_target(handler, **spec_kwargs) -> OpenAICompatibleTarget:
    spec = OpenAICompatibleTargetSpec(base_url="https://x.test/v1", model="m", **spec_kwargs)
    return OpenAICompatibleTarget(
        spec, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )


def capture():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    return seen, handler


class TestCapabilityGating:
    def test_without_retrieval_config_it_is_not_a_rag_target(self):
        """Guessing where retrieved text lands would test the wrong application."""
        target = openai_target(lambda r: httpx.Response(200))
        assert not target.supports(TargetCapability.DOCUMENT_INJECTION)

    def test_with_retrieval_config_it_is(self):
        target = openai_target(lambda r: httpx.Response(200), retrieval=RetrievalConfig())
        assert target.supports(TargetCapability.DOCUMENT_INJECTION)

    def test_other_capabilities_are_unaffected(self):
        target = openai_target(lambda r: httpx.Response(200))
        assert target.supports(TargetCapability.TOOL_CALLING)
        assert target.supports(TargetCapability.SYSTEM_PROMPT_CONTROL)

    def test_the_mock_mirrors_the_same_rule(self):
        assert not MockTarget(MockTargetSpec()).supports(TargetCapability.DOCUMENT_INJECTION)
        assert MockTarget(MockTargetSpec(retrieval=RetrievalConfig())).supports(
            TargetCapability.DOCUMENT_INJECTION
        )


class TestRendering:
    async def test_context_is_inserted_before_the_final_user_turn(self):
        """Where essentially every RAG implementation puts it."""
        seen, handler = capture()
        await openai_target(handler, retrieval=RetrievalConfig()).send(ASK, documents=[DOC])

        roles = [m["role"] for m in seen["body"]["messages"]]
        contents = [m["content"] for m in seen["body"]["messages"]]
        assert roles == ["system", "user", "user"]
        assert "Orders ship in 3 days." in contents[1]
        assert contents[2] == "When does my order ship?"

    async def test_the_operators_templates_are_used(self):
        seen, handler = capture()
        retrieval = RetrievalConfig(
            role="system",
            document_template="<doc src={source}>{content}</doc>",
            context_template="KNOWLEDGE:\n{documents}",
        )
        await openai_target(handler, retrieval=retrieval).send(ASK, documents=[DOC])

        injected = seen["body"]["messages"][1]
        assert injected["role"] == "system"
        assert injected["content"] == "KNOWLEDGE:\n<doc src=kb://ship>Orders ship in 3 days.</doc>"

    async def test_multiple_documents_are_numbered(self):
        seen, handler = capture()
        second = DOC.model_copy(update={"id": "d2", "title": "Returns"})
        await openai_target(handler, retrieval=RetrievalConfig()).send(ASK, documents=[DOC, second])

        injected = seen["body"]["messages"][1]["content"]
        assert "[1] Shipping policy" in injected
        assert "[2] Returns" in injected

    async def test_no_documents_means_no_extra_message(self):
        seen, handler = capture()
        await openai_target(handler, retrieval=RetrievalConfig()).send(ASK)
        assert len(seen["body"]["messages"]) == 2

    async def test_documents_are_ignored_without_retrieval_config(self):
        """Nothing is silently dropped into an unknown position in the prompt."""
        seen, handler = capture()
        await openai_target(handler).send(ASK, documents=[DOC])
        assert len(seen["body"]["messages"]) == 2


class TestMockDocumentBehaviour:
    async def test_it_records_what_it_was_given(self):
        target = MockTarget(MockTargetSpec(retrieval=RetrievalConfig()))
        await target.send(ASK, documents=[DOC])
        assert target.documents_seen[0][0].title == "Shipping policy"

    async def test_quoting_returns_the_document_verbatim(self):
        target = MockTarget(MockTargetSpec(retrieval=RetrievalConfig(), quote_documents=True))
        response = await target.send(ASK, documents=[DOC])
        assert "Orders ship in 3 days." in response.content

    async def test_emit_pattern_acts_on_document_content(self):
        target = MockTarget(
            MockTargetSpec(retrieval=RetrievalConfig(), document_emit_pattern=r"CODE:\s*(\S+)")
        )
        doc = DOC.model_copy(update={"content": "CODE: ABC-123"})
        response = await target.send(ASK, documents=[doc])
        assert response.content == "ABC-123"

    async def test_a_target_that_ignores_documents_falls_through(self):
        target = MockTarget(MockTargetSpec(retrieval=RetrievalConfig(), default_response="hi"))
        response = await target.send(ASK, documents=[DOC])
        assert response.content == "hi"

    @pytest.mark.parametrize("field", ["quote_documents", "document_emit_pattern"])
    async def test_document_behaviour_needs_documents(self, field):
        spec = MockTargetSpec(
            retrieval=RetrievalConfig(),
            default_response="hi",
            **{field: True if field == "quote_documents" else r"(\S+)"},
        )
        response = await MockTarget(spec).send(ASK)
        assert response.content == "hi"
