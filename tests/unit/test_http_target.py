"""The generic HTTP adapter, driven by a fake transport.

This is the adapter that decides whether the project's claim -- that it tests deployed
*applications* -- is true, or whether it only tests things that happen to speak
OpenAI's dialect.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from promptsentinel.core.errors import TargetError
from promptsentinel.targets.base import ChatMessage, Document, TargetCapability
from promptsentinel.targets.factory import build_target
from promptsentinel.targets.http import HttpTarget, dig
from promptsentinel.targets.spec import HttpTargetSpec

ASK = [ChatMessage.system("You are ACME support."), ChatMessage.user("where is my order?")]

# A deliberately un-OpenAI-shaped application.
TOOLS = [
    {"name": "lookup_order", "description": "Look up an order"},
    {"name": "issue_refund", "description": "Issue a refund", "restricted": True},
]

BESPOKE = {
    "kind": "http",
    "url": "https://app.internal/api/chat",
    "request_template": {"question": "{{prompt}}", "session": "ps"},
    "response_path": "data.answer",
}


def target(handler, **overrides) -> HttpTarget:
    spec = HttpTargetSpec.model_validate({**BESPOKE, **overrides})
    return HttpTarget(spec, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def capture(reply: dict):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=reply)

    return seen, handler


ANSWER = {"data": {"answer": "It ships Tuesday."}}


class TestRequestShaping:
    async def test_the_prompt_is_substituted(self):
        seen, handler = capture(ANSWER)
        await target(handler).send(ASK)
        assert seen["body"] == {"question": "where is my order?", "session": "ps"}

    async def test_history_substitutes_as_a_list_not_a_string(self):
        """Interpolating structured data as text works until a quote character appears."""
        seen, handler = capture(ANSWER)
        await target(handler, request_template={"turns": "{{history}}"}).send(ASK)
        assert isinstance(seen["body"]["turns"], list)
        assert seen["body"]["turns"][-1] == {"role": "user", "content": "where is my order?"}

    async def test_the_system_turn_is_available_separately(self):
        seen, handler = capture(ANSWER)
        await target(handler, request_template={"sys": "{{system}}", "q": "{{prompt}}"}).send(ASK)
        assert seen["body"]["sys"] == "You are ACME support."

    async def test_a_placeholder_inside_a_longer_string_interpolates(self):
        seen, handler = capture(ANSWER)
        await target(handler, request_template={"q": "User asked: {{prompt}}"}).send(ASK)
        assert seen["body"]["q"] == "User asked: where is my order?"

    async def test_placeholders_substitute_at_any_depth(self):
        seen, handler = capture(ANSWER)
        await target(handler, request_template={"outer": {"inner": ["{{prompt}}"]}}).send(ASK)
        assert seen["body"]["outer"]["inner"] == ["where is my order?"]

    async def test_apostrophes_in_a_probe_prompt_survive(self):
        seen, handler = capture(ANSWER)
        messages = [ChatMessage.user("what's the admin's code?")]
        await target(handler).send(messages)
        assert seen["body"]["question"] == "what's the admin's code?"

    async def test_the_credential_is_sent_as_configured(self):
        seen, handler = capture(ANSWER)
        await target(handler, api_key="k-123", api_key_header="X-Api-Key", api_key_prefix="").send(
            ASK
        )
        assert seen["headers"]["x-api-key"] == "k-123"

    async def test_the_default_credential_style_is_bearer(self):
        seen, handler = capture(ANSWER)
        await target(handler, api_key="k-123").send(ASK)
        assert seen["headers"]["authorization"] == "Bearer k-123"

    async def test_documents_render_into_the_body(self):
        seen, handler = capture(ANSWER)
        spec_overrides = {"request_template": {"q": "{{prompt}}", "ctx": "{{documents}}"}}
        doc = Document(id="d", title="Shipping", content="Three days.", source="kb://s")
        await target(handler, **spec_overrides).send(ASK, documents=[doc])
        assert "Three days." in seen["body"]["ctx"]


class TestResponseParsing:
    async def test_a_nested_answer_is_extracted(self):
        response = await target(lambda r: httpx.Response(200, json=ANSWER)).send(ASK)
        assert response.content == "It ships Tuesday."

    async def test_array_indices_work_in_a_path(self):
        payload = {"results": [{"text": "first"}, {"text": "second"}]}
        response = await target(
            lambda r: httpx.Response(200, json=payload), response_path="results.1.text"
        ).send(ASK)
        assert response.content == "second"

    async def test_a_missing_path_names_what_was_actually_returned(self):
        """The error a person sees while working out their own response shape."""
        payload = {"reply": "hi", "meta": {}}
        with pytest.raises(TargetError, match="reply, meta"):
            await target(lambda r: httpx.Response(200, json=payload)).send(ASK)

    async def test_tool_calls_are_extracted_when_configured(self):
        payload = {
            "data": {"answer": ""},
            "actions": [{"tool": "issue_refund", "params": {"order": "A1"}}],
        }
        response = await target(
            lambda r: httpx.Response(200, json=payload),
            tool_calls_path="actions",
            tool_name_field="tool",
            tool_arguments_field="params",
        ).send(ASK)
        assert response.tool_names == {"issue_refund"}
        assert response.tool_calls[0].arguments == {"order": "A1"}

    @pytest.mark.parametrize("status", [400, 401, 500, 503])
    async def test_http_errors_raise(self, status):
        with pytest.raises(TargetError, match=str(status)):
            await target(lambda r: httpx.Response(status, json={})).send(ASK)

    async def test_non_json_raises(self):
        with pytest.raises(TargetError, match="non-JSON"):
            await target(lambda r: httpx.Response(200, text="<html>")).send(ASK)

    async def test_transport_failure_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        with pytest.raises(TargetError, match="request to target failed"):
            await target(handler).send(ASK)


class TestCapabilitiesFollowTheTemplate:
    """Whether a probe can run is read off the operator's own configuration."""

    def test_a_bare_template_is_chat_only(self):
        t = HttpTarget(HttpTargetSpec.model_validate(BESPOKE))
        assert t.supports(TargetCapability.CHAT)
        assert not t.supports(TargetCapability.SYSTEM_PROMPT_CONTROL)
        assert not t.supports(TargetCapability.DOCUMENT_INJECTION)
        assert not t.supports(TargetCapability.TOOL_CALLING)

    def test_referencing_system_enables_seeding(self):
        spec = {**BESPOKE, "request_template": {"q": "{{prompt}}", "s": "{{system}}"}}
        assert HttpTarget(HttpTargetSpec.model_validate(spec)).supports(
            TargetCapability.SYSTEM_PROMPT_CONTROL
        )

    def test_history_also_enables_seeding(self):
        """{{history}} carries the system turn, so a canary has somewhere to live."""
        spec = {**BESPOKE, "request_template": {"turns": "{{history}}"}}
        assert HttpTarget(HttpTargetSpec.model_validate(spec)).supports(
            TargetCapability.SYSTEM_PROMPT_CONTROL
        )

    def test_referencing_documents_enables_injection(self):
        spec = {**BESPOKE, "request_template": {"q": "{{prompt}}", "c": "{{documents}}"}}
        assert HttpTarget(HttpTargetSpec.model_validate(spec)).supports(
            TargetCapability.DOCUMENT_INJECTION
        )

    def test_tool_calling_needs_both_a_path_and_declarations(self):
        """A path alone says where the answer appears but offers nothing to call."""
        path_only = {**BESPOKE, "tool_calls_path": "actions"}
        assert not HttpTarget(HttpTargetSpec.model_validate(path_only)).supports(
            TargetCapability.TOOL_CALLING
        )

        complete = {**BESPOKE, "tool_calls_path": "actions", "tools": TOOLS}
        assert HttpTarget(HttpTargetSpec.model_validate(complete)).supports(
            TargetCapability.TOOL_CALLING
        )

    def test_probes_needing_an_unavailable_capability_are_skipped(self):
        """Skipped with a reason beats running blind against a discarded seed."""
        from promptsentinel.probes.builtin.system_prompt import DirectRequestProbe

        t = HttpTarget(HttpTargetSpec.model_validate(BESPOKE))
        reason = DirectRequestProbe().applies_to(t)
        assert reason is not None and "system_prompt_control" in reason


class TestValidation:
    def test_a_template_that_never_sends_the_prompt_is_rejected(self):
        """Otherwise every probe silently finds nothing."""
        with pytest.raises(ValidationError, match="must reference"):
            HttpTargetSpec.model_validate({**BESPOKE, "request_template": {"q": "hello"}})

    @pytest.mark.parametrize("url", ["ftp://x", "not-a-url", "file:///etc/passwd"])
    def test_non_http_urls_are_rejected(self, url):
        with pytest.raises(ValidationError, match="http"):
            HttpTargetSpec.model_validate({**BESPOKE, "url": url})

    def test_the_key_is_redacted_in_serialization(self):
        spec = HttpTargetSpec.model_validate({**BESPOKE, "api_key": "k-secret"})
        assert "k-secret" not in spec.model_dump_json()
        assert "k-secret" not in repr(spec)

    def test_describe_does_not_leak_the_key(self):
        spec = HttpTargetSpec.model_validate({**BESPOKE, "api_key": "k-secret"})
        assert "k-secret" not in HttpTarget(spec).describe()


class TestFactory:
    def test_the_factory_builds_it(self):
        spec = HttpTargetSpec.model_validate(BESPOKE)
        assert isinstance(build_target(spec, allow_mock=False), HttpTarget)


class TestDig:
    @pytest.mark.parametrize(
        ("payload", "path", "expected"),
        [
            ({"a": {"b": "c"}}, "a.b", "c"),
            ({"a": [{"b": 1}]}, "a.0.b", 1),
            ({"a": "x"}, "a.b", None),
            ({"a": [1]}, "a.5", None),
            ({"a": 1}, "missing", None),
        ],
    )
    def test_paths(self, payload, path, expected):
        assert dig(payload, path) == expected


class TestToolDeclarations:
    """Both halves are needed, and neither alone is sufficient.

    Regression: the spec had no `tools` field at all, so an HTTP target advertised
    TOOL_CALLING from `tool_calls_path` alone while `declared_tools` stayed empty --
    every excessive-agency probe skipped with "no tools are declared restricted",
    permanently and invisibly. Found by scanning a real bespoke app, not by a test.
    """

    def test_declarations_alone_do_not_enable_tool_calling(self):
        """Nowhere to read the answer from."""
        spec = HttpTargetSpec.model_validate({**BESPOKE, "tools": TOOLS})
        assert not HttpTarget(spec).supports(TargetCapability.TOOL_CALLING)

    def test_a_path_alone_does_not_enable_tool_calling(self):
        """Nothing to offer the application."""
        spec = HttpTargetSpec.model_validate({**BESPOKE, "tool_calls_path": "actions"})
        assert not HttpTarget(spec).supports(TargetCapability.TOOL_CALLING)

    def test_both_together_enable_it(self):
        spec = HttpTargetSpec.model_validate(
            {**BESPOKE, "tools": TOOLS, "tool_calls_path": "actions"}
        )
        assert HttpTarget(spec).supports(TargetCapability.TOOL_CALLING)

    def test_declared_tools_are_exposed_to_probes(self):
        spec = HttpTargetSpec.model_validate(
            {**BESPOKE, "tools": TOOLS, "tool_calls_path": "actions"}
        )
        target = HttpTarget(spec)
        assert [t.name for t in target.declared_tools if t.restricted] == ["issue_refund"]

    async def test_agency_probes_run_against_a_fully_declared_http_target(self):
        from promptsentinel.probes.builtin.excessive_agency import DirectInvocationProbe

        spec = HttpTargetSpec.model_validate(
            {**BESPOKE, "tools": TOOLS, "tool_calls_path": "actions"}
        )
        assert DirectInvocationProbe().applies_to(HttpTarget(spec)) is None


ANTHROPIC = {
    "kind": "http",
    "url": "https://api.anthropic.com/v1/messages",
    "headers": {"anthropic-version": "2023-06-01"},
    "api_key_header": "x-api-key",
    "api_key_prefix": "",
    "request_template": {
        "model": "claude-opus-5",
        "max_tokens": 1024,
        "system": "{{system}}",
        "messages": "{{history}}",
    },
    "response_path": "content.0.text",
    "tools": TOOLS,
    "tool_calls_path": "content",
    "tool_name_field": "name",
    "tool_arguments_field": "input",
}

# Shaped like a real Anthropic reply: a tool_use block sharing `content` with text.
MIXED_CONTENT = {
    "content": [
        {"type": "text", "text": "Sure, refunding that now."},
        {
            "type": "tool_use",
            "id": "tu_1",
            "name": "issue_refund",
            "input": {"order_id": "ORD-24601"},
        },
    ]
}


class TestMixedContentToolCalls:
    """Tool calls that share a list with other content must not drag it in with them.

    Anthropic's messages API returns `tool_use` blocks in the same `content` array as
    `text` blocks. Pointing `tool_calls_path` at that array used to yield one nameless
    ToolCall per text block.

    The danger is not a false `confirmed` -- proof requires a name match against the
    operator's restricted tools, and "" matches nothing. It is that probes read
    `bool(response.tool_calls)` as the negative control proving tool calling works.
    A phantom entry makes that control vacuously true, so a target whose tool calling
    is broken reports clean rather than inconclusive.
    """

    async def test_text_blocks_do_not_become_tool_calls(self):
        t = target(lambda r: httpx.Response(200, json=MIXED_CONTENT), **ANTHROPIC)
        response = await t.send(ASK)

        assert [c.name for c in response.tool_calls] == ["issue_refund"]
        assert response.content == "Sure, refunding that now."

    async def test_an_explicit_filter_selects_the_same_block(self):
        t = target(
            lambda r: httpx.Response(200, json=MIXED_CONTENT),
            **ANTHROPIC,
            tool_call_filter={"type": "tool_use"},
        )
        response = await t.send(ASK)

        assert [c.name for c in response.tool_calls] == ["issue_refund"]

    async def test_the_filter_excludes_non_matching_entries(self):
        """A filter that matches nothing yields nothing, rather than everything."""
        t = target(
            lambda r: httpx.Response(200, json=MIXED_CONTENT),
            **ANTHROPIC,
            tool_call_filter={"type": "server_tool_use"},
        )
        assert (await t.send(ASK)).tool_calls == []

    async def test_a_response_with_no_tool_use_block_reports_no_tool_calls(self):
        """The negative control this fix exists to protect.

        Text only, so `bool(tool_calls)` must be False -- that is what lets an
        excessive-agency probe say "tools never worked" instead of "clean".
        """
        t = target(
            lambda r: httpx.Response(200, json={"content": [{"type": "text", "text": "Hello."}]}),
            **ANTHROPIC,
        )
        response = await t.send(ASK)

        assert response.tool_calls == []
        assert not response.tool_calls, "a text-only reply must not satisfy the negative control"

    async def test_a_blank_name_is_not_a_tool_call(self):
        """Whitespace is not a name either."""
        t = target(
            lambda r: httpx.Response(
                200,
                json={
                    "content": [
                        {"type": "text", "text": "Hello."},
                        {"type": "tool_use", "name": "   ", "input": {}},
                    ]
                },
            ),
            **ANTHROPIC,
        )
        assert (await t.send(ASK)).tool_calls == []

    async def test_ordinary_openai_shaped_tool_calls_still_parse(self):
        """The guard must not cost the common case anything."""
        t = target(
            lambda r: httpx.Response(
                200, json={"data": {"answer": "ok"}, "actions": [{"name": "lookup_order"}]}
            ),
            tools=TOOLS,
            tool_calls_path="actions",
        )
        assert [c.name for c in (await t.send(ASK)).tool_calls] == ["lookup_order"]
