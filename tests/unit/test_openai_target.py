"""The OpenAI-compatible adapter, driven by a fake transport.

No network, but the real request construction and response parsing.
"""

from __future__ import annotations

import httpx
import pytest

from promptsentinel.core.errors import TargetError
from promptsentinel.targets.base import ChatMessage, ToolSpec
from promptsentinel.targets.openai_compatible import OpenAICompatibleTarget
from promptsentinel.targets.spec import OpenAICompatibleTargetSpec

SPEC = OpenAICompatibleTargetSpec(
    base_url="https://api.example.com/v1", model="gpt-test", api_key="sk-secret-abc"
)
MESSAGES = [ChatMessage.system("You are a bot."), ChatMessage.user("hello")]


def target_with(handler) -> OpenAICompatibleTarget:
    return OpenAICompatibleTarget(
        SPEC, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )


def responds(body, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return handler


def completion(content="hi", tool_calls=None):
    message: dict = {"content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"choices": [{"message": message, "finish_reason": "stop"}]}


class TestRequestConstruction:
    async def test_posts_to_chat_completions(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            return httpx.Response(200, json=completion())

        await target_with(handler).send(MESSAGES)
        assert seen["url"] == "https://api.example.com/v1/chat/completions"

    async def test_sends_the_api_key_as_a_bearer_token(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json=completion())

        await target_with(handler).send(MESSAGES)
        assert seen["auth"] == "Bearer sk-secret-abc"

    async def test_sends_messages_verbatim(self):
        """A scanner that rewrites prompts is not testing what it claims to test."""
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json=completion())

        await target_with(handler).send(MESSAGES)
        assert seen["body"]["messages"] == [
            {"role": "system", "content": "You are a bot."},
            {"role": "user", "content": "hello"},
        ]

    async def test_tools_are_sent_in_openai_function_format(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json=completion())

        tool = ToolSpec(name="refund", description="Issue a refund")
        await target_with(handler).send(MESSAGES, tools=[tool])
        assert seen["body"]["tools"][0]["function"]["name"] == "refund"


class TestResponseParsing:
    async def test_extracts_content(self):
        response = await target_with(responds(completion("the answer"))).send(MESSAGES)
        assert response.content == "the answer"

    async def test_null_content_becomes_empty_string(self):
        """A tool-call-only reply has content: null. Probes must not crash on it."""
        response = await target_with(responds(completion(None))).send(MESSAGES)
        assert response.content == ""

    async def test_parses_tool_calls_structurally(self):
        calls = [{"function": {"name": "refund", "arguments": '{"order_id": "A1"}'}}]
        response = await target_with(responds(completion(None, calls))).send(MESSAGES)
        assert response.tool_names == {"refund"}
        assert response.tool_calls[0].arguments == {"order_id": "A1"}

    async def test_malformed_tool_arguments_preserve_the_raw_text(self):
        """Malformed arguments may themselves be the finding; never discard evidence."""
        calls = [{"function": {"name": "refund", "arguments": "{not json"}}]
        response = await target_with(responds(completion(None, calls))).send(MESSAGES)
        assert response.tool_calls[0].arguments == {}
        assert response.tool_calls[0].raw_arguments == "{not json"

    async def test_records_latency(self):
        response = await target_with(responds(completion())).send(MESSAGES)
        assert response.latency_ms >= 0


class TestErrorHandling:
    @pytest.mark.parametrize("status", [400, 401, 429, 500, 503])
    async def test_http_errors_raise_target_error(self, status):
        """Never swallowed: an unreachable target must not read as a secure one."""
        with pytest.raises(TargetError, match=str(status)):
            await target_with(responds({"error": "nope"}, status)).send(MESSAGES)

    async def test_non_json_response_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>gateway</html>")

        with pytest.raises(TargetError, match="non-JSON"):
            await target_with(handler).send(MESSAGES)

    async def test_empty_choices_raises(self):
        with pytest.raises(TargetError, match="no choices"):
            await target_with(responds({"choices": []})).send(MESSAGES)

    async def test_transport_failure_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        with pytest.raises(TargetError, match="request to target failed"):
            await target_with(handler).send(MESSAGES)


class TestSecretHygiene:
    def test_describe_does_not_leak_the_api_key(self):
        """describe() ends up in reports and logs."""
        described = OpenAICompatibleTarget(SPEC).describe()
        assert "sk-secret-abc" not in described
        assert "gpt-test" in described

    def test_json_dump_redacts_the_api_key(self):
        assert SPEC.model_dump(mode="json")["api_key"] == "**********"

    def test_repr_redacts_the_api_key(self):
        assert "sk-secret-abc" not in repr(SPEC)


class TestUrlValidation:
    @pytest.mark.parametrize("url", ["ftp://x/v1", "file:///etc/passwd", "not-a-url"])
    def test_non_http_schemes_are_rejected(self, url):
        with pytest.raises(ValueError, match="http"):
            OpenAICompatibleTargetSpec(base_url=url, model="m")

    def test_trailing_slash_is_normalized(self):
        spec = OpenAICompatibleTargetSpec(base_url="https://x.test/v1/", model="m")
        assert spec.base_url == "https://x.test/v1"

    def test_localhost_is_allowed(self):
        """The whole point is testing your own app, which usually runs locally."""
        spec = OpenAICompatibleTargetSpec(base_url="http://localhost:11434/v1", model="m")
        assert spec.base_url.startswith("http://localhost")
