"""Adapter for arbitrary HTTP chat applications.

The OpenAI-compatible adapter covers a lot of deployments. This one covers the rest:
the internal endpoint that takes ``{"question": ...}`` and answers
``{"data": {"answer": ...}}``, which no amount of dialect-guessing would reach.

Two design points are worth the attention.

**The template declares the capabilities.** Whether this target supports a seeded system
prompt, retrieved documents or tool calls is read off the operator's own configuration
-- if their template never interpolates ``{{system}}``, there is nowhere to put a canary
and probes needing one are skipped rather than run blind against a target that silently
discards the seed. That is the same rule the other adapters follow, applied to a target
whose shape is not known in advance.

**Placeholders substitute by value, not by string.** ``{"history": "{{history}}"``
becomes a JSON *list*, not the string ``"[{'role': ...}]"``. Interpolating structured
data into a string is the kind of thing that appears to work until an apostrophe in a
probe's prompt breaks the request.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any, ClassVar

import httpx

from promptsentinel.core.errors import TargetError
from promptsentinel.targets.base import (
    ChatMessage,
    Document,
    Target,
    TargetCapability,
    TargetResponse,
    ToolCall,
    ToolDefinition,
    ToolSpec,
)
from promptsentinel.targets.spec import HttpTargetSpec

PROMPT = "{{prompt}}"
HISTORY = "{{history}}"
SYSTEM = "{{system}}"
DOCUMENTS = "{{documents}}"


def dig(payload: Any, path: str) -> Any:
    """Follow a dotted path, treating numeric segments as list indices.

    Returns ``None`` rather than raising: a missing path is reported by the caller with
    the keys that *were* present, which is far more useful when someone is working out
    their own response shape.
    """
    current = payload
    for segment in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            if segment not in current:
                return None
            current = current[segment]
        else:
            return None
    return current


class HttpTarget(Target):
    """A chat application described by a request template and response paths."""

    kind: ClassVar[str] = "http"
    default_capabilities: ClassVar[frozenset[TargetCapability]] = frozenset({TargetCapability.CHAT})

    def __init__(self, spec: HttpTargetSpec, *, client: httpx.AsyncClient | None = None):
        self._spec = spec
        self._template_text = json.dumps(spec.request_template)
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(spec.timeout_s), follow_redirects=False
        )

    @property
    def capabilities(self) -> frozenset[TargetCapability]:
        extra = set()
        if SYSTEM in self._template_text or HISTORY in self._template_text:
            # {{history}} carries the system turn, so either placeholder gives a probe
            # somewhere to seed a canary.
            extra.add(TargetCapability.SYSTEM_PROMPT_CONTROL)
        if DOCUMENTS in self._template_text:
            extra.add(TargetCapability.DOCUMENT_INJECTION)
        if self._spec.tool_calls_path and self._spec.tools:
            # Both halves are required and neither is sufficient: declarations say what
            # to offer the application, the path says where its answer appears.
            # Advertising the capability with only one of them produces probes that run
            # and can never observe anything.
            extra.add(TargetCapability.TOOL_CALLING)
        return self.default_capabilities | extra

    @property
    def declared_tools(self) -> Sequence[ToolDefinition]:
        return self._spec.tools

    @property
    def system_prompt(self) -> str | None:
        return self._spec.system_prompt

    def describe(self) -> str:
        return f"{self.kind}:{self._spec.url}"

    async def send(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ) -> TargetResponse:
        body = self._render(messages, documents)
        headers = dict(self._spec.headers)
        if self._spec.api_key is not None:
            headers[self._spec.api_key_header] = (
                f"{self._spec.api_key_prefix}{self._spec.api_key.get_secret_value()}"
            )

        started = time.perf_counter()
        try:
            response = await self._client.request(
                self._spec.method, self._spec.url, json=body, headers=headers
            )
        except httpx.HTTPError as exc:
            raise TargetError(f"request to target failed: {exc}") from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        if response.status_code >= 400:
            raise TargetError(f"target returned HTTP {response.status_code}: {response.text[:300]}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetError(f"target returned non-JSON response: {exc}") from exc

        return self._parse(payload, latency_ms)

    def _render(self, messages: Sequence[ChatMessage], documents: Sequence[Document] | None) -> Any:
        values = {
            PROMPT: _last_user(messages),
            HISTORY: [
                {"role": m.role, "content": m.content} for m in messages if m.role != "system"
            ],
            SYSTEM: _system(messages) or self._spec.system_prompt or "",
            DOCUMENTS: self._render_documents(documents),
        }
        return _substitute(self._spec.request_template, values)

    def _render_documents(self, documents: Sequence[Document] | None) -> str:
        if not documents:
            return ""
        return "\n\n".join(
            self._spec.document_template.format(
                index=index, title=doc.title, source=doc.source, content=doc.content
            )
            for index, doc in enumerate(documents, start=1)
        )

    def _parse(self, payload: Any, latency_ms: int) -> TargetResponse:
        content = dig(payload, self._spec.response_path)
        if content is None:
            available = ", ".join(payload) if isinstance(payload, dict) else type(payload).__name__
            raise TargetError(
                f"response_path {self._spec.response_path!r} not found in the target's "
                f"reply (top level: {available})"
            )

        tool_calls: list[ToolCall] = []
        if self._spec.tool_calls_path:
            raw = dig(payload, self._spec.tool_calls_path) or []
            if isinstance(raw, list):
                tool_calls = [
                    ToolCall(
                        name=str(call.get(self._spec.tool_name_field, "")),
                        arguments=_as_dict(call.get(self._spec.tool_arguments_field)),
                        raw_arguments=json.dumps(call.get(self._spec.tool_arguments_field)),
                    )
                    for call in raw
                    if isinstance(call, dict)
                ]

        return TargetResponse(
            content=str(content),
            tool_calls=tool_calls,
            latency_ms=latency_ms,
            raw=payload if isinstance(payload, dict) else {"response": payload},
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _substitute(node: Any, values: dict[str, Any]) -> Any:
    """Replace placeholders throughout the template.

    A string that is *exactly* a placeholder becomes the typed value, so ``{{history}}``
    yields a real list. A placeholder embedded in a longer string is interpolated as
    text, which is what someone writing ``"User asked: {{prompt}}"`` intends.
    """
    if isinstance(node, dict):
        return {key: _substitute(value, values) for key, value in node.items()}
    if isinstance(node, list):
        return [_substitute(item, values) for item in node]
    if isinstance(node, str):
        if node in values:
            return values[node]
        for placeholder, value in values.items():
            if placeholder in node:
                text = value if isinstance(value, str) else json.dumps(value)
                node = node.replace(placeholder, text)
        return node
    return node


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _last_user(messages: Sequence[ChatMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    return ""


def _system(messages: Sequence[ChatMessage]) -> str | None:
    for message in messages:
        if message.role == "system":
            return message.content
    return None
