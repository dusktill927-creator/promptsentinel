"""Adapter for OpenAI-compatible chat-completion endpoints."""

from __future__ import annotations

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
from promptsentinel.targets.spec import OpenAICompatibleTargetSpec


class OpenAICompatibleTarget(Target):
    """Speaks ``POST {base_url}/chat/completions``.

    Note what this adapter does *not* do: no retries on 4xx, no prompt rewriting, no
    "helpful" normalization of the response. A scanner that silently repairs the
    target's behaviour cannot report on it accurately.
    """

    kind: ClassVar[str] = "openai_compatible"
    default_capabilities: ClassVar[frozenset[TargetCapability]] = frozenset(
        {TargetCapability.CHAT, TargetCapability.SYSTEM_PROMPT_CONTROL}
    )

    @property
    def capabilities(self) -> frozenset[TargetCapability]:
        """Configuration decides, not type.

        DOCUMENT_INJECTION needs the operator's retrieval description, or we would be
        guessing where retrieved text lands. TOOL_CALLING needs their tool declarations,
        or there is nothing to offer the model and nothing to recognise if it answers.
        In both cases a probe that guesses wrong reports a clean result for an attack
        path it never exercised, which is the outcome worth engineering against.
        """
        extra = set()
        if self._spec.retrieval is not None:
            extra.add(TargetCapability.DOCUMENT_INJECTION)
        if self._spec.tools:
            extra.add(TargetCapability.TOOL_CALLING)
        return self.default_capabilities | extra

    @property
    def declared_tools(self) -> Sequence[ToolDefinition]:
        return self._spec.tools

    def __init__(
        self, spec: OpenAICompatibleTargetSpec, *, client: httpx.AsyncClient | None = None
    ):
        self._spec = spec
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(spec.timeout_s),
            follow_redirects=False,
        )

    @property
    def system_prompt(self) -> str | None:
        return self._spec.system_prompt

    def describe(self) -> str:
        return f"{self.kind}:{self._spec.model} @ {self._spec.base_url}"

    async def send(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ) -> TargetResponse:
        rendered = self._render_documents(messages, documents)
        payload: dict[str, Any] = {
            "model": self._spec.model,
            "messages": [{"role": m.role, "content": m.content} for m in rendered],
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters or {"type": "object", "properties": {}},
                    },
                }
                for t in tools
            ]

        headers = dict(self._spec.headers)
        if self._spec.api_key is not None:
            headers["Authorization"] = f"Bearer {self._spec.api_key.get_secret_value()}"

        started = time.perf_counter()
        try:
            response = await self._client.post(
                f"{self._spec.base_url}/chat/completions", json=payload, headers=headers
            )
        except httpx.HTTPError as exc:
            raise TargetError(f"request to target failed: {exc}") from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        if response.status_code >= 400:
            raise TargetError(f"target returned HTTP {response.status_code}: {response.text[:300]}")
        try:
            body: dict[str, Any] = response.json()
        except ValueError as exc:
            raise TargetError(f"target returned non-JSON response: {exc}") from exc

        return self._parse(body, latency_ms)

    def _render_documents(
        self, messages: Sequence[ChatMessage], documents: Sequence[Document] | None
    ) -> list[ChatMessage]:
        """Insert retrieved context where this application puts it.

        The context message goes immediately before the final user turn, which is where
        virtually every RAG implementation places it, and is templated from the
        operator's own configuration rather than from our assumptions.
        """
        rendered = list(messages)
        if not documents or self._spec.retrieval is None:
            return rendered

        config = self._spec.retrieval
        body = "\n\n".join(
            config.document_template.format(
                index=index, title=doc.title, source=doc.source, content=doc.content
            )
            for index, doc in enumerate(documents, start=1)
        )
        context = ChatMessage(
            role=config.role, content=config.context_template.format(documents=body)
        )

        insert_at = len(rendered)
        for position in range(len(rendered) - 1, -1, -1):
            if rendered[position].role == "user":
                insert_at = position
                break
        rendered.insert(insert_at, context)
        return rendered

    def _parse(self, body: dict[str, Any], latency_ms: int) -> TargetResponse:
        choices = body.get("choices") or []
        if not choices:
            raise TargetError("target response contained no choices")
        message = choices[0].get("message") or {}

        tool_calls: list[ToolCall] = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            raw_arguments = function.get("arguments") or ""
            tool_calls.append(
                ToolCall(
                    name=function.get("name", ""),
                    arguments=_safe_json_object(raw_arguments),
                    raw_arguments=raw_arguments,
                )
            )

        return TargetResponse(
            content=message.get("content") or "",
            tool_calls=tool_calls,
            latency_ms=latency_ms,
            finish_reason=choices[0].get("finish_reason"),
            raw=body,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _safe_json_object(raw: str) -> dict[str, Any]:
    """Parse tool arguments leniently.

    Malformed arguments are themselves a finding a probe may care about, so a parse
    failure yields an empty dict and leaves ``raw_arguments`` intact rather than
    raising and losing the evidence.
    """
    import json

    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}
