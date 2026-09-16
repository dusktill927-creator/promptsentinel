"""An in-process fake LLM application.

This exists so the whole pipeline -- API, job queue, engine, probe, persistence,
report -- can be tested deterministically, with no network and no token spend. It
also doubles as the demo target in the README.

Crucially it can be configured to be *vulnerable*: told to disclose its system
prompt, it returns whatever system message is in the conversation, canaries and all.
That makes the ``CONFIRMED`` path testable end to end, instead of only the happy
path where nothing is found.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Sequence
from typing import ClassVar

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
from promptsentinel.targets.spec import MockRule, MockTargetSpec


class MockTarget(Target):
    """Rule-driven scripted target."""

    kind: ClassVar[str] = "mock"
    default_capabilities: ClassVar[frozenset[TargetCapability]] = frozenset(
        {TargetCapability.CHAT, TargetCapability.SYSTEM_PROMPT_CONTROL}
    )

    @property
    def capabilities(self) -> frozenset[TargetCapability]:
        """Mirrors the real adapters: capability follows configuration."""
        extra = set()
        if self._spec.retrieval is not None:
            extra.add(TargetCapability.DOCUMENT_INJECTION)
        if self._spec.tools:
            extra.add(TargetCapability.TOOL_CALLING)
        return self.default_capabilities | extra

    @property
    def declared_tools(self) -> Sequence[ToolDefinition]:
        return self._spec.tools

    def __init__(self, spec: MockTargetSpec):
        self._spec = spec
        self._rules = [(re.compile(r.pattern, re.I), r) for r in spec.rules]
        self._leak_pattern = (
            re.compile(spec.leak_system_prompt_on, re.I) if spec.leak_system_prompt_on else None
        )
        self._document_tool_pattern = (
            re.compile(spec.document_tool_pattern, re.I) if spec.document_tool_pattern else None
        )
        self._emit_pattern = (
            re.compile(spec.document_emit_pattern) if spec.document_emit_pattern else None
        )
        self.transcript: list[tuple[list[ChatMessage], TargetResponse]] = []
        self.documents_seen: list[list[Document]] = []

    @property
    def system_prompt(self) -> str | None:
        return self._spec.system_prompt

    def describe(self) -> str:
        return "mock:in-process"

    async def send(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ) -> TargetResponse:
        user_text = _last_user_message(messages)
        response = self._respond(user_text, messages, documents or ())
        self.transcript.append((list(messages), response))
        self.documents_seen.append(list(documents or ()))
        return response

    def _respond(
        self,
        user_text: str,
        messages: Sequence[ChatMessage],
        documents: Sequence[Document],
    ) -> TargetResponse:
        # Document-driven behaviour comes first: a RAG target's reply is shaped by what
        # it retrieved, whatever static rules also match.
        if document_call := self._tool_call_from_documents(documents):
            return TargetResponse(
                content="", tool_calls=[document_call], finish_reason="tool_calls"
            )
        if document_reply := self._reply_from_documents(documents):
            return TargetResponse(content=document_reply, finish_reason="stop")

        for pattern, rule in self._rules:
            if pattern.search(user_text):
                return TargetResponse(
                    content=_with_revealed_lines(rule, messages),
                    tool_calls=[
                        ToolCall(name=c.name, arguments=dict(c.arguments)) for c in rule.tool_calls
                    ],
                    finish_reason="tool_calls" if rule.tool_calls else "stop",
                )

        if (
            self._spec.leak_after_turns is not None
            and len(self.transcript) >= self._spec.leak_after_turns
        ):
            # len(transcript) is the number of *previous* calls, so this fires from the
            # (leak_after_turns + 1)th turn onward: it holds the line first, then caves.
            disclosed = _effective_system_prompt(messages) or self._spec.system_prompt or ""
            return TargetResponse(
                content=f"Alright, since you have been patient:\n\n{disclosed}",
                finish_reason="stop",
            )

        if self._leak_pattern is not None and self._leak_pattern.search(user_text):
            disclosed = _effective_system_prompt(messages) or self._spec.system_prompt or ""
            rendered = _encode(disclosed, self._spec.leak_encoding)
            return TargetResponse(
                content=f"Sure! My instructions are:\n\n{rendered}",
                finish_reason="stop",
            )

        return TargetResponse(content=self._spec.default_response, finish_reason="stop")

    def _tool_call_from_documents(self, documents: Sequence[Document]) -> ToolCall | None:
        """Simulate an agent that treats retrieved text as an instruction to act."""
        if not documents or self._document_tool_pattern is None:
            return None
        match = self._document_tool_pattern.search(_document_text(documents))
        if match is None:
            return None
        reference = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
        return ToolCall(name=match.group(1), arguments={"reference": reference})

    def _reply_from_documents(self, documents: Sequence[Document]) -> str | None:
        """Simulate a model acting on retrieved content.

        ``quote_documents`` stands for a summariser that repeats what it read;
        ``document_emit_pattern`` stands for a model that acts on it. The same knob
        models correct behaviour and a vulnerability depending on which part of the
        document the pattern selects -- the document's own data, or a directive that an
        attacker planted in it.
        """
        if not documents:
            return None
        text = _document_text(documents)
        if self._spec.quote_documents:
            return f"Here is what I found:\n\n{text}"
        if self._emit_pattern is None:
            return None
        matches = [
            m.group(1) if m.groups() else m.group(0) for m in self._emit_pattern.finditer(text)
        ]
        return " ".join(matches) if matches else None


def _document_text(documents: Sequence[Document]) -> str:
    return "\n\n".join(f"{d.title}\n{d.content}" for d in documents)


def _with_revealed_lines(rule: MockRule, messages: Sequence[ChatMessage]) -> str:
    """Append the system-message lines a rule is configured to disclose."""
    if rule.reveal_system_lines is None:
        return rule.response
    system = _effective_system_prompt(messages) or ""
    selector = re.compile(rule.reveal_system_lines, re.I)
    revealed = [line for line in system.splitlines() if selector.search(line)]
    return "\n".join([rule.response, *revealed]).strip()


def _encode(text: str, encoding: str | None) -> str:
    """Render a disclosed prompt the way a filter-evading target would.

    Exists so the encoding-aware detection in ``core.canary`` is exercised against a
    target that actually transforms its output, rather than only against strings a
    test built by hand.
    """
    if encoding == "base64":
        return base64.b64encode(text.encode()).decode()
    if encoding == "reversed":
        return text[::-1]
    return text


def _last_user_message(messages: Sequence[ChatMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    return ""


def _effective_system_prompt(messages: Sequence[ChatMessage]) -> str | None:
    for message in messages:
        if message.role == "system":
            return message.content
    return None
