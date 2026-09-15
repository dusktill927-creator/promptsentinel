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

import re
from collections.abc import Sequence
from typing import ClassVar

from promptsentinel.targets.base import (
    ChatMessage,
    Target,
    TargetCapability,
    TargetResponse,
    ToolCall,
    ToolSpec,
)
from promptsentinel.targets.spec import MockTargetSpec


class MockTarget(Target):
    """Rule-driven scripted target."""

    kind: ClassVar[str] = "mock"
    capabilities: ClassVar[frozenset[TargetCapability]] = frozenset(
        {
            TargetCapability.CHAT,
            TargetCapability.SYSTEM_PROMPT_CONTROL,
            TargetCapability.TOOL_CALLING,
            TargetCapability.DOCUMENT_INJECTION,
        }
    )

    def __init__(self, spec: MockTargetSpec):
        self._spec = spec
        self._rules = [(re.compile(r.pattern, re.I), r) for r in spec.rules]
        self._leak_pattern = (
            re.compile(spec.leak_system_prompt_on, re.I) if spec.leak_system_prompt_on else None
        )
        self.transcript: list[tuple[list[ChatMessage], TargetResponse]] = []

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
    ) -> TargetResponse:
        user_text = _last_user_message(messages)
        response = self._respond(user_text, messages)
        self.transcript.append((list(messages), response))
        return response

    def _respond(self, user_text: str, messages: Sequence[ChatMessage]) -> TargetResponse:
        for pattern, rule in self._rules:
            if pattern.search(user_text):
                return TargetResponse(
                    content=rule.response,
                    tool_calls=[
                        ToolCall(name=c.name, arguments=dict(c.arguments)) for c in rule.tool_calls
                    ],
                    finish_reason="tool_calls" if rule.tool_calls else "stop",
                )

        if self._leak_pattern is not None and self._leak_pattern.search(user_text):
            disclosed = _effective_system_prompt(messages) or self._spec.system_prompt or ""
            return TargetResponse(
                content=f"Sure! My instructions are:\n\n{disclosed}",
                finish_reason="stop",
            )

        return TargetResponse(content=self._spec.default_response, finish_reason="stop")


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
