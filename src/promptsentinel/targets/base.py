"""The Target interface.

A *target* is a deployed LLM application, not a model. That distinction is the
product thesis: garak and PyRIT probe a model's weights; PromptSentinel probes the
thing the operator actually shipped -- its system prompt, its retrieval pipeline,
its tool wiring.

Probes are written against this interface only. Adding a new kind of target (a raw
HTTP chatbot, a LangChain server, an Anthropic-native endpoint) means implementing
:class:`Target`, and no probe changes.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from enum import StrEnum
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

Role = Literal["system", "user", "assistant", "tool"]


class TargetCapability(StrEnum):
    """What a target can do.

    Probes declare the capabilities they need; the engine skips a probe whose
    requirements a target does not meet, and reports it as ``SKIPPED`` rather than
    silently passing. An indirect-injection probe run against a target with no
    retrieval pipeline would otherwise report a clean bill of health it never earned.
    """

    CHAT = "chat"
    """Accepts a message list and returns an assistant message."""

    SYSTEM_PROMPT_CONTROL = "system_prompt_control"
    """The operator can seed a system prompt -- required to plant canaries in it."""

    TOOL_CALLING = "tool_calling"
    """Can be offered tools and may emit tool calls."""

    DOCUMENT_INJECTION = "document_injection"
    """Accepts a simulated retrieved document -- required for indirect injection."""


class ChatMessage(BaseModel):
    """One turn of conversation sent to the target."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Role
    content: str

    @classmethod
    def system(cls, content: str) -> ChatMessage:
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> ChatMessage:
        return cls(role="user", content=content)


class ToolSpec(BaseModel):
    """A tool offered to the target, in the shape probes care about."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """A tool invocation the target emitted.

    Recorded structurally rather than as text: an unauthorized tool call is one of
    the few things that can be proven, and proving it requires the name and
    arguments as data, not a string we later regex.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_arguments: str = ""


class TargetResponse(BaseModel):
    """What came back. Probes read ``content`` and ``tool_calls``; the rest is audit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    latency_ms: int = 0
    finish_reason: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def tool_names(self) -> set[str]:
        return {call.name for call in self.tool_calls}


class Document(BaseModel):
    """A simulated retrieved document.

    Probes hand these to a target rather than formatting them into a message
    themselves, because only the adapter knows how a given application presents
    retrieved context -- as a system block, a user turn, or its own message role.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    title: str
    content: str
    source: str = Field(
        default="kb://internal",
        description="Where the document claims to come from. Appears in the rendered "
        "context, because provenance is often what an injected instruction impersonates.",
    )


class Target(abc.ABC):
    """A system under test.

    Implementations must be safe to call concurrently: the engine runs several probes
    against one target at a time.
    """

    kind: ClassVar[str]
    """Stable identifier used in scan requests, e.g. ``openai_compatible``."""

    default_capabilities: ClassVar[frozenset[TargetCapability]] = frozenset({TargetCapability.CHAT})
    """What this adapter can do before configuration is taken into account."""

    @property
    def capabilities(self) -> frozenset[TargetCapability]:
        """What *this configured target* can do.

        A property rather than a class attribute because capability depends on how the
        target was set up, not only on its type: the same OpenAI-compatible adapter is
        a RAG target when the operator describes their retrieval context and a plain
        chat target when they do not. Reporting a capability the deployment does not
        have would let an indirect-injection probe claim a clean result it never earned.
        """
        return self.default_capabilities

    @abc.abstractmethod
    async def send(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ) -> TargetResponse:
        """Send a conversation and return the target's reply.

        ``documents`` simulates retrieval: the adapter renders them the way the
        application presents retrieved context, so a probe can plant content without
        knowing the application's prompt format.

        Raises:
            TargetError: on transport failure or an unparseable response. Probes let
                this propagate; the engine converts it into an ``ERRORED`` result so
                a flaky endpoint is never reported as a secure one.
        """

    async def aclose(self) -> None:  # noqa: B027 - optional hook, not abstract
        """Release connections.

        Deliberately concrete and empty: a stateless target has nothing to close, and
        forcing every implementation to write ``pass`` buys nothing.
        """

    def describe(self) -> str:
        """One-line identification for the report header.

        Implementations must never include credentials in the return value.
        """
        return self.kind

    def supports(self, capability: TargetCapability) -> bool:
        return capability in self.capabilities

    @property
    def system_prompt(self) -> str | None:
        """The application's own system prompt, when the operator supplied it.

        Probes that seed canaries append to this rather than replacing it, so the
        target is tested in the configuration it actually runs in.
        """
        return None
