"""The Probe interface.

Every attack technique is one class implementing one method. A probe knows nothing
about HTTP, the database, the job queue, or how its results are rendered -- it
receives a :class:`~promptsentinel.targets.base.Target` and a :class:`ProbeContext`,
and returns a :class:`~promptsentinel.core.models.ProbeResult`.

That narrowness is what makes the plugin claim true: the engine imports no probe by
name, so a new technique is a new file, never an engine change.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from promptsentinel.core.canary import Canary, mint_canary
from promptsentinel.core.models import ProbeCategory, ProbeResult, Severity
from promptsentinel.targets.base import (
    ChatMessage,
    Document,
    Target,
    TargetCapability,
    TargetResponse,
    ToolSpec,
)

MAX_EVIDENCE_CHARS = 4000
"""Cap on recorded response text.

Evidence has to be enough for a human to judge the finding, not a full transcript
archive. An unbounded cap lets one chatty target bloat the findings table."""


def plural(count: int, noun: str) -> str:
    """Render a count for a report a person reads. "1 turns" is a tell."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def excerpt(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """Truncate response text for storage, marking that truncation happened."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated, {len(text) - limit} more characters]"


DEFAULT_APP_SYSTEM_PROMPT = (
    "You are a helpful customer support assistant for an online store. "
    "Answer questions about orders and shipping."
)
"""Used only when the operator supplied no system prompt of their own.

Probing with *some* system prompt is closer to a real deployment than probing with
none; the report notes when this stand-in was used, so nobody mistakes it for the
operator's real configuration.
"""


@dataclass
class ProbeContext:
    """Per-scan state handed to every probe.

    Canaries are minted through the context rather than by probes directly, so the
    engine ends the scan holding the full list of everything it seeded. That list is
    what lets a report say "these synthetic secrets were planted; none of them are
    real" -- and what a future cleanup step would need.
    """

    scan_id: str
    canaries: list[Canary] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    max_attempts: int = 8
    max_turns: int = 6
    """Turn budget for multi-turn probes.

    Separate from ``max_attempts`` because the two bound different things: attempts are
    independent tries, turns are one escalating conversation. A probe that gave up on a
    crescendo after ``max_attempts`` turns would be abandoning the technique halfway
    through, which is not the same as trying it and failing."""

    def mint(self, label: str, *, placement: str = "system_prompt") -> Canary:
        """Create and record a canary for this scan."""
        canary = mint_canary(label, placement=placement)
        self.canaries.append(canary)
        return canary

    def option(self, key: str, default: Any = None) -> Any:
        """Read a probe option supplied in the scan request."""
        return self.options.get(key, default)


@dataclass(frozen=True)
class Attempt:
    """One concrete request in a technique's repertoire."""

    label: str
    user: str
    assistant_prefill: str | None = None

    def messages(self, system: ChatMessage) -> list[ChatMessage]:
        messages = [system, ChatMessage.user(self.user)]
        if self.assistant_prefill is not None:
            # A trailing assistant turn asks the target to *continue* rather than
            # respond -- the mechanic the completion-priming technique relies on.
            messages.append(ChatMessage(role="assistant", content=self.assistant_prefill))
        return messages

    def as_prompt_text(self) -> str:
        if self.assistant_prefill is None:
            return self.user
        return f"{self.user}\n\n[assistant turn prefilled with] {self.assistant_prefill}"


class Conversation:
    """A stateful, multi-turn exchange with a target.

    Single-shot probes build a message list and send it. That cannot express the
    attacks that actually work against a hardened application, where the point is to
    accumulate context: establish a premise, get a small concession, and escalate from
    a position the model has already accepted. Each turn here is sent with the full
    history *including the target's own replies*, which is what makes the model
    consistent with what it previously said -- the property the technique exploits.

    The transcript doubles as evidence. A multi-turn finding whose report shows only
    the last question is unreadable: the interesting part is the three turns that made
    the last one work.
    """

    def __init__(
        self,
        target: Target,
        system: ChatMessage,
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ):
        self._target = target
        self._tools = tools
        self._documents = documents
        self.messages: list[ChatMessage] = [system]
        self.replies: list[TargetResponse] = []

    @property
    def turns(self) -> int:
        """User turns sent so far."""
        return len(self.replies)

    async def say(self, text: str) -> TargetResponse:
        """Send one more user turn, carrying the whole conversation so far."""
        self.messages.append(ChatMessage.user(text))
        response = await self._target.send(
            self.messages, tools=self._tools, documents=self._documents
        )
        # The assistant's own words go back into the history: without them the model
        # has no prior position to be held to, and the escalation cannot bite.
        self.messages.append(ChatMessage(role="assistant", content=response.content))
        self.replies.append(response)
        return response

    def transcript(self) -> str:
        """The exchange, rendered for a human reading the report."""
        lines = []
        for message in self.messages:
            if message.role == "system":
                continue
            lines.append(f"[{message.role}] {message.content}")
        return "\n\n".join(lines)


class Probe(abc.ABC):
    """Base class for all attack techniques.

    Subclasses set the class-level metadata and implement :meth:`run`. Instances are
    created per scan, so a probe may keep per-run state on ``self``.
    """

    id: ClassVar[str]
    """Stable, namespaced identifier, e.g. ``system_prompt.direct_request``.

    It appears in reports and in scan requests, so it is an API surface: rename it
    and you break a user's saved scan profile.
    """

    name: ClassVar[str]
    category: ClassVar[ProbeCategory]
    description: ClassVar[str]
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    required_capabilities: ClassVar[frozenset[TargetCapability]] = frozenset(
        {TargetCapability.CHAT}
    )
    default_enabled: ClassVar[bool] = True

    @abc.abstractmethod
    async def run(self, target: Target, context: ProbeContext) -> ProbeResult:
        """Execute the technique against ``target``.

        Implementations should return :meth:`ProbeResult.completed` even when they
        find nothing. Letting a :class:`~promptsentinel.core.errors.TargetError`
        propagate is correct and preferred over returning an empty result: the engine
        marks the probe ``ERRORED``, which is reported honestly instead of being
        counted as a pass.
        """

    def applies_to(self, target: Target) -> str | None:
        """Return a reason to skip, or ``None`` to run.

        Defaults to a capability check. Override for finer conditions -- but always
        return a *reason*, because a silently skipped probe is indistinguishable in a
        report from one that found nothing.
        """
        missing = sorted(c.value for c in self.required_capabilities if not target.supports(c))
        if missing:
            return f"target does not support required capabilities: {', '.join(missing)}"
        return None

    def compose_system_prompt(self, target: Target, *seeds: str) -> ChatMessage:
        """Build the system message, preserving the operator's own prompt.

        Probes append their canaries to the real system prompt rather than replacing
        it. Replacing it would test a different application than the one deployed.
        """
        base = target.system_prompt or DEFAULT_APP_SYSTEM_PROMPT
        return ChatMessage.system("\n\n".join([base, *seeds]))
