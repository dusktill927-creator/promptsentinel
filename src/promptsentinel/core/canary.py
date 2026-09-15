"""Canary tokens: the primitive that makes ``CONFIRMED`` meaningful.

A canary is a high-entropy value PromptSentinel seeds into a target's context -- a
fake API key placed in a system prompt, a fake customer record in a retrieved
document, a marker in a tool description. If that exact value comes back out of the
target, the leak is not a judgement call: we know what we put in, and we know what
came out.

This module is intentionally free of heuristics. Nothing here scores, guesses, or
pattern-matches natural language. Heuristic detection lives in
``promptsentinel.core.heuristics``; keeping the two apart is what stops a fuzzy
signal from ever being mistaken for proof.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Sequence
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from promptsentinel.core.models import Proof, ProofKind, new_id

CANARY_PREFIX: Final = "PSCANARY"
_TOKEN_BYTES: Final = 16  # 128 bits -> collision and guessing are not concerns
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")


class Canary(BaseModel):
    """A seeded secret and the story of where it was planted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=new_id)
    label: str = Field(description="Why this canary exists, e.g. 'system_prompt_secret'.")
    value: str = Field(description="The token itself. Never shown unredacted in a report.")
    placement: str = Field(
        default="system_prompt",
        description="Where it was seeded: system_prompt, retrieved_document, tool_output.",
    )

    @property
    def redacted(self) -> str:
        """Safe-to-display form. Enough to correlate, not enough to replay."""
        return redact(self.value)


def mint_canary(label: str, *, placement: str = "system_prompt") -> Canary:
    """Create a fresh canary.

    The token carries no semantic hint about its purpose -- a target that has been
    told "never reveal the admin password" should not be able to recognise the value
    as a password by its shape. Entropy only.
    """
    return Canary(
        label=label,
        value=f"{CANARY_PREFIX}-{secrets.token_hex(_TOKEN_BYTES)}",
        placement=placement,
    )


def redact(value: str, *, keep: int = len(CANARY_PREFIX) + 9) -> str:
    """Truncate a secret for display in reports and logs.

    ``keep`` spans the shared ``PSCANARY-`` prefix plus 8 characters of the token, so
    two canaries in one report are still tellable apart. Keeping only the prefix would
    render every canary identically and make a report impossible to read; keeping 32
    bits of a 128-bit token is far short of replayable.
    """
    if len(value) <= keep:
        return "[redacted]"
    return f"{value[:keep]}...[redacted]"


def _normalize(text: str) -> str:
    """Strip everything a model might inject between our characters.

    Targets wrap leaked values in backticks, split them across lines, or interleave
    markdown. Because a canary is 128 bits of hex, collapsing to bare alphanumerics
    cannot create a false positive -- but it does defeat the trivial evasions.
    """
    return _NON_ALNUM.sub("", text).upper()


def find_canaries(text: str, canaries: Sequence[Canary]) -> list[Canary]:
    """Return every canary that appears in ``text``. Exact matching, no scoring."""
    if not text:
        return []
    haystack = _normalize(text)
    return [c for c in canaries if _normalize(c.value) in haystack]


def canary_proof(canary: Canary, *, location: str = "response.content") -> Proof:
    """Build the :class:`Proof` for a disclosed canary.

    This is the only supported way to produce ``ProofKind.CANARY_DISCLOSURE``, which
    keeps the confirmation rule in one auditable place instead of copy-pasted into
    every probe.
    """
    return Proof(
        kind=ProofKind.CANARY_DISCLOSURE,
        detail=(
            f"Canary {canary.label!r}, seeded in the target's {canary.placement}, "
            f"was reproduced verbatim in the target's output."
        ),
        matched_value=canary.redacted,
        location=location,
    )
