"""The authorization gate.

PromptSentinel attacks applications. The only thing separating that from abuse is an
explicit, recorded attestation that the operator owns or is permitted to test the
target. This module makes that attestation a *type*.

The design follows "parse, don't validate": :class:`Authorization` cannot be
constructed in an invalid state, and :class:`~promptsentinel.engine.runner.ScanEngine`
requires one by signature. There is therefore no code path -- HTTP, CLI, or direct
library import -- that reaches a probe without having passed the gate, because an
unauthorized request cannot even be represented as the argument the engine takes.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from promptsentinel.core.errors import AuthorizationError
from promptsentinel.core.models import utcnow

REQUIRED_ATTESTATION = "I own or am authorized to security test this target."
"""The exact phrase an operator must submit.

A free-text "yes" or a bare boolean is too easy to set by accident -- a default in a
client library, a copy-pasted script, a checkbox pre-ticked in a future UI. Requiring
a specific sentence makes authorization something a human had to type on purpose.
"""

_WHITESPACE = re.compile(r"\s+")


def _normalize(statement: str) -> str:
    """Compare attestations by substance, not by formatting."""
    return _WHITESPACE.sub(" ", statement).strip().rstrip(".").casefold()


class Authorization(BaseModel):
    """A valid, recorded authorization attestation.

    Existence of an instance means the gate was passed. Invalid input raises during
    construction rather than producing an object someone downstream must remember to
    check.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    confirmed: bool
    attested_by: str = Field(
        min_length=1,
        max_length=200,
        description="Who is taking responsibility. Retained as an audit record.",
    )
    statement: str = Field(description=f"Must read: {REQUIRED_ATTESTATION!r}")
    reference: str | None = Field(
        default=None,
        max_length=200,
        description="Optional engagement, ticket, or change-request identifier.",
    )
    attested_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _verify(self) -> Self:
        if not self.confirmed:
            raise ValueError("authorization was not confirmed")
        if _normalize(self.statement) != _normalize(REQUIRED_ATTESTATION):
            raise ValueError(f"attestation statement must read exactly: {REQUIRED_ATTESTATION!r}")
        if not self.attested_by.strip():
            raise ValueError("attested_by must name a responsible party")
        return self

    def verify(self) -> None:
        """Re-run validation on an existing instance.

        Defense in depth. ``model_construct`` and ``pickle`` can both produce an
        instance without running validators; the engine calls this before the first
        probe so that a bypass has to survive two independent checks.
        """
        try:
            type(self).model_validate(self.__dict__)
        except Exception as exc:
            raise AuthorizationError(f"invalid authorization attestation: {exc}") from exc


def require_authorization(
    *,
    confirmed: bool,
    attested_by: str,
    statement: str,
    reference: str | None = None,
) -> Authorization:
    """Gate entry point: turn untrusted input into an :class:`Authorization` or refuse.

    Raises:
        AuthorizationError: always, when the attestation is missing or malformed.
            Callers must let this propagate -- never downgrade it to a warning and
            never run a scan "in dry-run mode" instead.
    """
    try:
        return Authorization(
            confirmed=confirmed,
            attested_by=attested_by,
            statement=statement,
            reference=reference,
        )
    except AuthorizationError:
        raise
    except Exception as exc:
        raise AuthorizationError(
            "refusing to scan: this target has not been attested as owned or authorized. "
            f"Submit authorization.statement exactly as: {REQUIRED_ATTESTATION!r} "
            f"({_reason(exc)})"
        ) from exc


def _reason(exc: Exception) -> str:
    """The one-line reason, not the whole validation dump.

    This message is read by a person at a terminal and pasted into an HTTP response.
    A Pydantic traceback with a docs URL buries the single sentence that tells them
    what to fix.
    """
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    try:
        first = errors()[0]
    except (IndexError, TypeError):
        return str(exc)
    message = str(first.get("msg", "")).removeprefix("Value error, ")
    return message or str(exc)
