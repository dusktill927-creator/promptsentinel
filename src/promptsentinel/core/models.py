"""Domain models.

These types are the contract between probes and everything else. They are
deliberately *not* the HTTP schemas (see ``api/schemas.py``) and *not* the database
rows (see ``db/models.py``) -- keeping the three apart means a column rename or an
API version bump never forces a change to probe code.

The central invariant of this module is the confidence tier. See
:class:`Finding` for how it is enforced.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow() -> datetime:
    """Timezone-aware UTC now. Naive datetimes are a persistence bug waiting to happen."""
    return datetime.now(UTC)


def new_id() -> str:
    """Opaque identifier. String UUIDs keep SQLite and Postgres interchangeable."""
    return uuid.uuid4().hex


class Severity(StrEnum):
    """How bad the issue is *if real*. Orthogonal to how sure we are that it is real."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How sure we are that the issue is real.

    ``CONFIRMED`` is reserved for findings backed by machine-verifiable proof: a
    seeded canary came back, a disallowed tool was invoked, a known marker appeared.
    ``SUSPICIOUS`` means a heuristic fired and a human should look. There is no tier
    in between, and nothing promotes a finding from one to the other after the fact.
    """

    INFORMATIONAL = "informational"
    SUSPICIOUS = "suspicious"
    CONFIRMED = "confirmed"


class ProbeCategory(StrEnum):
    """The V1 taxonomy. ``DIAGNOSTIC`` covers probes that test PromptSentinel itself."""

    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    JAILBREAK = "jailbreak"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    EXCESSIVE_AGENCY = "excessive_agency"
    DIAGNOSTIC = "diagnostic"


class ProofKind(StrEnum):
    """The finite set of things that count as hard proof.

    New probes may add members, but a probe may never invent an ad-hoc proof reason:
    if it is not enumerable and checkable here, the finding is ``SUSPICIOUS``.
    """

    CANARY_DISCLOSURE = "canary_disclosure"
    """A high-entropy value we seeded came back out of the target."""

    UNAUTHORIZED_TOOL_CALL = "unauthorized_tool_call"
    """The target invoked a tool the scan configuration marked as disallowed."""

    SYSTEM_PROMPT_DISCLOSURE = "system_prompt_disclosure"
    """A verbatim span of the operator-supplied system prompt was reproduced."""

    POLICY_BYPASS_MARKER = "policy_bypass_marker"
    """The target emitted content its own system prompt forbade under any framing."""


class Proof(BaseModel):
    """Machine-verifiable evidence that an issue is real.

    The distinction between :class:`Proof` and :class:`Evidence` is the whole design:
    *evidence* is what happened (a prompt and a response, always recorded); *proof* is
    a check that succeeded (this exact secret appeared in that response). Only proof
    unlocks ``CONFIRMED``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ProofKind
    detail: str = Field(description="Human-readable statement of what was verified.")
    matched_value: str = Field(description="The exact value that was matched, redacted.")
    location: str = Field(
        default="response.content",
        description="Where in the target's response the match occurred.",
    )


class Evidence(BaseModel):
    """The interaction that produced a finding. Recorded for every tier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    prompt: str
    response: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """A single security issue reported by a probe.

    Invariants, enforced by the type rather than by convention:

    1. ``CONFIRMED`` requires a :class:`Proof`.
    2. A :class:`Proof` requires ``CONFIRMED`` -- a probe cannot attach proof while
       hedging on the tier.
    3. The model is frozen, so no caller can mutate ``confidence`` after construction.
    4. :meth:`model_copy` is overridden to re-validate, closing Pydantic's documented
       hole where ``model_copy(update=...)`` skips validators.

    Together these mean the only way to produce a confirmed finding is to call
    :meth:`confirmed` and hand it proof.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=new_id)
    probe_id: str
    category: ProbeCategory
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: Evidence
    proof: Proof | None = None
    signals: list[str] = Field(
        default_factory=list,
        description="Heuristic signals that fired. Explains a SUSPICIOUS tier to a human.",
    )
    created_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _check_confidence_invariant(self) -> Self:
        if self.confidence is Confidence.CONFIRMED and self.proof is None:
            raise ValueError("a CONFIRMED finding requires proof; use Finding.suspicious() instead")
        if self.confidence is not Confidence.CONFIRMED and self.proof is not None:
            raise ValueError("proof implies CONFIRMED; do not attach proof to a lower-tier finding")
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Re-validate on copy.

        Pydantic's ``model_copy`` skips validators by design. Left alone, that would
        make ``finding.model_copy(update={"confidence": "confirmed"})`` a silent
        upgrade -- exactly the thing this class exists to prevent.
        """
        copied = super().model_copy(update=update, deep=deep)
        return type(self).model_validate(copied.__dict__)

    @classmethod
    def confirmed(
        cls,
        *,
        probe_id: str,
        category: ProbeCategory,
        title: str,
        description: str,
        severity: Severity,
        evidence: Evidence,
        proof: Proof,
        signals: list[str] | None = None,
    ) -> Finding:
        """Build a confirmed finding. ``proof`` is keyword-required and non-optional."""
        return cls(
            probe_id=probe_id,
            category=category,
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence=evidence,
            proof=proof,
            signals=signals or [],
        )

    @classmethod
    def suspicious(
        cls,
        *,
        probe_id: str,
        category: ProbeCategory,
        title: str,
        description: str,
        severity: Severity,
        evidence: Evidence,
        signals: list[str],
    ) -> Finding:
        """Build a suspicious finding. There is no ``proof`` parameter to pass."""
        return cls(
            probe_id=probe_id,
            category=category,
            title=title,
            description=description,
            severity=severity,
            confidence=Confidence.SUSPICIOUS,
            evidence=evidence,
            proof=None,
            signals=signals,
        )

    @classmethod
    def informational(
        cls,
        *,
        probe_id: str,
        category: ProbeCategory,
        title: str,
        description: str,
        evidence: Evidence,
        signals: list[str] | None = None,
    ) -> Finding:
        """Build an informational note: observed, not a vulnerability claim."""
        return cls(
            probe_id=probe_id,
            category=category,
            title=title,
            description=description,
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            evidence=evidence,
            proof=None,
            signals=signals or [],
        )


class ProbeStatus(StrEnum):
    """Outcome of running one probe. Distinct from whether it *found* anything."""

    COMPLETED = "completed"
    ERRORED = "errored"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class ProbeResult(BaseModel):
    """What a probe hands back to the engine.

    A probe that finds nothing returns ``COMPLETED`` with an empty ``findings`` list.
    A probe that crashes returns ``ERRORED`` -- the engine never lets one probe's
    failure abort the scan, and an errored probe is reported as such rather than
    quietly counted as "clean".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str
    status: ProbeStatus
    findings: list[Finding] = Field(default_factory=list)
    attempts: int = Field(default=0, description="Requests sent to the target.")
    duration_ms: int = 0
    error: str | None = None
    detail: str | None = Field(default=None, description="Why a probe was skipped.")

    @model_validator(mode="after")
    def _check_status_invariant(self) -> Self:
        if self.status in (ProbeStatus.ERRORED, ProbeStatus.TIMED_OUT) and self.findings:
            raise ValueError("a failed probe run must not report findings")
        if self.status is ProbeStatus.ERRORED and not self.error:
            raise ValueError("an ERRORED result must carry an error message")
        return self

    @classmethod
    def completed(cls, probe_id: str, findings: list[Finding], *, attempts: int = 0) -> ProbeResult:
        return cls(
            probe_id=probe_id,
            status=ProbeStatus.COMPLETED,
            findings=findings,
            attempts=attempts,
        )

    @classmethod
    def errored(cls, probe_id: str, error: str, *, attempts: int = 0) -> ProbeResult:
        return cls(probe_id=probe_id, status=ProbeStatus.ERRORED, error=error, attempts=attempts)

    @classmethod
    def timed_out(cls, probe_id: str, timeout_s: float, *, attempts: int = 0) -> ProbeResult:
        return cls(
            probe_id=probe_id,
            status=ProbeStatus.TIMED_OUT,
            error=f"probe exceeded its {timeout_s:g}s budget",
            attempts=attempts,
        )

    @classmethod
    def skipped(cls, probe_id: str, detail: str) -> ProbeResult:
        return cls(probe_id=probe_id, status=ProbeStatus.SKIPPED, detail=detail)


class ScanStatus(StrEnum):
    """Lifecycle of an async scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in (ScanStatus.COMPLETED, ScanStatus.FAILED)
