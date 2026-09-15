"""HTTP request and response models.

These are the public contract. They are separate from the domain models on purpose:
the wire format has to stay stable for clients, while the domain is free to change.
The translation is explicit, in ``from_row`` constructors, so nothing leaks from the
database into the API by accident -- including credentials.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from promptsentinel.core.authorization import REQUIRED_ATTESTATION
from promptsentinel.core.models import Confidence, ProbeCategory, Severity
from promptsentinel.db.models import FindingRow, ProbeRunRow, ScanRow
from promptsentinel.probes.base import Probe
from promptsentinel.targets.spec import TargetSpec


class AuthorizationInput(BaseModel):
    """The operator's attestation that they may test this target.

    Every field defaults to a refusing value. Forgetting to send this block is a 403,
    not an accidental scan -- the failure mode of an omitted field must be "no scan".
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "confirmed": True,
                "attested_by": "security@example.com",
                "statement": REQUIRED_ATTESTATION,
                "reference": "JIRA-4821",
            }
        },
    )

    confirmed: bool = Field(
        default=False, description="Must be true. There is no implicit consent."
    )
    attested_by: str = Field(
        default="", description="Who takes responsibility. Recorded with the scan."
    )
    statement: str = Field(
        default="",
        description=f"Must read exactly: {REQUIRED_ATTESTATION!r}",
    )
    reference: str | None = Field(
        default=None, description="Optional ticket or engagement reference."
    )


class ScanRequest(BaseModel):
    """Submit a scan."""

    model_config = ConfigDict(extra="forbid")

    target: TargetSpec = Field(description="The application under test.")
    authorization: AuthorizationInput = Field(
        description="Required. The scan is refused without a valid attestation."
    )
    probes: list[str] | None = Field(
        default=None, description="Probe IDs to run. Omit to run all enabled probes."
    )
    categories: list[ProbeCategory] | None = Field(
        default=None, description="Restrict to these categories. Ignored if `probes` is set."
    )
    options: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Per-probe options, keyed by probe ID."
    )
    webhook_url: HttpUrl | None = Field(
        default=None,
        description="POSTed a summary when the scan finishes. Never receives evidence.",
    )


class ScanAccepted(BaseModel):
    """202 response. The scan has been queued, not run."""

    id: str
    status: str
    created_at: datetime
    probes_selected: list[str]
    status_url: str
    report_url: str


class FindingOut(BaseModel):
    """A reported issue.

    ``proof`` is present if and only if ``confidence == "confirmed"``. A client can
    rely on that: it is enforced at construction in the domain model, not here.
    """

    id: str
    probe_id: str
    category: ProbeCategory
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: dict[str, Any]
    proof: dict[str, Any] | None
    signals: list[str]

    @classmethod
    def from_row(cls, row: FindingRow) -> FindingOut:
        return cls(
            id=row.id,
            probe_id=row.probe_id,
            category=ProbeCategory(row.category),
            title=row.title,
            description=row.description,
            severity=Severity(row.severity),
            confidence=Confidence(row.confidence),
            evidence=dict(row.evidence),
            proof=dict(row.proof) if row.proof else None,
            signals=[str(s) for s in row.signals],
        )


class ProbeRunOut(BaseModel):
    """What one probe did. Reported whether or not it found anything."""

    probe_id: str
    status: str
    attempts: int
    duration_ms: int
    error: str | None
    detail: str | None

    @classmethod
    def from_row(cls, row: ProbeRunRow) -> ProbeRunOut:
        return cls(
            probe_id=row.probe_id,
            status=row.status,
            attempts=row.attempts,
            duration_ms=row.duration_ms,
            error=row.error,
            detail=row.detail,
        )


class ScanSummary(BaseModel):
    """Headline numbers.

    ``probes_errored`` and ``probes_skipped`` sit next to the finding counts
    deliberately. "0 findings" means something very different when three probes
    crashed, and a summary that hides that is a lie by omission.
    """

    total_findings: int
    confirmed: int
    suspicious: int
    informational: int
    by_severity: dict[str, int]
    probes_run: int
    probes_completed: int
    probes_errored: int
    probes_skipped: int


class ScanStatusOut(BaseModel):
    """Poll response."""

    id: str
    status: str
    target_kind: str
    target: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    webhook_status: str | None

    @classmethod
    def from_row(cls, row: ScanRow) -> ScanStatusOut:
        return cls(
            id=row.id,
            status=row.status,
            target_kind=row.target_kind,
            target=row.target_description,
            created_at=row.created_at,
            started_at=row.started_at,
            finished_at=row.finished_at,
            error=row.error,
            webhook_status=row.webhook_status,
        )


class AuthorizationRecord(BaseModel):
    """The attestation, echoed back in the report as part of the audit trail."""

    confirmed: bool
    attested_by: str
    statement: str
    reference: str | None
    attested_at: datetime


class CanaryRecord(BaseModel):
    """A synthetic secret that was planted. Values are redacted."""

    id: str
    label: str
    placement: str
    value: str


class ScanReport(BaseModel):
    """The full result of a completed scan."""

    scan: ScanStatusOut
    summary: ScanSummary
    authorization: AuthorizationRecord
    target_spec: dict[str, Any] = Field(description="As submitted, with credentials redacted.")
    findings: list[FindingOut]
    probe_runs: list[ProbeRunOut]
    canaries_seeded: list[CanaryRecord]

    @classmethod
    def from_row(cls, row: ScanRow) -> ScanReport:
        findings = [FindingOut.from_row(f) for f in row.findings]
        runs = [ProbeRunOut.from_row(r) for r in row.probe_runs]
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

        return cls(
            scan=ScanStatusOut.from_row(row),
            summary=ScanSummary(
                total_findings=len(findings),
                confirmed=sum(1 for f in findings if f.confidence is Confidence.CONFIRMED),
                suspicious=sum(1 for f in findings if f.confidence is Confidence.SUSPICIOUS),
                informational=sum(1 for f in findings if f.confidence is Confidence.INFORMATIONAL),
                by_severity=by_severity,
                probes_run=len(runs),
                probes_completed=sum(1 for r in runs if r.status == "completed"),
                probes_errored=sum(1 for r in runs if r.status in ("errored", "timed_out")),
                probes_skipped=sum(1 for r in runs if r.status == "skipped"),
            ),
            authorization=AuthorizationRecord(
                confirmed=row.authorization_confirmed,
                attested_by=row.authorized_by,
                statement=row.authorization_statement,
                reference=row.authorization_reference,
                attested_at=row.authorized_at,
            ),
            target_spec=dict(row.target_spec_redacted),
            findings=findings,
            probe_runs=runs,
            canaries_seeded=[CanaryRecord(**c) for c in row.canaries_seeded],
        )


class ProbeInfo(BaseModel):
    """Catalogue entry. Lets a client discover probes instead of hardcoding IDs."""

    id: str
    name: str
    category: ProbeCategory
    description: str
    default_severity: Severity
    required_capabilities: list[str]
    default_enabled: bool

    @classmethod
    def from_probe(cls, probe_cls: type[Probe]) -> ProbeInfo:
        return cls(
            id=probe_cls.id,
            name=probe_cls.name,
            category=probe_cls.category,
            description=probe_cls.description,
            default_severity=probe_cls.default_severity,
            required_capabilities=sorted(c.value for c in probe_cls.required_capabilities),
            default_enabled=probe_cls.default_enabled,
        )


class ErrorResponse(BaseModel):
    """Uniform error body."""

    error: str = Field(description="Machine-readable error code.")
    detail: str = Field(description="Human-readable explanation.")
