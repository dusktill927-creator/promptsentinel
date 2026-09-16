"""Comparing two scans.

A scanner that reports the same twelve findings on every run gets switched off. What a
team actually wants from CI is a narrower question: *did this change make things worse?*

So a diff distinguishes new findings from ones already known, and a gate can fail only
on the new ones. Existing issues stay visible in the report without blocking every
build while they are being worked through.

Identity across scans is the hard part, and it was already solved for SARIF: findings
are matched on :func:`~promptsentinel.reporting.sarif.fingerprint`, which covers the
probe, category and title and deliberately excludes evidence and proof. Those contain
canaries minted fresh every run, so fingerprinting them would make every finding look
new and the diff would report nothing but churn.

Coverage is compared too. "No new findings" means something very different when a probe
that ran last time errored this time, so a diff that only counted findings would be
quietly reassuring at exactly the wrong moment.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.core.models import Confidence, Finding
from promptsentinel.reporting.sarif import fingerprint

_TIER_RANK = {
    Confidence.INFORMATIONAL: 0,
    Confidence.SUSPICIOUS: 1,
    Confidence.CONFIRMED: 2,
}


@dataclass(frozen=True)
class ProbeCoverage:
    """How a probe fared in one scan."""

    probe_id: str
    status: str

    @property
    def produced_a_verdict(self) -> bool:
        """Whether this run actually tested anything.

        ``skipped`` counts as no verdict as much as ``errored`` does: the attack path
        was not exercised either way.
        """
        return self.status == "completed"


@dataclass(frozen=True)
class ScanReportData:
    """The parts of a saved report a diff needs."""

    target: str
    findings: list[Finding]
    coverage: dict[str, ProbeCoverage]


@dataclass
class ScanDiff:
    """What changed between two scans."""

    baseline_target: str
    current_target: str
    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    coverage_lost: list[str] = field(default_factory=list)
    coverage_gained: list[str] = field(default_factory=list)

    @property
    def same_target(self) -> bool:
        return self.baseline_target == self.current_target

    def new_at_or_above(self, tier: Confidence) -> list[Finding]:
        """New findings at ``tier`` or more certain. What a CI gate acts on."""
        return [f for f in self.new if _TIER_RANK[f.confidence] >= _TIER_RANK[tier]]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "unchanged": len(self.unchanged),
            "coverage_lost": len(self.coverage_lost),
            "coverage_gained": len(self.coverage_gained),
        }


def load_report(path: Path) -> ScanReportData:
    """Read a report written by ``promptsentinel scan --format json``.

    Findings are rebuilt through the domain model rather than used as raw dicts, so a
    report edited by hand to upgrade a finding's tier fails to load instead of being
    diffed as though it were real.
    """
    try:
        payload: dict[str, Any] = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"could not read report {path}: {exc}") from exc
    if not isinstance(payload, dict) or "findings" not in payload:
        raise ConfigurationError(
            f"{path} is not a PromptSentinel JSON report "
            "(write one with: promptsentinel scan --format json --output FILE)"
        )

    try:
        findings = [Finding.model_validate(f) for f in payload["findings"]]
    except Exception as exc:
        raise ConfigurationError(f"{path} contains an invalid finding: {exc}") from exc

    coverage = {
        run["probe_id"]: ProbeCoverage(probe_id=run["probe_id"], status=run["status"])
        for run in payload.get("probe_runs", [])
    }
    return ScanReportData(
        target=str(payload.get("target", "unknown")), findings=findings, coverage=coverage
    )


def diff_reports(baseline: ScanReportData, current: ScanReportData) -> ScanDiff:
    """Compare two scans."""
    before = {fingerprint(f): f for f in baseline.findings}
    after = {fingerprint(f): f for f in current.findings}

    result = ScanDiff(
        baseline_target=baseline.target,
        current_target=current.target,
        new=[f for key, f in after.items() if key not in before],
        fixed=[f for key, f in before.items() if key not in after],
        unchanged=[f for key, f in after.items() if key in before],
    )

    for probe_id, was in baseline.coverage.items():
        now = current.coverage.get(probe_id)
        if was.produced_a_verdict and (now is None or not now.produced_a_verdict):
            # Reported prominently rather than folded into the counts: a finding that
            # disappeared because its probe stopped running has not been fixed.
            result.coverage_lost.append(probe_id)
    for probe_id, now in current.coverage.items():
        previously = baseline.coverage.get(probe_id)
        if now.produced_a_verdict and (previously is None or not previously.produced_a_verdict):
            result.coverage_gained.append(probe_id)

    result.coverage_lost.sort()
    result.coverage_gained.sort()
    return result


def render_text(diff: ScanDiff, *, fail_on: Confidence | None = Confidence.CONFIRMED) -> str:
    """Human-readable summary, newest problems first."""
    lines = ["", f"PromptSentinel diff of {diff.current_target}", ""]
    if not diff.same_target:
        lines.append(
            f"  WARNING: comparing different targets "
            f"({diff.baseline_target} -> {diff.current_target}); the diff may be meaningless."
        )
        lines.append("")

    if diff.coverage_lost:
        lines.append(
            "  COVERAGE LOST: these probes produced a verdict before and did not this "
            "time, so any finding they would have reported is simply absent:"
        )
        lines.extend(f"    - {probe_id}" for probe_id in diff.coverage_lost)
        lines.append("")

    for label, findings in (("NEW", diff.new), ("FIXED", diff.fixed)):
        if not findings:
            continue
        lines.append(f"  {label} ({len(findings)}):")
        for finding in sorted(findings, key=lambda f: -_TIER_RANK[f.confidence]):
            lines.append(
                f"    [{finding.confidence.value}] {finding.severity.value} "
                f"{finding.probe_id} - {finding.title}"
            )
        lines.append("")

    if not diff.new and not diff.fixed:
        lines.append("  No change in findings.")
        lines.append("")

    counts = diff.counts
    lines.append(f"  {counts['new']} new, {counts['fixed']} fixed, {counts['unchanged']} unchanged")
    if fail_on is not None:
        blocking = diff.new_at_or_above(fail_on)
        lines.append(
            f"  {len(blocking)} new finding(s) at or above '{fail_on.value}'"
            + (" - gate fails" if blocking else " - gate passes")
        )
    lines.append("")
    return "\n".join(lines)


def render_json(diff: ScanDiff) -> str:
    """Machine-readable diff."""

    def summarise(findings: Sequence[Finding]) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": fingerprint(f),
                "probe_id": f.probe_id,
                "category": f.category.value,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
            }
            for f in findings
        ]

    return json.dumps(
        {
            "baseline_target": diff.baseline_target,
            "current_target": diff.current_target,
            "same_target": diff.same_target,
            "summary": diff.counts,
            "new": summarise(diff.new),
            "fixed": summarise(diff.fixed),
            "unchanged": summarise(diff.unchanged),
            "coverage_lost": diff.coverage_lost,
            "coverage_gained": diff.coverage_gained,
        },
        indent=2,
    )
