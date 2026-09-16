"""Report rendering for the terminal.

Plain ANSI rather than a rendering library: one less dependency in a security tool, and
colour is a progressive enhancement -- every line is readable when piped to a file or a
CI log, which is where these reports usually end up.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from promptsentinel.core.models import Confidence, ProbeResult, ProbeStatus, Severity
from promptsentinel.engine.runner import ScanOutcome

_COLOURS = {
    Confidence.CONFIRMED: "\033[1;31m",
    Confidence.SUSPICIOUS: "\033[1;33m",
    Confidence.INFORMATIONAL: "\033[1;34m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_CONFIDENCE_ORDER = {
    Confidence.CONFIRMED: 0,
    Confidence.SUSPICIOUS: 1,
    Confidence.INFORMATIONAL: 2,
}


def _colour(text: str, code: str, *, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def summarise(outcome: ScanOutcome) -> dict[str, int]:
    findings = [f for result in outcome.results for f in result.findings]
    return {
        "confirmed": sum(1 for f in findings if f.confidence is Confidence.CONFIRMED),
        "suspicious": sum(1 for f in findings if f.confidence is Confidence.SUSPICIOUS),
        "informational": sum(1 for f in findings if f.confidence is Confidence.INFORMATIONAL),
        "probes_run": len(outcome.results),
        "probes_errored": sum(
            1 for r in outcome.results if r.status in (ProbeStatus.ERRORED, ProbeStatus.TIMED_OUT)
        ),
        "probes_skipped": sum(1 for r in outcome.results if r.status is ProbeStatus.SKIPPED),
    }


def render_text(outcome: ScanOutcome, *, target: str, colour: bool | None = None) -> str:
    """Human-readable report."""
    enabled = sys.stdout.isatty() if colour is None else colour
    counts = summarise(outcome)
    lines: list[str] = ["", f"PromptSentinel scan of {target}", ""]

    findings = sorted(
        (f for result in outcome.results for f in result.findings),
        key=lambda f: (_CONFIDENCE_ORDER[f.confidence], _SEVERITY_ORDER[f.severity]),
    )
    if not findings:
        lines.append("  No findings.")
    for finding in findings:
        tier = _colour(
            finding.confidence.value.upper(), _COLOURS[finding.confidence], enabled=enabled
        )
        lines.append(f"  [{tier}] {finding.severity.value.upper():<8} {finding.title}")
        lines.append(f"      probe: {finding.probe_id}")
        if finding.proof is not None:
            lines.append(f"      proof: {finding.proof.detail}")
        if finding.signals:
            lines.append(f"      signals: {', '.join(finding.signals)}")
        lines.append("")

    # Errored and skipped probes are printed, not hidden: "0 findings" reads very
    # differently when three probes never ran.
    for result in outcome.results:
        if result.status is ProbeStatus.SKIPPED:
            lines.append(
                _colour(f"  skipped: {result.probe_id} - {result.detail}", _DIM, enabled=enabled)
            )
        elif result.status in (ProbeStatus.ERRORED, ProbeStatus.TIMED_OUT):
            lines.append(f"  ERRORED: {result.probe_id} - {result.error}")

    lines.extend(
        [
            "",
            f"  {counts['confirmed']} confirmed, {counts['suspicious']} suspicious, "
            f"{counts['informational']} informational",
            f"  {counts['probes_run']} probes run, {counts['probes_errored']} errored, "
            f"{counts['probes_skipped']} skipped",
            "",
        ]
    )
    return "\n".join(lines)


def render_json(outcome: ScanOutcome, *, target: str) -> str:
    """Machine-readable report, for piping into other tooling."""
    payload: dict[str, Any] = {
        "target": target,
        "summary": summarise(outcome),
        "findings": [
            json.loads(f.model_dump_json()) for result in outcome.results for f in result.findings
        ],
        "probe_runs": [_run(result) for result in outcome.results],
        "canaries_seeded": [
            {"id": c.id, "label": c.label, "placement": c.placement, "value": c.redacted}
            for c in outcome.canaries
        ],
    }
    return json.dumps(payload, indent=2)


def _run(result: ProbeResult) -> dict[str, Any]:
    return {
        "probe_id": result.probe_id,
        "status": result.status.value,
        "attempts": result.attempts,
        "duration_ms": result.duration_ms,
        "error": result.error,
        "detail": result.detail,
        "last_response": result.last_response,
    }
