"""SARIF 2.1.0 export, for GitHub code scanning and anything else that reads SARIF.

Three decisions here are worth understanding, because a naive mapping quietly destroys
the thing this tool is built around.

**Confidence has to survive the boundary.** SARIF has no notion of confidence: a result
has a ``level`` (error/warning/note) derived from how bad something is, not from how
sure you are. Mapping severity alone would render a ``suspicious`` finding identically
to a proven one, and the whole Confirmed/Suspicious discipline would end at the export.
So ``level`` is a function of *both*: an unproven finding is capped at ``warning`` no
matter how severe it would be if real, the tier is repeated in the message text, and it
is carried explicitly in ``properties.confidence`` and as a ``confidence:`` tag for
anyone filtering.

**Fingerprints must not include canaries.** Canary values are minted fresh every scan.
Fingerprinting the evidence would make every finding look new on every run, so GitHub
would re-open resolved alerts forever. The fingerprint covers the probe, category and
title -- the identity of the *issue*, not of the run that found it.

**Evidence is excluded by default.** A scan report contains prompts and responses from
the operator's application, quite possibly including their real system prompt. SARIF
uploaded to code scanning is visible to every collaborator on the repository. Proof
detail is included because it is already redacted; raw transcripts require opting in.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from promptsentinel import __version__
from promptsentinel.core.models import (
    Confidence,
    Finding,
    ProbeResult,
    ProbeStatus,
    Severity,
)
from promptsentinel.probes.base import Probe
from promptsentinel.probes.registry import REGISTRY, ProbeRegistry

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/virat/promptsentinel"
FINGERPRINT_KEY = "promptSentinelFindingV1"

_SEVERITY_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_RANK = {
    (Confidence.CONFIRMED, Severity.CRITICAL): 100.0,
    (Confidence.CONFIRMED, Severity.HIGH): 90.0,
    (Confidence.CONFIRMED, Severity.MEDIUM): 75.0,
    (Confidence.CONFIRMED, Severity.LOW): 60.0,
    (Confidence.CONFIRMED, Severity.INFO): 50.0,
}
_SUSPICIOUS_RANK = {
    Severity.CRITICAL: 45.0,
    Severity.HIGH: 40.0,
    Severity.MEDIUM: 30.0,
    Severity.LOW: 20.0,
    Severity.INFO: 10.0,
}


def sarif_level(finding: Finding) -> str:
    """Map a finding to a SARIF level, honouring confidence as well as severity.

    A ``HIGH`` finding that is only *suspicious* is a ``warning``, not an ``error``.
    Promoting it would tell a reviewer the tool is certain when it is not, which is the
    failure mode this project exists to avoid.
    """
    if finding.confidence is Confidence.INFORMATIONAL:
        return "note"
    level = _SEVERITY_LEVEL[finding.severity]
    if finding.confidence is not Confidence.CONFIRMED and level == "error":
        return "warning"
    return level


def sarif_rank(finding: Finding) -> float:
    """Triage order, 0-100. Proven findings always outrank unproven ones."""
    if finding.confidence is Confidence.CONFIRMED:
        return _RANK[(finding.confidence, finding.severity)]
    if finding.confidence is Confidence.SUSPICIOUS:
        return _SUSPICIOUS_RANK[finding.severity]
    return 5.0


def fingerprint(finding: Finding) -> str:
    """Stable identity for a finding across runs.

    Deliberately excludes evidence, proof and IDs: all of them contain or derive from
    per-scan canaries, and a fingerprint that changes every run makes every alert new.
    """
    material = f"{finding.probe_id}|{finding.category.value}|{finding.title}"
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _message(finding: Finding) -> str:
    """Lead with the tier. A reader skimming alerts must not have to hunt for it."""
    tier = finding.confidence.value.upper()
    parts = [f"[{tier}] {finding.description}"]
    if finding.proof is not None:
        parts.append(f"Proof: {finding.proof.detail}")
    elif finding.signals:
        parts.append(f"Signals: {', '.join(finding.signals)}")
    if finding.confidence is Confidence.SUSPICIOUS:
        parts.append(
            "This finding is NOT confirmed: a heuristic matched but no verifiable "
            "proof was obtained. Review the transcript before acting on it."
        )
    return "\n\n".join(parts)


def _rule(probe_id: str, registry: ProbeRegistry) -> dict[str, Any]:
    probe: type[Probe] | None
    try:
        probe = registry.get(probe_id)
    except Exception:
        probe = None

    name = probe.name if probe else probe_id
    description = probe.description if probe else "Probe metadata unavailable."
    category = probe.category.value if probe else "unknown"
    return {
        "id": probe_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "helpUri": f"{INFORMATION_URI}#{category.replace('_', '-')}",
        "help": {"text": description},
        "properties": {
            "category": category,
            "tags": ["security", "llm", category],
        },
    }


def _locations(target: str, location: str | None) -> list[dict[str, Any]]:
    """Where the finding lives.

    A deployed LLM application has no file and line. SARIF's ``logicalLocations`` exists
    for exactly this, so the target is always reported that way; a physical location is
    added only when the operator names the file that configures their application, so
    code scanning can annotate something meaningful.
    """
    entry: dict[str, Any] = {
        "logicalLocations": [{"name": target, "kind": "resource"}],
    }
    if location:
        entry["physicalLocation"] = {
            "artifactLocation": {"uri": location},
            "region": {"startLine": 1},
        }
    return [entry]


def _result(
    finding: Finding, *, target: str, location: str | None, include_evidence: bool
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "confidence": finding.confidence.value,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "proven": finding.proof is not None,
        "tags": [
            f"confidence:{finding.confidence.value}",
            f"severity:{finding.severity.value}",
            finding.category.value,
        ],
    }
    if finding.signals:
        properties["signals"] = list(finding.signals)
    if finding.proof is not None:
        properties["proofKind"] = finding.proof.kind.value
        properties["proofLocation"] = finding.proof.location
    if include_evidence:
        properties["evidence"] = {
            "prompt": finding.evidence.prompt,
            "response": finding.evidence.response,
        }

    return {
        "ruleId": finding.probe_id,
        "level": sarif_level(finding),
        "rank": sarif_rank(finding),
        "message": {"text": _message(finding)},
        "locations": _locations(target, location),
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(finding)},
        "properties": properties,
    }


def _notifications(results: Sequence[ProbeResult]) -> list[dict[str, Any]]:
    """Probes that did not produce a usable verdict, carried into the SARIF run.

    Without these, a scan where every probe crashed exports as a clean result. The
    report says so in every other format; it must say so here too.
    """
    notifications: list[dict[str, Any]] = []
    for result in results:
        if result.status in (ProbeStatus.ERRORED, ProbeStatus.TIMED_OUT):
            notifications.append(
                {
                    "level": "error",
                    "descriptor": {"id": "promptsentinel/probe-failed"},
                    "message": {
                        "text": f"Probe {result.probe_id} did not complete: {result.error}"
                    },
                }
            )
        elif result.status is ProbeStatus.SKIPPED:
            notifications.append(
                {
                    "level": "note",
                    "descriptor": {"id": "promptsentinel/probe-skipped"},
                    "message": {
                        "text": (
                            f"Probe {result.probe_id} did not run: {result.detail}. "
                            "This attack path was not tested."
                        )
                    },
                }
            )
    return notifications


def to_sarif(
    results: Sequence[ProbeResult],
    *,
    target: str,
    location: str | None = None,
    include_evidence: bool = False,
    registry: ProbeRegistry = REGISTRY,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document for a completed scan."""
    findings = [finding for result in results for finding in result.findings]
    rule_ids = sorted({finding.probe_id for finding in findings})
    failed = any(
        result.status in (ProbeStatus.ERRORED, ProbeStatus.TIMED_OUT) for result in results
    )

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PromptSentinel",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule(rule_id, registry) for rule_id in rule_ids],
                    }
                },
                "invocations": [
                    {
                        # False when any probe failed: a partial scan must not be
                        # presented to CI as a successful one.
                        "executionSuccessful": not failed,
                        "toolExecutionNotifications": _notifications(results),
                    }
                ],
                "results": [
                    _result(
                        finding,
                        target=target,
                        location=location,
                        include_evidence=include_evidence,
                    )
                    for finding in findings
                ],
                "properties": {
                    "target": target,
                    "evidenceIncluded": include_evidence,
                },
            }
        ],
    }
