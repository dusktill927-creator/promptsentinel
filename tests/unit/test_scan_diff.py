"""Comparing two scans.

The behaviour that makes this worth having is narrow: fail on findings that are *new*,
stay quiet about ones already known. A gate that fires on a backlog gets switched off,
and a switched-off gate protects nothing.
"""

from __future__ import annotations

import json

import pytest

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.core.models import (
    Confidence,
    Evidence,
    Finding,
    ProbeCategory,
    Proof,
    ProofKind,
    Severity,
)
from promptsentinel.reporting.diff import (
    ProbeCoverage,
    ScanReportData,
    diff_reports,
    load_report,
    render_json,
    render_text,
)

PROOF = Proof(kind=ProofKind.CANARY_DISCLOSURE, detail="d", matched_value="x")


def confirmed(probe_id="a.b", title="Leak") -> Finding:
    return Finding.confirmed(
        probe_id=probe_id,
        category=ProbeCategory.SYSTEM_PROMPT_EXTRACTION,
        title=title,
        description="d",
        severity=Severity.HIGH,
        evidence=Evidence(prompt="p", response="r"),
        proof=PROOF,
    )


def suspicious(probe_id="c.d", title="Maybe") -> Finding:
    return Finding.suspicious(
        probe_id=probe_id,
        category=ProbeCategory.JAILBREAK,
        title=title,
        description="d",
        severity=Severity.MEDIUM,
        evidence=Evidence(prompt="p", response="r"),
        signals=["s"],
    )


def report(*findings, coverage=None, target="mock") -> ScanReportData:
    return ScanReportData(
        target=target,
        findings=list(findings),
        coverage=coverage or {},
    )


class TestMatching:
    def test_an_unchanged_finding_is_not_new(self):
        result = diff_reports(report(confirmed()), report(confirmed()))
        assert result.new == []
        assert len(result.unchanged) == 1

    def test_findings_match_across_scans_despite_fresh_canaries(self):
        """Evidence differs every run; identity must not depend on it."""
        first = confirmed()
        second = confirmed().model_copy(
            update={"evidence": Evidence(prompt="different", response="different")}
        )
        result = diff_reports(report(first), report(second))
        assert result.new == []

    def test_a_genuinely_new_finding_is_reported(self):
        result = diff_reports(report(confirmed()), report(confirmed(), suspicious()))
        assert [f.probe_id for f in result.new] == ["c.d"]

    def test_a_resolved_finding_is_reported_fixed(self):
        result = diff_reports(report(confirmed(), suspicious()), report(confirmed()))
        assert [f.probe_id for f in result.fixed] == ["c.d"]

    def test_a_different_title_from_the_same_probe_is_new(self):
        """A probe escalating from suspicious to confirmed changes its title."""
        result = diff_reports(
            report(suspicious(probe_id="x.y", title="Possible leak")),
            report(confirmed(probe_id="x.y", title="Leak confirmed")),
        )
        assert len(result.new) == 1
        assert len(result.fixed) == 1


class TestGating:
    def test_new_confirmed_findings_trip_the_gate(self):
        result = diff_reports(report(), report(confirmed()))
        assert len(result.new_at_or_above(Confidence.CONFIRMED)) == 1

    def test_a_new_suspicious_finding_does_not_trip_a_confirmed_gate(self):
        result = diff_reports(report(), report(suspicious()))
        assert result.new_at_or_above(Confidence.CONFIRMED) == []
        assert len(result.new_at_or_above(Confidence.SUSPICIOUS)) == 1

    def test_pre_existing_findings_never_trip_the_gate(self):
        """The whole point: a backlog must not fail every build."""
        result = diff_reports(report(confirmed()), report(confirmed()))
        assert result.new_at_or_above(Confidence.CONFIRMED) == []


class TestCoverage:
    def test_a_probe_that_stopped_running_is_flagged(self):
        """A finding that vanished because its probe errored has not been fixed."""
        before = report(coverage={"a.b": ProbeCoverage("a.b", "completed")})
        after = report(coverage={"a.b": ProbeCoverage("a.b", "errored")})
        assert diff_reports(before, after).coverage_lost == ["a.b"]

    def test_a_skipped_probe_counts_as_lost_coverage(self):
        before = report(coverage={"a.b": ProbeCoverage("a.b", "completed")})
        after = report(coverage={"a.b": ProbeCoverage("a.b", "skipped")})
        assert diff_reports(before, after).coverage_lost == ["a.b"]

    def test_a_probe_that_started_working_is_flagged(self):
        before = report(coverage={"a.b": ProbeCoverage("a.b", "skipped")})
        after = report(coverage={"a.b": ProbeCoverage("a.b", "completed")})
        assert diff_reports(before, after).coverage_gained == ["a.b"]

    def test_stable_coverage_reports_neither(self):
        cov = {"a.b": ProbeCoverage("a.b", "completed")}
        result = diff_reports(report(coverage=cov), report(coverage=cov))
        assert result.coverage_lost == [] and result.coverage_gained == []


class TestRendering:
    def test_text_names_new_findings_and_the_verdict(self):
        out = render_text(diff_reports(report(), report(confirmed())))
        assert "NEW (1)" in out
        assert "gate fails" in out

    def test_text_says_so_when_nothing_changed(self):
        out = render_text(diff_reports(report(confirmed()), report(confirmed())))
        assert "No change in findings." in out
        assert "gate passes" in out

    def test_lost_coverage_is_prominent(self):
        before = report(coverage={"a.b": ProbeCoverage("a.b", "completed")})
        after = report(coverage={"a.b": ProbeCoverage("a.b", "errored")})
        out = render_text(diff_reports(before, after))
        assert "COVERAGE LOST" in out
        assert out.index("COVERAGE LOST") < out.index("new,")

    def test_a_different_target_is_called_out(self):
        """Diffing two different applications produces meaningless results."""
        out = render_text(diff_reports(report(target="app-a"), report(target="app-b")))
        assert "WARNING" in out and "different targets" in out

    def test_json_is_parseable_and_carries_fingerprints(self):
        payload = json.loads(render_json(diff_reports(report(), report(confirmed()))))
        assert payload["summary"]["new"] == 1
        assert payload["new"][0]["fingerprint"]
        assert payload["new"][0]["probe_id"] == "a.b"


class TestLoading:
    def test_a_real_report_round_trips(self, tmp_path):
        from promptsentinel.cli.render import render_json as report_json
        from promptsentinel.core.models import ProbeResult
        from promptsentinel.engine.runner import ScanOutcome

        outcome = ScanOutcome(results=[ProbeResult.completed("a.b", [confirmed()])], canaries=[])
        path = tmp_path / "r.json"
        path.write_text(report_json(outcome, target="mock"))

        loaded = load_report(path)
        assert loaded.target == "mock"
        assert len(loaded.findings) == 1
        assert loaded.coverage["a.b"].produced_a_verdict

    def test_a_missing_file_is_a_clear_error(self, tmp_path):
        with pytest.raises(ConfigurationError, match="could not read"):
            load_report(tmp_path / "nope.json")

    def test_a_non_report_json_file_is_rejected(self, tmp_path):
        path = tmp_path / "other.json"
        path.write_text('{"hello": "world"}')
        with pytest.raises(ConfigurationError, match="not a PromptSentinel"):
            load_report(path)

    def test_a_tampered_finding_fails_to_load(self, tmp_path):
        """Rebuilt through the domain model, so the confidence invariant still applies."""
        path = tmp_path / "t.json"
        path.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            **json.loads(suspicious().model_dump_json()),
                            "confidence": "confirmed",
                        }
                    ]
                }
            )
        )
        with pytest.raises(ConfigurationError, match="invalid finding"):
            load_report(path)
