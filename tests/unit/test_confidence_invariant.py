"""The confidence tier is the product's core promise. These tests defend it.

If any test in this file goes red, the tool is claiming certainty it does not have.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from promptsentinel.core.models import (
    Confidence,
    Evidence,
    Finding,
    ProbeCategory,
    ProbeResult,
    ProbeStatus,
    Proof,
    ProofKind,
    Severity,
)

EVIDENCE = Evidence(prompt="p", response="r")
PROOF = Proof(kind=ProofKind.CANARY_DISCLOSURE, detail="d", matched_value="PSCANARY-abc...")


def _kwargs(**overrides):
    base = {
        "probe_id": "test.probe",
        "category": ProbeCategory.DIAGNOSTIC,
        "title": "t",
        "description": "d",
        "severity": Severity.HIGH,
        "evidence": EVIDENCE,
    }
    base.update(overrides)
    return base


class TestConfirmedRequiresProof:
    def test_confirmed_without_proof_is_rejected(self):
        with pytest.raises(ValidationError, match="requires proof"):
            Finding(**_kwargs(confidence=Confidence.CONFIRMED, proof=None))

    def test_proof_without_confirmed_is_rejected(self):
        """Prevents a probe hedging: attaching proof while claiming a lower tier."""
        with pytest.raises(ValidationError, match="proof implies CONFIRMED"):
            Finding(**_kwargs(confidence=Confidence.SUSPICIOUS, proof=PROOF))

    def test_confirmed_with_proof_is_accepted(self):
        finding = Finding.confirmed(**_kwargs(), proof=PROOF)
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.proof is not None


class TestNoSilentUpgrade:
    """A suspicious finding must not become confirmed after the fact."""

    def test_finding_is_immutable(self):
        finding = Finding.suspicious(**_kwargs(), signals=["looks_weird"])
        with pytest.raises(ValidationError):
            finding.confidence = Confidence.CONFIRMED  # type: ignore[misc]

    def test_model_copy_cannot_upgrade_confidence(self):
        """Pydantic's model_copy skips validators by default.

        Finding overrides it to re-validate, so this documented escape hatch cannot
        be used to launder a suspicious finding into a confirmed one.
        """
        finding = Finding.suspicious(**_kwargs(), signals=["looks_weird"])
        with pytest.raises(ValidationError, match="requires proof"):
            finding.model_copy(update={"confidence": Confidence.CONFIRMED})

    def test_model_copy_still_works_for_legitimate_updates(self):
        finding = Finding.suspicious(**_kwargs(), signals=["a"])
        assert finding.model_copy(update={"title": "new"}).title == "new"

    def test_suspicious_constructor_takes_no_proof(self):
        with pytest.raises(TypeError):
            Finding.suspicious(**_kwargs(), signals=[], proof=PROOF)  # type: ignore[call-arg]


class TestProbeResultIntegrity:
    def test_errored_result_cannot_carry_findings(self):
        """A failed probe reporting findings would be reporting on work it did not do."""
        finding = Finding.suspicious(**_kwargs(), signals=["s"])
        with pytest.raises(ValidationError, match="must not report findings"):
            ProbeResult(
                probe_id="test.probe",
                status=ProbeStatus.ERRORED,
                error="boom",
                findings=[finding],
            )

    def test_errored_result_requires_a_message(self):
        with pytest.raises(ValidationError, match="must carry an error message"):
            ProbeResult(probe_id="test.probe", status=ProbeStatus.ERRORED)

    def test_completed_with_no_findings_is_valid(self):
        result = ProbeResult.completed("test.probe", [])
        assert result.status is ProbeStatus.COMPLETED
        assert result.findings == []
