"""Canary minting and detection: the machinery behind every CONFIRMED finding."""

from __future__ import annotations

from promptsentinel.core.canary import (
    CANARY_PREFIX,
    canary_proof,
    find_canaries,
    mint_canary,
    redact,
)
from promptsentinel.core.models import ProofKind


class TestMinting:
    def test_canaries_are_unique(self):
        values = {mint_canary("x").value for _ in range(200)}
        assert len(values) == 200

    def test_value_is_prefixed_and_high_entropy(self):
        canary = mint_canary("secret")
        assert canary.value.startswith(f"{CANARY_PREFIX}-")
        assert len(canary.value) >= len(CANARY_PREFIX) + 33

    def test_value_carries_no_semantic_hint(self):
        """A target told to hide 'passwords' must not recognise the canary by shape."""
        assert "password" not in mint_canary("admin_password").value.lower()


class TestDetection:
    def test_exact_match(self):
        canary = mint_canary("x")
        assert find_canaries(f"the key is {canary.value}!", [canary]) == [canary]

    def test_no_match_returns_empty(self):
        canary = mint_canary("x")
        assert find_canaries("I cannot share that information.", [canary]) == []

    def test_empty_text_is_safe(self):
        assert find_canaries("", [mint_canary("x")]) == []

    def test_survives_markdown_wrapping(self):
        """Models wrap leaked values in backticks and split them across lines."""
        canary = mint_canary("x")
        chopped = f"`{canary.value[:10]}`\n`{canary.value[10:]}`"
        assert find_canaries(chopped, [canary]) == [canary]

    def test_survives_interleaved_punctuation(self):
        canary = mint_canary("x")
        spaced = "-".join(canary.value)
        assert find_canaries(spaced, [canary]) == [canary]

    def test_does_not_match_a_different_canary(self):
        """Normalization must never widen matching enough to create a false positive."""
        planted, other = mint_canary("a"), mint_canary("b")
        assert find_canaries(other.value, [planted]) == []

    def test_reports_only_the_canaries_present(self):
        present, absent = mint_canary("a"), mint_canary("b")
        assert find_canaries(f"...{present.value}...", [present, absent]) == [present]


class TestRedaction:
    def test_redacted_value_is_not_replayable(self):
        canary = mint_canary("x")
        assert canary.value not in canary.redacted
        assert canary.redacted.startswith(canary.value[:8])

    def test_short_values_are_fully_hidden(self):
        assert redact("abc") == "[redacted]"


class TestProofConstruction:
    def test_proof_records_the_kind_and_redacts_the_value(self):
        canary = mint_canary("system_secret", placement="system_prompt")
        proof = canary_proof(canary)
        assert proof.kind is ProofKind.CANARY_DISCLOSURE
        assert canary.value not in proof.matched_value
        assert "system_prompt" in proof.detail

    def test_two_canaries_are_distinguishable_when_redacted(self):
        """Redacting down to the shared prefix would make a report unreadable."""
        a, b = mint_canary("first"), mint_canary("second")
        assert a.redacted != b.redacted
