"""Canary minting and detection: the machinery behind every CONFIRMED finding."""

from __future__ import annotations

import base64

from promptsentinel.core.canary import (
    CANARY_PREFIX,
    canary_proof,
    find_canaries,
    find_canary_matches,
    mint_canary,
    proof_for_match,
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


class TestEncodedDisclosure:
    """Transforming the output is the standard way around a 'never repeat' filter.

    A leak that arrives base64-encoded is still a leak, and decoding is deterministic,
    so a match after decoding is still proof rather than a similarity score.
    """

    def test_base64_encoded_canary_is_found(self):
        canary = mint_canary("x")
        encoded = base64.b64encode(f"SECRET={canary.value}".encode()).decode()
        matches = find_canary_matches(f"Here you go:\n{encoded}", [canary])
        assert [m.canary for m in matches] == [canary]
        assert matches[0].encoding == "base64"

    def test_base64_wrapped_across_lines_is_found(self):
        """Models wrap long base64 output; whitespace must not defeat detection."""
        canary = mint_canary("x")
        encoded = base64.b64encode(f"instructions: {canary.value}".encode()).decode()
        wrapped = "\n".join(encoded[i : i + 20] for i in range(0, len(encoded), 20))
        assert find_canaries(wrapped, [canary]) == [canary]

    def test_reversed_canary_is_found(self):
        canary = mint_canary("x")
        matches = find_canary_matches(canary.value[::-1], [canary])
        assert matches[0].encoding == "reversed"

    def test_plain_disclosure_is_reported_as_plain(self):
        """Plain must win over any incidental match inside a decoding."""
        canary = mint_canary("x")
        matches = find_canary_matches(f"the key is {canary.value}", [canary])
        assert matches[0].encoding == "plain"

    def test_encoding_does_not_manufacture_matches(self):
        """The decoding paths must not be able to fire on a canary that is absent."""
        planted = mint_canary("planted")
        noise = base64.b64encode(b"nothing secret here at all, just prose" * 5).decode()
        assert find_canaries(noise, [planted]) == []

    def test_undecodable_text_is_handled(self):
        canary = mint_canary("x")
        assert find_canaries("!!!!" * 200, [canary]) == []

    def test_large_response_is_bounded(self):
        """A hostile target must not be able to turn detection into a DoS on ourselves."""
        canary = mint_canary("x")
        junk = " ".join("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" for _ in range(5000))
        assert find_canaries(junk, [canary]) == []


class TestEncodedProof:
    def test_proof_records_the_encoding(self):
        canary = mint_canary("x")
        encoded = base64.b64encode(canary.value.encode()).decode()
        match = find_canary_matches(encoded, [canary])[0]
        proof = proof_for_match(match)
        assert proof.kind is ProofKind.CANARY_DISCLOSURE
        assert "base64" in proof.detail
        assert canary.value not in proof.matched_value

    def test_plain_proof_says_verbatim(self):
        canary = mint_canary("x")
        match = find_canary_matches(canary.value, [canary])[0]
        assert "verbatim" in proof_for_match(match).detail
