"""The authorization gate. The one control that keeps this tool ethical."""

from __future__ import annotations

import pytest

from promptsentinel.core.authorization import (
    REQUIRED_ATTESTATION,
    Authorization,
    require_authorization,
)
from promptsentinel.core.errors import AuthorizationError


def _authorize(**overrides):
    kwargs = {
        "confirmed": True,
        "attested_by": "tester@example.com",
        "statement": REQUIRED_ATTESTATION,
    }
    kwargs.update(overrides)
    return require_authorization(**kwargs)


class TestGateAccepts:
    def test_valid_attestation(self):
        authorization = _authorize(reference="TICKET-1")
        assert authorization.confirmed
        assert authorization.reference == "TICKET-1"

    @pytest.mark.parametrize(
        "statement",
        [
            REQUIRED_ATTESTATION.upper(),
            REQUIRED_ATTESTATION.rstrip("."),
            f"  {REQUIRED_ATTESTATION}  ",
            REQUIRED_ATTESTATION.replace(" ", "  "),
        ],
    )
    def test_statement_is_compared_by_substance(self, statement):
        """Casing and whitespace are formatting. The words are what matter."""
        assert _authorize(statement=statement).confirmed


class TestGateRefuses:
    def test_missing_confirmation(self):
        with pytest.raises(AuthorizationError, match="refusing to scan"):
            _authorize(confirmed=False)

    def test_empty_statement(self):
        with pytest.raises(AuthorizationError):
            _authorize(statement="")

    def test_close_but_wrong_statement(self):
        """'yes I promise' is not the attestation. Near-misses must fail closed."""
        with pytest.raises(AuthorizationError):
            _authorize(statement="yes I own this target I promise")

    def test_negated_statement_is_not_accepted(self):
        with pytest.raises(AuthorizationError):
            _authorize(statement="I do not own or am authorized to security test this target.")

    def test_anonymous_attestation(self):
        """Someone must be named. An attestation nobody signed is not an audit record."""
        with pytest.raises(AuthorizationError):
            _authorize(attested_by="   ")


class TestDefenseInDepth:
    def test_verify_catches_validator_bypass(self):
        """model_construct skips validators. verify() is the engine's second check."""
        forged = Authorization.model_construct(
            confirmed=False, attested_by="", statement="whatever", reference=None
        )
        with pytest.raises(AuthorizationError, match="invalid authorization"):
            forged.verify()

    def test_verify_passes_for_a_real_attestation(self):
        _authorize().verify()

    def test_authorization_is_immutable(self):
        authorization = _authorize()
        with pytest.raises(Exception):  # noqa: B017 - pydantic raises ValidationError
            authorization.confirmed = False  # type: ignore[misc]
