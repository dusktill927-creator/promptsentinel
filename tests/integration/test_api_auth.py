"""API authentication.

An unauthenticated instance is a machine that will attack any URL anyone posts to it,
with the operator's credentials and from the operator's network. These tests cover the
three things that keeps honest: it fails closed at startup, it guards the endpoints that
matter, and it leaks nothing about which keys exist.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from promptsentinel.api.app import create_app
from promptsentinel.api.security import generate_key, hash_key, verify
from promptsentinel.config import Settings
from promptsentinel.core.errors import ConfigurationError
from promptsentinel.db.session import Database
from tests.conftest import LEAKY_MOCK_TARGET, VALID_AUTHORIZATION

KEY = "ps_test_key_value"
OTHER_KEY = "ps_other_key_value"
GUARDED = ["/v1/scans", "/v1/probes"]


@pytest.fixture
def auth_settings(tmp_path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/auth.db",
        api_key_hashes=[hash_key(KEY), hash_key(OTHER_KEY)],
        allow_unauthenticated=False,
        allow_mock_targets=True,
    )


@pytest.fixture
async def auth_client(auth_settings: Settings) -> AsyncIterator[AsyncClient]:
    database = Database(auth_settings.database_url)
    await database.create_all()
    app: FastAPI = create_app(settings=auth_settings, database=database)
    try:
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as http:
                yield http
    finally:
        await database.dispose()


def submission() -> dict:
    return {
        "target": dict(LEAKY_MOCK_TARGET),
        "authorization": dict(VALID_AUTHORIZATION),
        "probes": ["diagnostic.canary_echo"],
    }


class TestFailClosedAtStartup:
    async def test_no_keys_and_no_opt_out_refuses_to_start(self, tmp_path):
        """A warning would be ignored for months. Refusing to boot will not be."""
        settings = Settings(
            database_url=f"sqlite+aiosqlite:///{tmp_path}/x.db",
            api_key_hashes=[],
            allow_unauthenticated=False,
        )
        database = Database(settings.database_url)
        app = create_app(settings=settings, database=database)
        try:
            with pytest.raises(ConfigurationError, match="no API keys configured"):
                async with app.router.lifespan_context(app):
                    pass
        finally:
            await database.dispose()

    async def test_the_error_says_how_to_fix_it(self, tmp_path):
        settings = Settings(database_url=f"sqlite+aiosqlite:///{tmp_path}/x.db")
        database = Database(settings.database_url)
        app = create_app(settings=settings, database=database)
        try:
            with pytest.raises(ConfigurationError) as caught:
                async with app.router.lifespan_context(app):
                    pass
        finally:
            await database.dispose()
        assert "promptsentinel keygen" in str(caught.value)
        assert "PROMPTSENTINEL_ALLOW_UNAUTHENTICATED" in str(caught.value)

    async def test_explicit_opt_out_is_honoured(self, client):
        """The `client` fixture sets allow_unauthenticated; it must actually work."""
        assert (await client.get("/v1/probes")).status_code == 200


class TestGuardedEndpoints:
    @pytest.mark.parametrize("path", GUARDED)
    async def test_no_key_is_rejected(self, auth_client, path):
        response = await auth_client.get(path)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    @pytest.mark.parametrize("path", GUARDED)
    async def test_a_valid_bearer_token_is_accepted(self, auth_client, path):
        response = await auth_client.get(path, headers={"Authorization": f"Bearer {KEY}"})
        assert response.status_code == 200

    @pytest.mark.parametrize("path", GUARDED)
    async def test_the_x_api_key_header_also_works(self, auth_client, path):
        response = await auth_client.get(path, headers={"X-API-Key": KEY})
        assert response.status_code == 200

    async def test_any_configured_key_is_accepted(self, auth_client):
        for key in (KEY, OTHER_KEY):
            response = await auth_client.get("/v1/probes", headers={"X-API-Key": key})
            assert response.status_code == 200

    async def test_scan_submission_is_guarded(self, auth_client):
        """The endpoint that makes this instance attack things."""
        response = await auth_client.post("/v1/scans", json=submission())
        assert response.status_code == 401

    async def test_scan_submission_works_with_a_key(self, auth_client):
        response = await auth_client.post(
            "/v1/scans", json=submission(), headers={"X-API-Key": KEY}
        )
        assert response.status_code == 202

    async def test_reports_are_guarded(self, auth_client):
        """Reports contain your real system prompt and transcripts."""
        response = await auth_client.get("/v1/scans/anything/report")
        assert response.status_code == 401


class TestUnguardedEndpoints:
    @pytest.mark.parametrize("path", ["/healthz", "/readyz"])
    async def test_health_needs_no_key(self, auth_client, path):
        """A liveness probe needing a credential reports an outage when it rotates."""
        assert (await auth_client.get(path)).status_code == 200

    async def test_openapi_is_reachable(self, auth_client):
        assert (await auth_client.get("/openapi.json")).status_code == 200


class TestRejectionLeaksNothing:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer wrong-key"},
            {"Authorization": KEY},
            {"Authorization": "Basic abc"},
            {"X-API-Key": ""},
            {"X-API-Key": "wrong-key"},
        ],
        ids=["absent", "wrong_bearer", "no_scheme", "wrong_scheme", "empty", "wrong_header"],
    )
    async def test_every_failure_looks_identical(self, auth_client, headers):
        """Missing and wrong must be indistinguishable, or probing reveals key shape."""
        response = await auth_client.get("/v1/probes", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "a valid API key is required"

    async def test_a_valid_key_is_never_echoed(self, auth_client):
        response = await auth_client.get("/v1/probes", headers={"X-API-Key": "wrong-key"})
        assert "wrong-key" not in response.text


class TestKeyHandling:
    def test_generated_keys_are_unique_and_prefixed(self):
        keys = {generate_key()[0] for _ in range(100)}
        assert len(keys) == 100
        assert all(k.startswith("ps_") for k in keys)

    def test_generate_returns_a_matching_hash(self):
        key, digest = generate_key()
        assert digest == hash_key(key)
        assert verify(key, [digest])

    def test_the_key_is_not_recoverable_from_the_hash(self):
        key, digest = generate_key()
        assert key not in digest
        assert len(digest) == 64

    def test_verify_rejects_a_non_matching_key(self):
        _, digest = generate_key()
        assert not verify("ps_not_the_key", [digest])

    def test_verify_against_no_configured_hashes_is_false(self):
        """Fail closed: an empty allowlist admits nobody."""
        assert not verify("anything", [])

    def test_verify_checks_all_hashes(self):
        key, digest = generate_key()
        assert verify(key, [hash_key("other"), digest, hash_key("another")])
