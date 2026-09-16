"""The read-only dashboard.

Three properties matter: it is off unless asked for, it cannot be read without a key,
and it cannot change anything. The third is the one that keeps it cheap to reason about
-- there are no state-changing endpoints, so there is no CSRF surface worth the name,
and nothing here can start a scan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from promptsentinel.api.app import create_app
from promptsentinel.api.routes.dashboard import COOKIE_NAME
from promptsentinel.api.security import hash_key
from promptsentinel.config import Settings
from promptsentinel.db.session import Database
from tests.conftest import LEAKY_MOCK_TARGET, VALID_AUTHORIZATION

KEY = "ps_dashboard_key"


def submission() -> dict:
    return {
        "target": dict(LEAKY_MOCK_TARGET),
        "authorization": dict(VALID_AUTHORIZATION),
        "probes": ["diagnostic.canary_echo"],
    }


@pytest.fixture
async def dash(tmp_path) -> AsyncIterator[tuple[AsyncClient, FastAPI]]:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/dash.db",
        api_key_hashes=[hash_key(KEY)],
        allow_unauthenticated=False,
        enable_dashboard=True,
        allow_mock_targets=True,
        target_requests_per_second=1000.0,
        target_burst=1000,
    )
    database = Database(settings.database_url)
    await database.create_all()
    app = create_app(settings=settings, database=database)
    try:
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                yield client, app
    finally:
        await database.dispose()


class TestDisabledByDefault:
    async def test_no_dashboard_routes_without_the_setting(self, client):
        """The default app should not grow HTTP endpoints nobody asked for."""
        for path in ("/dashboard", "/dashboard/login"):
            assert (await client.get(path)).status_code == 404

    async def test_enabled_when_asked(self, dash):
        dashboard, _ = dash
        assert (await dashboard.get("/dashboard/login")).status_code == 200


class TestAuthentication:
    async def test_anonymous_access_redirects_to_login(self, dash):
        dashboard, _ = dash
        response = await dashboard.get("/dashboard", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard/login"

    async def test_a_wrong_key_is_rejected(self, dash):
        dashboard, _ = dash
        response = await dashboard.post("/dashboard/login", data={"key": "wrong"})
        assert response.status_code == 401
        assert "not accepted" in response.text
        assert COOKIE_NAME not in response.cookies

    async def test_an_empty_key_is_rejected(self, dash):
        dashboard, _ = dash
        assert (await dashboard.post("/dashboard/login", data={"key": ""})).status_code == 401

    async def test_a_valid_key_sets_a_session_and_redirects(self, dash):
        dashboard, _ = dash
        response = await dashboard.post(
            "/dashboard/login", data={"key": KEY}, follow_redirects=False
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"

        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie.replace("samesite", "SameSite")
        assert "Path=/dashboard" in cookie

    async def test_the_session_grants_access(self, dash):
        dashboard, _ = dash
        await dashboard.post("/dashboard/login", data={"key": KEY})
        assert (await dashboard.get("/dashboard")).status_code == 200

    async def test_the_header_also_works(self, dash):
        """So the dashboard can sit behind a proxy that injects the key."""
        dashboard, _ = dash
        response = await dashboard.get("/dashboard", headers={"X-API-Key": KEY})
        assert response.status_code == 200

    async def test_an_oversized_login_body_is_refused(self, dash):
        """An unauthenticated caller must not be able to make us read arbitrary memory."""
        dashboard, _ = dash
        response = await dashboard.post("/dashboard/login", content=b"key=" + b"x" * 9000)
        assert response.status_code == 413

    async def test_a_report_page_needs_a_session_too(self, dash):
        dashboard, _ = dash
        response = await dashboard.get("/dashboard/scans/anything", follow_redirects=False)
        assert response.status_code == 303


class TestReadOnly:
    def test_the_only_non_get_route_is_login(self):
        """No state-changing endpoints means no CSRF surface worth the name.

        Asserted against the router itself: this FastAPI version wraps included routers,
        so app.routes does not expose them individually.
        """
        from promptsentinel.api.routes.dashboard import router

        mutating = sorted(
            (r.path, method)
            for r in router.routes
            for method in (getattr(r, "methods", None) or set())
            if method not in {"GET", "HEAD", "OPTIONS"}
        )
        assert mutating == [("/dashboard/login", "POST")]

    async def test_scans_cannot_be_started_from_the_dashboard(self, dash):
        dashboard, _ = dash
        await dashboard.post("/dashboard/login", data={"key": KEY})
        assert (await dashboard.post("/dashboard/scans")).status_code in (404, 405)


class TestContent:
    @pytest.fixture
    async def with_scan(self, dash):
        dashboard, app = dash
        await dashboard.post("/dashboard/login", data={"key": KEY})
        response = await dashboard.post("/v1/scans", json=submission(), headers={"X-API-Key": KEY})
        await app.state.queue.wait_idle()
        return dashboard, response.json()["id"]

    async def test_the_index_lists_scans(self, with_scan):
        dashboard, scan_id = with_scan
        response = await dashboard.get("/dashboard")
        assert scan_id[:12] in response.text
        assert "mock:in-process" in response.text

    async def test_a_completed_scan_links_to_its_report(self, with_scan):
        dashboard, scan_id = with_scan
        assert f'href="/dashboard/scans/{scan_id}"' in (await dashboard.get("/dashboard")).text

    async def test_the_report_page_renders(self, with_scan):
        dashboard, scan_id = with_scan
        response = await dashboard.get(f"/dashboard/scans/{scan_id}")
        assert response.status_code == 200
        assert "PromptSentinel report" in response.text
        assert "CONFIRMED" in response.text.upper()

    async def test_pages_carry_the_security_headers(self, with_scan):
        dashboard, scan_id = with_scan
        for path in ("/dashboard", f"/dashboard/scans/{scan_id}"):
            headers = (await dashboard.get(path)).headers
            assert "default-src 'none'" in headers["content-security-policy"]
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["referrer-policy"] == "no-referrer"

    async def test_an_empty_dashboard_says_so(self, dash):
        dashboard, _ = dash
        await dashboard.post("/dashboard/login", data={"key": KEY})
        assert "No scans yet." in (await dashboard.get("/dashboard")).text

    async def test_an_unknown_scan_is_404(self, dash):
        dashboard, _ = dash
        await dashboard.post("/dashboard/login", data={"key": KEY})
        assert (await dashboard.get("/dashboard/scans/nope")).status_code == 404


class TestEscaping:
    async def test_a_hostile_target_description_is_escaped(self, dash):
        """The target description comes from user-supplied configuration."""
        dashboard, app = dash
        await dashboard.post("/dashboard/login", data={"key": KEY})
        payload = submission()
        payload["target"] = {
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1:9/v1",
            "model": "<script>alert(1)</script>",
        }
        await dashboard.post("/v1/scans", json=payload, headers={"X-API-Key": KEY})
        await app.state.queue.wait_idle()

        response = await dashboard.get("/dashboard")
        assert "<script>alert(1)</script>" not in response.text
        assert "&lt;script&gt;" in response.text
