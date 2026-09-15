"""Health and discovery endpoints."""

from __future__ import annotations


class TestHealth:
    async def test_healthz_does_not_touch_the_database(self, client):
        """Liveness must not fail because a dependency is slow, or pods get restarted."""
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_readyz_checks_the_database(self, client):
        assert (await client.get("/readyz")).json()["status"] == "ready"


class TestProbeCatalogue:
    async def test_probes_are_discoverable_at_runtime(self, client):
        """Clients should not have to hardcode probe IDs from documentation."""
        probes = (await client.get("/v1/probes")).json()
        by_id = {p["id"]: p for p in probes}
        assert "diagnostic.canary_echo" in by_id
        assert by_id["diagnostic.canary_echo"]["required_capabilities"]


class TestOpenAPI:
    async def test_schema_documents_the_authorization_requirement(self, client):
        schema = (await client.get("/openapi.json")).json()
        submit = schema["paths"]["/v1/scans"]["post"]
        assert "403" in submit["responses"]
