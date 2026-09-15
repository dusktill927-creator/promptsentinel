"""End-to-end: HTTP submit -> background execution -> persisted report."""

from __future__ import annotations

import pytest

from tests.conftest import LEAKY_MOCK_TARGET, VALID_AUTHORIZATION


def body(**overrides):
    payload = {"target": dict(LEAKY_MOCK_TARGET), "authorization": dict(VALID_AUTHORIZATION)}
    payload.update(overrides)
    return payload


class TestAuthorizationGate:
    """No attestation, no scan. Checked before anything is persisted."""

    async def test_missing_authorization_block_is_422(self, client):
        response = await client.post("/v1/scans", json={"target": LEAKY_MOCK_TARGET})
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "authorization",
        [
            {
                "confirmed": False,
                "attested_by": "t",
                "statement": "I own or am authorized to security test this target.",
            },
            {"confirmed": True, "attested_by": "t", "statement": "sure whatever"},
            {
                "confirmed": True,
                "attested_by": "",
                "statement": "I own or am authorized to security test this target.",
            },
            {},
        ],
        ids=["not_confirmed", "wrong_statement", "anonymous", "empty"],
    )
    async def test_invalid_attestation_is_refused_with_403(self, client, authorization):
        response = await client.post("/v1/scans", json=body(authorization=authorization))
        assert response.status_code == 403
        assert response.json()["error"] == "authorization_required"

    async def test_a_refused_scan_is_not_persisted(self, client):
        """An unauthorized request must leave no trace."""
        await client.post("/v1/scans", json=body(authorization={"confirmed": False}))
        listing = await client.get("/v1/scans")
        assert listing.json() == []

    async def test_the_error_tells_the_caller_what_to_send(self, client):
        response = await client.post("/v1/scans", json=body(authorization={}))
        assert "I own or am authorized to security test this target." in response.json()["detail"]


class TestSubmission:
    async def test_submit_returns_202_with_a_job_id(self, client):
        response = await client.post("/v1/scans", json=body())
        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "pending"
        assert payload["probes_selected"] == ["diagnostic.canary_echo"]
        assert payload["report_url"].endswith("/report")

    async def test_unknown_probe_is_rejected_at_submit_time(self, client):
        """Fail loudly now, rather than handing back an empty report later."""
        response = await client.post("/v1/scans", json=body(probes=["nope.nope"]))
        assert response.status_code == 400
        assert "unknown probe" in response.json()["detail"]

    async def test_unknown_target_kind_is_rejected(self, client):
        response = await client.post("/v1/scans", json=body(target={"kind": "telepathy"}))
        assert response.status_code == 422

    async def test_extra_fields_are_rejected(self, client):
        """A typo'd field name must not be silently ignored by a security tool."""
        response = await client.post("/v1/scans", json=body(probez=["x"]))
        assert response.status_code == 422


class TestLifecycle:
    async def test_report_is_409_until_the_scan_finishes(self, client, app):
        """A partial report reads as a pass. Better to make the client wait."""

        class StalledQueue:
            async def enqueue(self, scan_id, target_spec): ...
            async def aclose(self): ...

        app.state.queue = StalledQueue()
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]

        report = await client.get(f"/v1/scans/{scan_id}/report")
        assert report.status_code == 409
        assert report.headers["retry-after"] == "5"

    async def test_unknown_scan_is_404(self, client):
        assert (await client.get("/v1/scans/deadbeef")).status_code == 404
        assert (await client.get("/v1/scans/deadbeef/report")).status_code == 404

    async def test_status_endpoint_reports_completion(self, client, drain):
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]
        await drain()
        status = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert status["status"] == "completed"
        assert status["finished_at"] is not None


class TestReport:
    @pytest.fixture
    async def report(self, client, drain):
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]
        await drain()
        response = await client.get(f"/v1/scans/{scan_id}/report")
        assert response.status_code == 200
        return response.json()

    async def test_the_vulnerable_mock_yields_a_confirmed_finding(self, report):
        assert report["summary"]["confirmed"] == 1
        finding = report["findings"][0]
        assert finding["confidence"] == "confirmed"
        assert finding["proof"]["kind"] == "canary_disclosure"

    async def test_probe_runs_are_reported_even_when_they_find_nothing(self, report):
        assert report["summary"]["probes_run"] == 1
        assert report["summary"]["probes_errored"] == 0
        assert report["summary"]["probes_skipped"] == 0

    async def test_the_attestation_is_part_of_the_audit_trail(self, report):
        assert report["authorization"]["attested_by"] == "tester@example.com"
        assert report["authorization"]["confirmed"] is True

    async def test_seeded_canaries_are_listed_and_redacted(self, report):
        canaries = report["canaries_seeded"]
        assert len(canaries) == 1
        assert canaries[0]["value"].endswith("[redacted]")

    async def test_evidence_is_included_for_triage(self, report):
        evidence = report["findings"][0]["evidence"]
        assert evidence["prompt"]
        assert evidence["response"]


class TestCleanTarget:
    async def test_a_refusing_target_produces_a_clean_report(self, client, drain):
        target = {
            "kind": "mock",
            "system_prompt": "You are a support bot.",
            "rules": [
                {"pattern": "repeat|configuration", "response": "I'm sorry, I can't do that."}
            ],
        }
        scan_id = (await client.post("/v1/scans", json=body(target=target))).json()["id"]
        await drain()
        report = (await client.get(f"/v1/scans/{scan_id}/report")).json()

        assert report["summary"]["total_findings"] == 0
        assert report["summary"]["probes_completed"] == 1


class TestSecretHandling:
    async def test_api_keys_are_never_persisted(self, client, drain):
        """The stored spec is what a future report, backup or dump would expose."""
        target = {
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1:9/v1",
            "model": "test-model",
            "api_key": "sk-super-secret-value",
        }
        scan_id = (await client.post("/v1/scans", json=body(target=target))).json()["id"]
        await drain()
        report = (await client.get(f"/v1/scans/{scan_id}/report")).json()

        assert "sk-super-secret-value" not in str(report)
        assert report["target_spec"]["api_key"] == "**********"

    async def test_an_unreachable_target_fails_the_scan_loudly(self, client, drain):
        """A connection error must never be rendered as a clean bill of health."""
        target = {
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1:9/v1",
            "model": "test-model",
        }
        scan_id = (await client.post("/v1/scans", json=body(target=target))).json()["id"]
        await drain()
        report = (await client.get(f"/v1/scans/{scan_id}/report")).json()

        assert report["summary"]["probes_errored"] == 1
        assert report["summary"]["total_findings"] == 0
