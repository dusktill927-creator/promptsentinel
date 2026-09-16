"""End-to-end: HTTP submit -> background execution -> persisted report."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.conftest import LEAKY_MOCK_TARGET, VALID_AUTHORIZATION


def body(**overrides):
    """A submission pinned to one probe.

    The API tests are about the pipeline, not about probe coverage. Pinning the probe
    list means adding a probe never breaks them -- and leaves the default-selection
    behaviour to its own explicit test below.
    """
    payload = {
        "target": dict(LEAKY_MOCK_TARGET),
        "authorization": dict(VALID_AUTHORIZATION),
        "probes": ["diagnostic.canary_echo"],
    }
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


class TestProbeSelection:
    async def test_default_selection_runs_the_real_probes(self, client):
        """A scan with no probe list runs the enabled catalogue, not the diagnostic.

        Asserted as properties rather than a fixed list, so shipping a new probe
        category does not break a test that is about selection behaviour.
        """
        payload = {
            "target": dict(LEAKY_MOCK_TARGET),
            "authorization": dict(VALID_AUTHORIZATION),
        }
        selected = (await client.post("/v1/scans", json=payload)).json()["probes_selected"]

        assert "diagnostic.canary_echo" not in selected
        assert len(selected) > 1
        assert len({p.split(".")[0] for p in selected}) > 1, "should span >1 family"

    async def test_a_disabled_probe_can_still_be_named_explicitly(self, client):
        response = await client.post("/v1/scans", json=body())
        assert response.json()["probes_selected"] == ["diagnostic.canary_echo"]

    async def test_category_selection(self, client):
        payload = {
            "target": dict(LEAKY_MOCK_TARGET),
            "authorization": dict(VALID_AUTHORIZATION),
            "categories": ["system_prompt_extraction"],
        }
        selected = (await client.post("/v1/scans", json=payload)).json()["probes_selected"]
        assert selected and all(p.startswith("system_prompt.") for p in selected)


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
            async def enqueue(self, scan_id): ...
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


class TestSarifReport:
    """The SARIF endpoint, including the integrity re-check on the way out."""

    @pytest.fixture
    async def scan_id(self, client, drain):
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]
        await drain()
        return scan_id

    async def test_sarif_is_served_for_a_completed_scan(self, client, scan_id):
        response = await client.get(f"/v1/scans/{scan_id}/report/sarif")
        assert response.status_code == 200
        doc = response.json()
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"][0]["level"] == "error"

    async def test_confidence_is_preserved_through_the_database(self, client, scan_id):
        doc = (await client.get(f"/v1/scans/{scan_id}/report/sarif")).json()
        result = doc["runs"][0]["results"][0]
        assert result["properties"]["confidence"] == "confirmed"
        assert result["properties"]["proven"] is True

    async def test_evidence_is_excluded_by_default(self, client, scan_id):
        doc = (await client.get(f"/v1/scans/{scan_id}/report/sarif")).json()
        assert "evidence" not in doc["runs"][0]["results"][0]["properties"]

    async def test_evidence_can_be_requested(self, client, scan_id):
        doc = (await client.get(f"/v1/scans/{scan_id}/report/sarif?include_evidence=true")).json()
        assert doc["runs"][0]["results"][0]["properties"]["evidence"]["prompt"]

    async def test_sarif_is_409_before_the_scan_finishes(self, client, app):
        class StalledQueue:
            async def enqueue(self, scan_id): ...
            async def aclose(self): ...

        app.state.queue = StalledQueue()
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]
        assert (await client.get(f"/v1/scans/{scan_id}/report/sarif")).status_code == 409

    async def test_sarif_is_404_for_an_unknown_scan(self, client):
        assert (await client.get("/v1/scans/nope/report/sarif")).status_code == 404

    async def test_a_tampered_finding_row_is_not_exported_as_proven(
        self, client, database, scan_id
    ):
        """Rebuilding domain objects re-runs the confidence invariant.

        A row edited directly in the database to claim `confirmed` without proof must
        fail loudly rather than export as a proven finding.
        """
        from sqlalchemy import update

        from promptsentinel.db.models import FindingRow

        async with database.session() as session:
            await session.execute(
                update(FindingRow).where(FindingRow.scan_id == scan_id).values(proof=None)
            )

        with pytest.raises(ValidationError):
            await client.get(f"/v1/scans/{scan_id}/report/sarif")


CREDENTIALED_TARGET = {
    "kind": "openai_compatible",
    "base_url": "http://127.0.0.1:9/v1",
    "model": "m",
    "api_key": "sk-live-credential",
}


class TestCredentialHandling:
    """A target's API key must reach the worker and nowhere else."""

    async def test_the_credential_never_enters_the_queue(self, client, app):
        """The queue message is a scan ID. That is what makes it distributable."""
        enqueued: list = []

        class RecordingQueue:
            async def enqueue(self, scan_id):
                enqueued.append(scan_id)

            async def aclose(self): ...

        app.state.queue = RecordingQueue()
        response = await client.post("/v1/scans", json=body(target=CREDENTIALED_TARGET))
        assert response.status_code == 202

        assert enqueued == [response.json()["id"]]
        assert "sk-live-credential" not in str(enqueued)

    async def test_the_credential_is_staged_for_the_worker(self, client, app):
        from promptsentinel.secrets import scan_secret_key

        class StalledQueue:
            async def enqueue(self, scan_id): ...
            async def aclose(self): ...

        app.state.queue = StalledQueue()
        scan_id = (await client.post("/v1/scans", json=body(target=CREDENTIALED_TARGET))).json()[
            "id"
        ]

        stored = await app.state.secrets.get(scan_secret_key(scan_id))
        assert "sk-live-credential" in stored

    async def test_the_credential_is_deleted_once_the_scan_ends(self, client, drain, app):
        """Deleted on completion, not left to wait out its TTL."""
        from promptsentinel.secrets import SecretNotFoundError, scan_secret_key

        scan_id = (await client.post("/v1/scans", json=body(target=CREDENTIALED_TARGET))).json()[
            "id"
        ]
        await drain()

        with pytest.raises(SecretNotFoundError):
            await app.state.secrets.get(scan_secret_key(scan_id))

    async def test_an_expired_credential_fails_the_scan_clearly(self, client, drain, app):
        """A scan that outlived its credential must say so, not report a clean run."""
        from promptsentinel.secrets import scan_secret_key

        class StalledQueue:
            async def enqueue(self, scan_id): ...
            async def aclose(self): ...

        app.state.queue = StalledQueue()
        scan_id = (await client.post("/v1/scans", json=body(target=CREDENTIALED_TARGET))).json()[
            "id"
        ]
        await app.state.secrets.delete(scan_secret_key(scan_id))

        from promptsentinel.jobs.worker import ScanWorker

        await ScanWorker(app.state.database, app.state.settings, app.state.secrets).execute(scan_id)

        status = (await client.get(f"/v1/scans/{scan_id}")).json()
        assert status["status"] == "failed"
        assert "credentials" in (status["error"] or "")

    async def test_a_failed_enqueue_does_not_strand_the_credential(self, client, app):
        from promptsentinel.secrets import SecretNotFoundError, scan_secret_key

        class BrokenQueue:
            async def enqueue(self, scan_id):
                raise RuntimeError("broker unreachable")

            async def aclose(self): ...

        app.state.queue = BrokenQueue()
        with pytest.raises(RuntimeError):
            await client.post("/v1/scans", json=body(target=CREDENTIALED_TARGET))

        listing = await client.get("/v1/scans")
        scan_id = listing.json()[0]["id"]
        with pytest.raises(SecretNotFoundError):
            await app.state.secrets.get(scan_secret_key(scan_id))


class TestHtmlReport:
    @pytest.fixture
    async def scan_id(self, client, drain):
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]
        await drain()
        return scan_id

    async def test_html_is_served_for_a_completed_scan(self, client, scan_id):
        response = await client.get(f"/v1/scans/{scan_id}/report/html")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert response.text.startswith("<!doctype html>")

    async def test_the_page_declares_a_restrictive_policy(self, client, scan_id):
        """Built from escaped text with no scripts; the header makes a browser enforce it."""
        response = await client.get(f"/v1/scans/{scan_id}/report/html")
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert response.headers["x-content-type-options"] == "nosniff"

    async def test_the_seeded_values_table_is_redacted(self, client, scan_id):
        """The audit table shows a truncated prefix, never a replayable value."""
        response = await client.get(f"/v1/scans/{scan_id}/report/html")
        assert "Seeded values" in response.text
        assert "[redacted]" in response.text

    async def test_transcripts_do_contain_the_leaked_value(self, client, scan_id):
        """Deliberate. The transcript is the evidence -- a redacted one proves nothing.

        It is also exactly why the report warns that it contains transcripts and why
        --exclude-evidence exists for sharing.
        """
        import re

        response = await client.get(f"/v1/scans/{scan_id}/report/html")
        assert re.search(r"PSCANARY-[0-9a-f]{32}", response.text)
        assert "Contains transcripts" in response.text

    async def test_excluding_transcripts_removes_every_leaked_value(self, client, scan_id):
        import re

        response = await client.get(f"/v1/scans/{scan_id}/report/html?include_evidence=false")
        assert not re.search(r"PSCANARY-[0-9a-f]{32}", response.text)
        assert "Seeded values" in response.text

    async def test_transcripts_can_be_omitted(self, client, scan_id):
        with_evidence = await client.get(f"/v1/scans/{scan_id}/report/html")
        without = await client.get(f"/v1/scans/{scan_id}/report/html?include_evidence=false")
        assert "Transcript" in with_evidence.text
        assert "Transcript" not in without.text

    async def test_html_is_409_before_the_scan_finishes(self, client, app):
        class StalledQueue:
            async def enqueue(self, scan_id): ...
            async def aclose(self): ...

        app.state.queue = StalledQueue()
        scan_id = (await client.post("/v1/scans", json=body())).json()["id"]
        assert (await client.get(f"/v1/scans/{scan_id}/report/html")).status_code == 409

    async def test_html_is_404_for_an_unknown_scan(self, client):
        assert (await client.get("/v1/scans/nope/report/html")).status_code == 404
