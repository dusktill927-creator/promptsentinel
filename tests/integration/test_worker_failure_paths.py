"""Worker behaviour when a scan cannot run.

A scan that fails must fail *visibly*. The dangerous outcome is a scan that quietly
records no findings and is read as a clean bill of health.
"""

from __future__ import annotations

import pytest
from sqlalchemy import update

from promptsentinel.config import Settings
from promptsentinel.core.authorization import REQUIRED_ATTESTATION, Authorization
from promptsentinel.db.models import ScanRow
from promptsentinel.db.repository import ScanRepository
from promptsentinel.db.session import Database
from promptsentinel.jobs import webhooks
from promptsentinel.jobs.worker import ScanWorker
from promptsentinel.secrets import InMemorySecretStore, scan_secret_key
from promptsentinel.targets.spec import MockTargetSpec, serialize_with_secrets

SPEC = MockTargetSpec(system_prompt="Bot.", leak_system_prompt_on="repeat")
AUTHORIZATION = Authorization(
    confirmed=True, attested_by="tester@example.com", statement=REQUIRED_ATTESTATION
)


async def make_scan(database: Database, *, probe_ids, webhook_url=None, secrets=None) -> str:
    async with database.session() as session:
        scan = await ScanRepository(session).create_scan(
            target_spec=SPEC,
            target_description="mock:in-process",
            authorization=AUTHORIZATION,
            requested_probe_ids=probe_ids,
            options={},
            webhook_url=webhook_url,
        )
        if secrets is not None:
            # In production the API stages credentials before enqueuing; these tests
            # call the worker directly, so they stand in for that step.
            await secrets.put(scan_secret_key(scan.id), serialize_with_secrets(SPEC), ttl_s=300.0)
        return scan.id


async def load(database: Database, scan_id: str) -> ScanRow:
    async with database.session() as session:
        scan = await ScanRepository(session).get(scan_id)
        assert scan is not None
        return scan


@pytest.fixture
def secrets() -> InMemorySecretStore:
    return InMemorySecretStore()


@pytest.fixture
def worker(database: Database, settings: Settings, secrets: InMemorySecretStore) -> ScanWorker:
    return ScanWorker(database, settings, secrets)


class TestUnrunnableScan:
    async def test_unknown_probe_marks_the_scan_failed(self, worker, database, secrets):
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["ghost.probe"])
        await worker.execute(scan_id)

        scan = await load(database, scan_id)
        assert scan.status == "failed"
        assert "unknown probe" in (scan.error or "")

    async def test_a_failed_scan_records_no_findings(self, worker, database, secrets):
        """FAILED with zero findings means 'we do not know', never 'you are clean'."""
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["ghost.probe"])
        await worker.execute(scan_id)

        scan = await load(database, scan_id)
        assert scan.findings == []
        assert scan.probe_runs == []

    async def test_a_vanished_scan_is_not_an_unhandled_crash(self, worker):
        await worker.execute("does-not-exist")


class TestAuthorizationAtTheStorageBoundary:
    async def test_a_tampered_authorization_row_refuses_to_run(self, worker, database, secrets):
        """Defense in depth against someone editing the database directly.

        The worker rebuilds the attestation through ``Authorization``, so a row whose
        confirmation was flipped off fails validation instead of scanning.
        """
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["diagnostic.canary_echo"])
        async with database.session() as session:
            await session.execute(
                update(ScanRow).where(ScanRow.id == scan_id).values(authorization_confirmed=False)
            )

        await worker.execute(scan_id)

        scan = await load(database, scan_id)
        assert scan.status == "failed"
        assert scan.findings == []

    async def test_a_tampered_statement_refuses_to_run(self, worker, database, secrets):
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["diagnostic.canary_echo"])
        async with database.session() as session:
            await session.execute(
                update(ScanRow)
                .where(ScanRow.id == scan_id)
                .values(authorization_statement="sure go ahead")
            )

        await worker.execute(scan_id)
        assert (await load(database, scan_id)).status == "failed"


class TestWebhookNotification:
    @pytest.fixture
    def captured(self, monkeypatch):
        calls: list[tuple[str, dict]] = []

        async def fake_deliver(url, payload, **kwargs):
            calls.append((url, payload))
            return "delivered_200"

        monkeypatch.setattr(webhooks, "deliver", fake_deliver)
        return calls

    async def test_completion_fires_the_webhook(self, worker, database, captured, secrets):
        scan_id = await make_scan(
            database,
            secrets=secrets,
            probe_ids=["diagnostic.canary_echo"],
            webhook_url="https://hooks.example.com/x",
        )
        await worker.execute(scan_id)

        assert len(captured) == 1
        url, payload = captured[0]
        assert url == "https://hooks.example.com/x"
        assert payload["status"] == "completed"
        assert payload["findings"]["confirmed"] == 1

    async def test_the_payload_carries_no_evidence(self, worker, database, captured, secrets):
        """A webhook URL is an endpoint we do not control. Counts only, never transcripts."""
        scan_id = await make_scan(
            database,
            secrets=secrets,
            probe_ids=["diagnostic.canary_echo"],
            webhook_url="https://hooks.example.com/x",
        )
        await worker.execute(scan_id)

        _, payload = captured[0]
        assert set(payload) == {"event", "scan_id", "status", "findings", "report_url"}
        assert "PSCANARY" not in str(payload)

    async def test_delivery_outcome_is_recorded(self, worker, database, captured, secrets):
        scan_id = await make_scan(
            database,
            secrets=secrets,
            probe_ids=["diagnostic.canary_echo"],
            webhook_url="https://hooks.example.com/x",
        )
        await worker.execute(scan_id)
        assert (await load(database, scan_id)).webhook_status == "delivered_200"

    async def test_no_webhook_means_no_call(self, worker, database, captured, secrets):
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["diagnostic.canary_echo"])
        await worker.execute(scan_id)
        assert captured == []

    async def test_a_failed_scan_still_notifies(self, worker, database, captured, secrets):
        """Silence on failure is the worst outcome for a CI pipeline that is waiting."""
        scan_id = await make_scan(
            database,
            secrets=secrets,
            probe_ids=["ghost.probe"],
            webhook_url="https://hooks.example.com/x",
        )
        await worker.execute(scan_id)

        assert captured[0][1]["status"] == "failed"
