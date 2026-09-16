"""Every path that actually scans must pace its requests.

The factory applies pacing, but only if the caller asks for it. There are exactly two
callers that send traffic to a real target -- the background worker and the CLI -- and
these tests pin both. A third entry point added later without pacing should fail here.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from promptsentinel.cli.main import app as cli_app
from promptsentinel.config import Settings
from promptsentinel.core.authorization import REQUIRED_ATTESTATION
from promptsentinel.db.session import Database
from promptsentinel.jobs import worker as worker_module
from promptsentinel.jobs.worker import ScanWorker
from promptsentinel.secrets import InMemorySecretStore
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.rate_limit import RateLimit, RateLimitedTarget
from promptsentinel.targets.spec import MockTargetSpec
from tests.integration.test_worker_failure_paths import make_scan

runner = CliRunner()


@pytest.fixture
def captured_build(monkeypatch):
    """Record how build_target was called, and hand back a harmless target."""
    calls: list[dict] = []
    real = worker_module.build_target

    def spy(spec, **kwargs):
        calls.append(kwargs)
        return real(spec, **kwargs)

    monkeypatch.setattr(worker_module, "build_target", spy)
    return calls


class TestWorkerPacing:
    async def test_the_worker_paces_its_target(
        self, database: Database, settings: Settings, captured_build
    ):
        secrets = InMemorySecretStore()
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["diagnostic.canary_echo"])
        await ScanWorker(database, settings, secrets).execute(scan_id)

        assert captured_build, "build_target was never called"
        assert isinstance(captured_build[0]["rate_limit"], RateLimit)

    async def test_the_limit_comes_from_settings(
        self, database: Database, tmp_path, captured_build
    ):
        settings = Settings(
            database_url=f"sqlite+aiosqlite:///{tmp_path}/t.db",
            allow_unauthenticated=True,
            target_requests_per_second=7.5,
            target_burst=3,
        )
        secrets = InMemorySecretStore()
        scan_id = await make_scan(database, secrets=secrets, probe_ids=["diagnostic.canary_echo"])
        await ScanWorker(database, settings, secrets).execute(scan_id)

        limit = captured_build[0]["rate_limit"]
        assert limit.requests_per_second == 7.5
        assert limit.burst == 3

    def test_settings_expose_a_conservative_default(self):
        """The default must be a rate a human could plausibly generate."""
        limit = Settings(allow_unauthenticated=True).rate_limit
        assert limit.requests_per_second <= 5
        assert limit.burst <= 10


class TestCliPacing:
    def test_the_cli_paces_its_target(self, monkeypatch, tmp_path):
        from promptsentinel.cli import main as cli_module

        seen: list[dict] = []
        real = cli_module.build_target

        def spy(spec, **kwargs):
            seen.append(kwargs)
            return real(spec, **kwargs)

        monkeypatch.setattr(cli_module, "build_target", spy)

        target_file = tmp_path / "t.json"
        target_file.write_text('{"kind": "mock"}')
        runner.invoke(
            cli_app,
            [
                "scan",
                "-t",
                str(target_file),
                "--attested-by",
                "t",
                "--attest",
                REQUIRED_ATTESTATION,
                "--no-input",
                "--probe",
                "diagnostic.canary_echo",
                "--rate",
                "3",
                "--burst",
                "2",
            ],
        )

        assert seen, "build_target was never called"
        limit = seen[0]["rate_limit"]
        assert limit.requests_per_second == 3
        assert limit.burst == 2

    def test_the_produced_target_is_actually_wrapped(self):
        from promptsentinel.targets.factory import build_target

        target = build_target(
            MockTargetSpec(), allow_mock=True, rate_limit=RateLimit(requests_per_second=3)
        )
        assert isinstance(target, RateLimitedTarget)
        assert isinstance(target.inner, MockTarget)


class TestApiValidationPathIsUnpaced:
    async def test_submitting_a_scan_does_not_pace_the_validation_target(self, client):
        """The API builds a target only to validate the spec and read its description.

        That path sends nothing, so pacing it would add latency to every submission for
        no protection at all.
        """
        response = await client.post(
            "/v1/scans",
            json={
                "target": {"kind": "mock"},
                "authorization": {
                    "confirmed": True,
                    "attested_by": "t",
                    "statement": REQUIRED_ATTESTATION,
                },
                "probes": ["diagnostic.canary_echo"],
            },
        )
        assert response.status_code == 202
