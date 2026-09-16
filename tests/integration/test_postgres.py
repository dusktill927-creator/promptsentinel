"""Postgres compatibility.

SQLite is the development default and Postgres is the production target, and the code
is written for both. "Written for both" is a claim, and an unverified claim about a
database is the kind that holds right up until a migration runs against real data.

These tests are skipped unless ``PROMPTSENTINEL_TEST_POSTGRES_URL`` is set, and CI sets
it. They cover the three things that genuinely differ between the two engines:

* **DDL portability** -- migrations that work on SQLite may not on Postgres, and the
  batch-mode rendering SQLite needs must not break the Postgres path.
* **Type mapping** -- the drift check compares the migrated schema against the ORM
  metadata on the real engine, catching anything that resolves differently there.
* **Referential integrity** -- SQLite ignores foreign keys unless asked; Postgres always
  enforces them. A cascade that silently does nothing locally must work here.
"""

from __future__ import annotations

import os
import uuid

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Connection, select, text
from sqlalchemy.ext.asyncio import create_async_engine

from promptsentinel.core.authorization import REQUIRED_ATTESTATION, Authorization
from promptsentinel.core.models import Evidence, Finding, ProbeCategory, ProbeResult, Severity
from promptsentinel.db.models import Base, FindingRow, ScanRow
from promptsentinel.db.repository import ScanRepository
from promptsentinel.db.session import Database
from promptsentinel.targets.spec import MockTargetSpec
from tests.integration.test_schema_migrations import alembic_config

POSTGRES_URL = os.environ.get("PROMPTSENTINEL_TEST_POSTGRES_URL", "")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL, reason="set PROMPTSENTINEL_TEST_POSTGRES_URL to run Postgres tests"
)

AUTHORIZATION = Authorization(
    confirmed=True, attested_by="tester@example.com", statement=REQUIRED_ATTESTATION
)


@pytest.fixture
async def pg_database():
    """A fresh Postgres database per test, built by running the migrations.

    A new database rather than a shared one with truncation: these tests are partly
    about DDL, so each needs the schema created from scratch the way a deploy would.
    """
    name = f"ps_test_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as connection:
        await connection.execute(text(f'CREATE DATABASE "{name}"'))
    await admin.dispose()

    url = POSTGRES_URL.rsplit("/", 1)[0] + f"/{name}"
    command.upgrade(alembic_config(url), "head")

    database = Database(url)
    try:
        yield database
    finally:
        await database.dispose()
        admin = create_async_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
        async with admin.connect() as connection:
            await connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


def _finding(scan_id: str) -> Finding:
    return Finding.suspicious(
        probe_id="test.probe",
        category=ProbeCategory.DIAGNOSTIC,
        title="t",
        description="d",
        severity=Severity.MEDIUM,
        evidence=Evidence(prompt="p", response="r"),
        signals=["s"],
    )


class TestMigrations:
    async def test_migrations_apply_and_match_the_models(self, pg_database: Database):
        """The drift check, on the engine that actually matters."""

        def compare(connection: Connection) -> list:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            return compare_metadata(context, Base.metadata)

        async with pg_database.engine.connect() as connection:
            diff = await connection.run_sync(compare)
        assert diff == []

    async def test_every_table_exists(self, pg_database: Database):
        async with pg_database.session() as session:
            result = await session.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                )
            )
            tables = {row[0] for row in result}
        assert {"scans", "probe_runs", "findings"} <= tables


class TestRoundTrip:
    async def test_a_scan_survives_a_write_and_read(self, pg_database: Database):
        async with pg_database.session() as session:
            scan = await ScanRepository(session).create_scan(
                target_spec=MockTargetSpec(),
                target_description="mock:in-process",
                authorization=AUTHORIZATION,
                requested_probe_ids=["diagnostic.canary_echo"],
                options={},
                webhook_url=None,
            )
            scan_id = scan.id

        async with pg_database.session() as session:
            loaded = await ScanRepository(session).get(scan_id)
            assert loaded is not None
            assert loaded.authorized_by == "tester@example.com"
            assert loaded.requested_probe_ids == ["diagnostic.canary_echo"]

    async def test_json_columns_round_trip(self, pg_database: Database):
        """JSON behaves differently enough between engines to be worth asserting."""
        async with pg_database.session() as session:
            scan = await ScanRepository(session).create_scan(
                target_spec=MockTargetSpec(system_prompt="hello"),
                target_description="mock",
                authorization=AUTHORIZATION,
                requested_probe_ids=[],
                options={"probe.id": {"nested": [1, 2, {"deep": True}]}},
                webhook_url=None,
            )
            scan_id = scan.id

        async with pg_database.session() as session:
            loaded = await ScanRepository(session).get(scan_id)
            assert loaded is not None
            assert loaded.options["probe.id"]["nested"][2]["deep"] is True
            assert loaded.target_spec_redacted["system_prompt"] == "hello"

    async def test_timestamps_come_back_timezone_aware(self, pg_database: Database):
        """Naive datetimes out of the database are a whole class of bug."""
        async with pg_database.session() as session:
            scan = await ScanRepository(session).create_scan(
                target_spec=MockTargetSpec(),
                target_description="mock",
                authorization=AUTHORIZATION,
                requested_probe_ids=[],
                options={},
                webhook_url=None,
            )
            scan_id = scan.id

        async with pg_database.session() as session:
            loaded = await ScanRepository(session).get(scan_id)
            assert loaded is not None
            assert loaded.created_at.tzinfo is not None

    async def test_results_are_persisted(self, pg_database: Database):
        async with pg_database.session() as session:
            scan = await ScanRepository(session).create_scan(
                target_spec=MockTargetSpec(),
                target_description="mock",
                authorization=AUTHORIZATION,
                requested_probe_ids=["test.probe"],
                options={},
                webhook_url=None,
            )
            scan_id = scan.id

        result = ProbeResult.completed("test.probe", [_finding(scan_id)], attempts=1)
        async with pg_database.session() as session:
            await ScanRepository(session).save_results(scan_id, [result], [])

        async with pg_database.session() as session:
            loaded = await ScanRepository(session).get(scan_id)
            assert loaded is not None
            assert loaded.status == "completed"
            assert len(loaded.findings) == 1
            assert loaded.findings[0].signals == ["s"]


class TestReferentialIntegrity:
    async def test_deleting_a_scan_cascades(self, pg_database: Database):
        """SQLite ignores foreign keys unless asked; Postgres always enforces them."""
        async with pg_database.session() as session:
            scan = await ScanRepository(session).create_scan(
                target_spec=MockTargetSpec(),
                target_description="mock",
                authorization=AUTHORIZATION,
                requested_probe_ids=["test.probe"],
                options={},
                webhook_url=None,
            )
            scan_id = scan.id

        result = ProbeResult.completed("test.probe", [_finding(scan_id)], attempts=1)
        async with pg_database.session() as session:
            await ScanRepository(session).save_results(scan_id, [result], [])

        async with pg_database.session() as session:
            scan_row = await session.get(ScanRow, scan_id)
            assert scan_row is not None
            await session.delete(scan_row)

        async with pg_database.session() as session:
            orphans = await session.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))
            assert orphans.scalars().all() == []

    async def test_a_finding_cannot_reference_a_missing_scan(self, pg_database: Database):
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            async with pg_database.session() as session:
                session.add(
                    FindingRow(
                        scan_id="does-not-exist",
                        probe_id="p",
                        category="diagnostic",
                        title="t",
                        description="d",
                        severity="low",
                        confidence="suspicious",
                    )
                )
