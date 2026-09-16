"""Migrations and models must never drift apart.

The application creates its schema from the ORM models in development and from Alembic
migrations in production. If those two ever disagree, the bug appears only after a
deploy, against real data, which is the worst possible place to discover it.

This test runs every migration against an empty database and asks Alembic to diff the
result against ``Base.metadata``. Any difference -- a column added to a model without a
migration, a migration that does not match the model -- fails here instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from promptsentinel.db.models import Base

REPO_ROOT = Path(__file__).resolve().parents[2]


def alembic_config(url: str) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    # -x url= wins over the environment, so the test never touches a real database.
    config.cmd_opts = type("Opts", (), {"x": [f"url={url}"]})()
    return config


@pytest.fixture
def migrated_url(tmp_path) -> str:
    """A database built the way production builds one: by running the migrations."""
    url = f"sqlite:///{tmp_path}/migrated.db"
    command.upgrade(alembic_config(url), "head")
    return url


class TestNoDrift:
    def test_migrations_produce_the_model_schema(self, migrated_url):
        engine = create_engine(migrated_url)
        try:
            with engine.connect() as connection:
                context = MigrationContext.configure(connection, opts={"compare_type": True})
                diff = compare_metadata(context, Base.metadata)
        finally:
            engine.dispose()

        assert diff == [], (
            "migrations and ORM models disagree; run "
            "`alembic revision --autogenerate` and commit the result"
        )

    def test_every_table_is_created(self, migrated_url):
        engine = create_engine(migrated_url)
        try:
            tables = set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
        assert {"scans", "probe_runs", "findings"} <= tables


class TestRevisions:
    def test_there_is_exactly_one_head(self):
        """Two heads mean a merge was missed, and `upgrade head` becomes ambiguous."""
        script = ScriptDirectory(str(REPO_ROOT / "migrations"))
        assert len(script.get_heads()) == 1

    def test_downgrade_is_implemented(self, tmp_path):
        """A migration you cannot roll back is a migration you cannot deploy safely."""
        url = f"sqlite:///{tmp_path}/roundtrip.db"
        config = alembic_config(url)
        command.upgrade(config, "head")
        command.downgrade(config, "base")

        engine = create_engine(url)
        try:
            tables = set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
        assert "scans" not in tables


class TestStartupBehaviour:
    async def test_schema_creation_can_be_disabled(self, tmp_path):
        """Production sets this false and runs migrations as a deploy step."""
        from promptsentinel.api.app import create_app
        from promptsentinel.config import Settings
        from promptsentinel.db.session import Database

        settings = Settings(
            database_url=f"sqlite+aiosqlite:///{tmp_path}/empty.db",
            auto_create_schema=False,
        )
        database = Database(settings.database_url)
        app = create_app(settings=settings, database=database)
        try:
            async with app.router.lifespan_context(app):
                pass
        finally:
            await database.dispose()

        engine = create_engine(f"sqlite:///{tmp_path}/empty.db")
        try:
            assert inspect(engine).get_table_names() == []
        finally:
            engine.dispose()
