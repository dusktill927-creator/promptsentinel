"""Alembic environment.

Two things here are deliberate:

* The URL comes from the application's own :class:`Settings`, not from ``alembic.ini``.
  A migration run against a different database than the application uses is a very
  expensive mistake to debug.
* Both async and sync URLs are supported. The application runs on ``aiosqlite`` or
  ``asyncpg``; the schema-drift test runs on a plain sync SQLite URL because comparing
  metadata is synchronous work. Supporting both keeps that test simple and honest.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from promptsentinel.config import get_settings
from promptsentinel.db.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """Explicit -x url= wins, then the application's configured URL."""
    override = context.get_x_argument(as_dictionary=True).get("url")
    return override or get_settings().database_url


def _is_async(url: str) -> bool:
    return "+aiosqlite" in url or "+asyncpg" in url or "+asyncmy" in url


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        # SQLite cannot ALTER most things in place; batch mode rewrites the table.
        # Without it, any future column change works on Postgres and fails locally.
        render_as_batch=connection.dialect.name == "sqlite",
    )


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations(url: str) -> None:
    engine = async_engine_from_config(
        {"sqlalchemy.url": url}, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    async with engine.connect() as connection:
        await connection.run_sync(_run)
        await connection.commit()
    await engine.dispose()


def _drive_async(url: str) -> None:
    """Run the async migration, whether or not a loop is already running.

    Alembic's command API is synchronous, so there is nothing to await from here. Called
    from ordinary tooling there is no loop and ``asyncio.run`` is correct; called from
    inside an async application or test there already is one, and ``asyncio.run`` would
    raise -- surfacing as a bare "coroutine was never awaited" warning rather than an
    error anyone can act on. In that case the migration gets its own loop on a worker
    thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(run_async_migrations(url))
        return

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(asyncio.run, run_async_migrations(url)).result()


def run_migrations_online() -> None:
    url = _database_url()
    if _is_async(url):
        _drive_async(url)
        return

    engine = engine_from_config(
        {"sqlalchemy.url": url}, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with engine.connect() as connection:
        _run(connection)
        connection.commit()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
