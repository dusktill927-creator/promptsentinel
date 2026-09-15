"""Engine and session lifecycle.

Wrapped in a small :class:`Database` object rather than module-level globals. Globals
make tests share state and make a second database (a test one, a read replica)
impossible to introduce later without a rewrite.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from promptsentinel.db.models import Base


class Database:
    """Owns the async engine and hands out sessions."""

    def __init__(self, url: str, *, echo: bool = False):
        self.url = url
        self._engine: AsyncEngine = create_async_engine(
            url,
            echo=echo,
            future=True,
            # SQLite's default pool serializes access badly under async; the
            # StaticPool/NullPool choice is left to SQLAlchemy's URL defaults, which
            # are correct for aiosqlite.
        )
        if url.startswith("sqlite"):
            _enable_sqlite_foreign_keys(self._engine)
        self.session_factory = async_sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def create_all(self) -> None:
        """Create the schema.

        Fine for V1 and for tests. Alembic migrations land before the first release
        that anyone else's data depends on -- see docs/ROADMAP.md.
        """
        async with self._engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """A session scoped to one unit of work, committed on success.

        Background jobs must use this rather than borrowing a request's session: the
        request is long gone by the time the scan finishes.
        """
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def dispose(self) -> None:
        await self._engine.dispose()


def _enable_sqlite_foreign_keys(engine: AsyncEngine) -> None:
    """SQLite ignores foreign keys unless asked, per connection.

    Without this, ``ON DELETE CASCADE`` silently does nothing locally and works in
    production -- the worst kind of environment difference.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_pragma(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
