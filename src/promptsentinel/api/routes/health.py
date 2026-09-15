"""Liveness and readiness."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from promptsentinel import __version__
from promptsentinel.api.deps import DatabaseDep

router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness probe")
async def healthz() -> dict[str, str]:
    """Process is up. Deliberately does not touch the database.

    Mixing liveness and readiness means a slow database gets your pods restarted.
    """
    return {"status": "ok", "version": __version__}


@router.get("/readyz", summary="Readiness probe")
async def readyz(database: DatabaseDep) -> dict[str, str]:
    """Dependencies are reachable."""
    async with database.session() as session:
        await session.execute(text("SELECT 1"))
    return {"status": "ready"}
