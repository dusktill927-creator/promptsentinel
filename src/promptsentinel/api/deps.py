"""FastAPI dependencies.

Everything the routes need is reached through a dependency rather than a module
global. That is what makes the integration tests possible: a test overrides
:func:`get_database` with an in-memory SQLite instance and the rest of the app is
unchanged.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from promptsentinel.config import Settings
from promptsentinel.db.session import Database
from promptsentinel.jobs.queue import JobQueue
from promptsentinel.probes.registry import ProbeRegistry
from promptsentinel.secrets import SecretStore


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_database(request: Request) -> Database:
    database: Database = request.app.state.database
    return database


def get_queue(request: Request) -> JobQueue:
    queue: JobQueue = request.app.state.queue
    return queue


def get_secrets(request: Request) -> SecretStore:
    store: SecretStore = request.app.state.secrets
    return store


def get_registry(request: Request) -> ProbeRegistry:
    registry: ProbeRegistry = request.app.state.registry
    return registry


SettingsDep = Annotated[Settings, Depends(get_settings)]
DatabaseDep = Annotated[Database, Depends(get_database)]
QueueDep = Annotated[JobQueue, Depends(get_queue)]
RegistryDep = Annotated[ProbeRegistry, Depends(get_registry)]
SecretsDep = Annotated[SecretStore, Depends(get_secrets)]
