"""Credential hand-off between the API and a worker.

The in-process queue could pass a live ``TargetSpec`` through memory, which kept API
keys off disk entirely. A distributed queue cannot: the worker is a different process,
often on a different machine. Putting credentials in the queue message would spread them
across every broker, replica and backup that message touches -- and queue payloads are
exactly the thing people dump when debugging.

So the queue carries **only a scan ID**, in both the in-process and distributed cases,
and credentials travel through a store built for the purpose:

* entries expire on their own, so a worker that dies never leaves a credential behind;
* the worker deletes the entry as soon as the scan ends, success or failure;
* the persisted scan row keeps its redacted copy, so the audit trail is unaffected.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from promptsentinel.core.errors import PromptSentinelError


class SecretNotFoundError(PromptSentinelError):
    """The credential is gone: expired, already consumed, or never stored.

    A distinct type because the operator response differs from other failures. It
    usually means the scan sat in the queue longer than the secret's lifetime, which is
    a capacity problem rather than a problem with their application.
    """


def scan_secret_key(scan_id: str) -> str:
    """Namespaced key for a scan's target configuration."""
    return f"promptsentinel:scan:{scan_id}:target"


class SecretStore(Protocol):
    """Somewhere to put a credential for as long as a scan takes, and no longer."""

    async def put(self, key: str, value: str, *, ttl_s: float) -> None:
        """Store ``value``, to be forgotten after ``ttl_s`` whatever else happens."""
        ...

    async def get(self, key: str) -> str:
        """Fetch a value.

        Raises:
            SecretNotFoundError: if it is absent or has expired.
        """
        ...

    async def delete(self, key: str) -> None:
        """Forget a value. Must not raise if it is already gone."""
        ...

    async def aclose(self) -> None:
        """Release resources."""
        ...


class InMemorySecretStore:
    """Process-local store, for development and for the in-process queue.

    Correct only while the API and the worker share a process. The startup checks in
    ``api/app.py`` refuse the combination of a distributed queue and this store rather
    than letting every scan fail at credential lookup.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._entries: dict[str, tuple[str, float]] = {}

    async def put(self, key: str, value: str, *, ttl_s: float) -> None:
        self._entries[key] = (value, self._clock() + ttl_s)

    async def get(self, key: str) -> str:
        entry = self._entries.get(key)
        if entry is None:
            raise SecretNotFoundError(f"no stored credentials for {key}")
        value, expires_at = entry
        if self._clock() >= expires_at:
            # Expire lazily. Nothing here is big enough to justify a sweeper, and a
            # caller can never observe an expired value.
            del self._entries[key]
            raise SecretNotFoundError(f"stored credentials for {key} have expired")
        return value

    async def delete(self, key: str) -> None:
        self._entries.pop(key, None)

    async def aclose(self) -> None:
        self._entries.clear()
