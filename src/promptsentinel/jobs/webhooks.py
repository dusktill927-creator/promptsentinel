"""Completion webhooks.

Polling works but wastes requests; a webhook lets a CI pipeline block on a scan
properly. Delivery is best-effort with bounded retries, and the outcome is recorded
on the scan so an operator can tell "we never told you" from "you never listened".

The payload carries only the scan ID, status, and finding counts -- never evidence.
A webhook URL is an endpoint we do not control, and transcripts from a security scan
are exactly the thing not to spray at third parties.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

logger = logging.getLogger(__name__)


async def deliver(
    url: str,
    payload: dict[str, Any],
    *,
    timeout_s: float = 10.0,
    max_attempts: int = 3,
    base_backoff_s: float = 1.0,
    client: httpx.AsyncClient | None = None,
) -> str:
    """POST ``payload`` to ``url``. Returns a short status string for the audit record.

    ``client`` and ``base_backoff_s`` exist so tests can drive every retry branch
    without opening a socket or waiting on real backoff.
    """
    last_error = "unknown"
    async with _client(client, timeout_s) as http:
        for attempt in range(1, max_attempts + 1):
            try:
                response = await http.post(url, json=payload)
            except httpx.HTTPError as exc:
                last_error = f"transport_error: {exc}"
            else:
                if response.status_code < 400:
                    return f"delivered_{response.status_code}"
                last_error = f"http_{response.status_code}"
                if 400 <= response.status_code < 500:
                    # The receiver rejected it. Retrying will not change their mind.
                    break
            if attempt < max_attempts:
                await asyncio.sleep(min(base_backoff_s * 2**attempt, 8.0))

    logger.warning("webhook delivery to %s failed: %s", url, last_error)
    return f"failed_{last_error}"[:50]


@asynccontextmanager
async def _client(
    provided: httpx.AsyncClient | None, timeout_s: float
) -> AsyncIterator[httpx.AsyncClient]:
    """Use a caller-supplied client, or own one for the duration of the delivery."""
    if provided is not None:
        yield provided
        return
    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=False) as owned:
        yield owned
