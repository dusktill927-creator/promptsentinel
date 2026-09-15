"""Webhook delivery: retries, give-up conditions, and what the payload may contain."""

from __future__ import annotations

import httpx

from promptsentinel.jobs import webhooks

PAYLOAD = {"event": "scan.completed", "scan_id": "abc"}


async def deliver(handler, **kwargs) -> str:
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        return await webhooks.deliver(
            "https://hooks.example.com/x", PAYLOAD, client=client, base_backoff_s=0, **kwargs
        )


class TestSuccess:
    async def test_2xx_is_recorded_as_delivered(self):
        assert await deliver(lambda r: httpx.Response(200)) == "delivered_200"

    async def test_202_counts_as_delivered(self):
        assert await deliver(lambda r: httpx.Response(202)) == "delivered_202"

    async def test_payload_is_posted_as_json(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(200)

        await deliver(handler)
        assert seen["body"] == PAYLOAD


class TestRetries:
    async def test_5xx_is_retried_then_reported_failed(self):
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(503)

        status = await deliver(handler, max_attempts=3)
        assert attempts == 3
        assert status.startswith("failed_http_503")

    async def test_4xx_is_not_retried(self):
        """The receiver rejected the payload. Retrying will not change their mind."""
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(400)

        await deliver(handler, max_attempts=3)
        assert attempts == 1

    async def test_transport_errors_are_retried(self):
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            raise httpx.ConnectError("refused")

        status = await deliver(handler, max_attempts=2)
        assert attempts == 2
        assert "transport_error" in status

    async def test_recovers_on_a_later_attempt(self):
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(500 if attempts == 1 else 200)

        assert await deliver(handler, max_attempts=3) == "delivered_200"

    async def test_status_string_fits_the_audit_column(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("x" * 500)

        assert len(await deliver(handler, max_attempts=1)) <= 50


class TestOwnedClient:
    async def test_works_without_an_injected_client(self):
        """Production path: deliver() opens and closes its own client."""
        status = await webhooks.deliver(
            "http://127.0.0.1:9/hook", PAYLOAD, max_attempts=1, base_backoff_s=0
        )
        assert status.startswith("failed_")
