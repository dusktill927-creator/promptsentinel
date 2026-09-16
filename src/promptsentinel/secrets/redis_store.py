"""Redis-backed credential store, for deployments where the worker is another process."""

from __future__ import annotations

from redis.asyncio import Redis

from promptsentinel.secrets.store import SecretNotFoundError


class RedisSecretStore:
    """Short-lived credential storage in Redis.

    Every write sets an expiry. There is no code path here that stores a credential
    without one, which matters more than it looks: the worker's explicit delete is the
    normal case, and the TTL is what covers the abnormal ones -- a worker killed
    mid-scan, a queue backlog, a scan enqueued against a broker nobody is reading.
    """

    def __init__(self, url: str, *, client: Redis | None = None):
        self._client: Redis = client or Redis.from_url(url, decode_responses=True)

    async def put(self, key: str, value: str, *, ttl_s: float) -> None:
        # SET with an expiry in one round trip: a separate EXPIRE could fail after the
        # SET succeeded and leave a credential in Redis forever.
        await self._client.set(key, value, ex=max(1, int(ttl_s)))

    async def get(self, key: str) -> str:
        value = await self._client.get(key)
        if value is None:
            raise SecretNotFoundError(
                f"no stored credentials for {key}; the scan may have waited longer "
                "than PROMPTSENTINEL_TARGET_SECRET_TTL_S"
            )
        return str(value)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def aclose(self) -> None:
        await self._client.aclose()
