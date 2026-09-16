"""Distributed mode: Redis queue, Redis secret store, separate worker.

Skipped unless ``PROMPTSENTINEL_TEST_REDIS_URL`` is set. These cover the pieces that
only exist once the API and the worker stop sharing a process -- the credential
hand-off in particular, which is the reason the in-process queue could stay simple.
"""

from __future__ import annotations

import os
import uuid

import pytest

from promptsentinel.jobs.redis_queue import RUN_SCAN, RedisJobQueue
from promptsentinel.secrets import SecretNotFoundError, scan_secret_key
from promptsentinel.secrets.redis_store import RedisSecretStore
from promptsentinel.targets.spec import (
    OpenAICompatibleTargetSpec,
    deserialize_spec,
    serialize_with_secrets,
)

REDIS_URL = os.environ.get("PROMPTSENTINEL_TEST_REDIS_URL", "")

pytestmark = pytest.mark.skipif(
    not REDIS_URL, reason="set PROMPTSENTINEL_TEST_REDIS_URL to run Redis tests"
)

SECRET = "sk-live-credential"
SPEC = OpenAICompatibleTargetSpec(base_url="https://api.example.com/v1", model="m", api_key=SECRET)


@pytest.fixture
async def store():
    secret_store = RedisSecretStore(REDIS_URL)
    try:
        yield secret_store
    finally:
        await secret_store.aclose()


@pytest.fixture
async def queue():
    job_queue = RedisJobQueue(REDIS_URL)
    try:
        yield job_queue
    finally:
        await job_queue.aclose()


def a_key() -> str:
    return scan_secret_key(uuid.uuid4().hex)


class TestRedisSecretStore:
    async def test_round_trip(self, store: RedisSecretStore):
        key = a_key()
        await store.put(key, "value", ttl_s=60)
        assert await store.get(key) == "value"
        await store.delete(key)

    async def test_a_credential_survives_the_hand_off(self, store: RedisSecretStore):
        """What the API writes is exactly what a separate worker will read."""
        key = a_key()
        await store.put(key, serialize_with_secrets(SPEC), ttl_s=60)

        restored = deserialize_spec(await store.get(key))
        assert isinstance(restored, OpenAICompatibleTargetSpec)
        assert restored.api_key is not None
        assert restored.api_key.get_secret_value() == SECRET
        await store.delete(key)

    async def test_missing_keys_raise(self, store: RedisSecretStore):
        with pytest.raises(SecretNotFoundError):
            await store.get(a_key())

    async def test_the_error_explains_the_likely_cause(self, store: RedisSecretStore):
        with pytest.raises(SecretNotFoundError, match="TARGET_SECRET_TTL_S"):
            await store.get(a_key())

    async def test_delete_is_idempotent(self, store: RedisSecretStore):
        await store.delete(a_key())

    async def test_every_write_carries_an_expiry(self, store: RedisSecretStore):
        """No path stores a credential without a TTL; that is what covers dead workers."""
        key = a_key()
        await store.put(key, "value", ttl_s=60)
        ttl = await store._client.ttl(key)
        assert 0 < ttl <= 60
        await store.delete(key)

    async def test_a_sub_second_ttl_still_expires(self, store: RedisSecretStore):
        """Redis expiries are integer seconds; a tiny TTL must not become 'forever'."""
        key = a_key()
        await store.put(key, "value", ttl_s=0.1)
        assert await store._client.ttl(key) >= 1
        await store.delete(key)


class TestRedisJobQueue:
    async def test_enqueue_publishes_the_job(self, queue: RedisJobQueue, store):
        scan_id = uuid.uuid4().hex
        await queue.enqueue(scan_id)

        pool = await queue._connect()
        assert await pool.exists(f"arq:job:scan:{scan_id}")

    async def test_the_message_is_only_an_id(self, queue: RedisJobQueue):
        """A credential must never be recoverable from the broker."""
        scan_id = uuid.uuid4().hex
        await queue.enqueue(scan_id)

        pool = await queue._connect()
        payload = await pool.get(f"arq:job:scan:{scan_id}")
        assert payload is not None
        assert SECRET.encode() not in payload
        assert scan_id.encode() in payload

    async def test_enqueuing_twice_is_idempotent(self, queue: RedisJobQueue):
        """A retried submission must not produce two workers scanning one target."""
        scan_id = uuid.uuid4().hex
        await queue.enqueue(scan_id)
        await queue.enqueue(scan_id)

        pool = await queue._connect()
        queued = await pool.zcard("arq:queue")
        assert queued >= 1
        jobs = await pool.keys(f"arq:job:scan:{scan_id}")
        assert len(jobs) == 1

    async def test_the_task_name_matches_the_worker(self, queue: RedisJobQueue):
        """A mismatch here means jobs queue forever and nothing reports an error."""
        from promptsentinel.jobs.arq_worker import WorkerSettings

        assert [f.__name__ for f in WorkerSettings.functions] == [RUN_SCAN]


class TestBackendSelection:
    def test_redis_url_switches_both_backends_together(self):
        """They must agree: a Redis queue with a local secret store fails every scan."""
        from promptsentinel.api.app import _build_backends
        from promptsentinel.config import Settings
        from promptsentinel.probes.registry import REGISTRY

        settings = Settings(redis_url=REDIS_URL, allow_unauthenticated=True)
        store, queue = _build_backends(settings, None, REGISTRY, None)  # type: ignore[arg-type]

        assert isinstance(store, RedisSecretStore)
        assert isinstance(queue, RedisJobQueue)

    def test_no_redis_url_keeps_everything_in_process(self):
        from promptsentinel.api.app import _build_backends
        from promptsentinel.config import Settings
        from promptsentinel.jobs.queue import InProcessJobQueue
        from promptsentinel.probes.registry import REGISTRY
        from promptsentinel.secrets import InMemorySecretStore

        settings = Settings(allow_unauthenticated=True)
        store, queue = _build_backends(settings, None, REGISTRY, None)  # type: ignore[arg-type]

        assert isinstance(store, InMemorySecretStore)
        assert isinstance(queue, InProcessJobQueue)
