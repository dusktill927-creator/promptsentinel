"""Credential hand-off.

The property under test is narrow and important: a target's API key reaches the worker
and nowhere else. Not the database, not the queue, not a report, and not the store for
longer than the scan needs it.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from promptsentinel.secrets import InMemorySecretStore, SecretNotFoundError, scan_secret_key
from promptsentinel.targets.spec import (
    MockTargetSpec,
    OpenAICompatibleTargetSpec,
    deserialize_spec,
    serialize_with_secrets,
)

SECRET = "sk-super-secret-value"
SPEC = OpenAICompatibleTargetSpec(
    base_url="https://api.example.com/v1",
    model="gpt-test",
    api_key=SECRET,
    system_prompt="You are ACME support.",
)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestInMemoryStore:
    async def test_round_trip(self):
        store = InMemorySecretStore()
        await store.put("k", "v", ttl_s=60)
        assert await store.get("k") == "v"

    async def test_missing_keys_raise(self):
        with pytest.raises(SecretNotFoundError):
            await InMemorySecretStore().get("nope")

    async def test_expired_values_raise(self):
        """A worker that picks up a stale job must not get a live credential."""
        clock = Clock()
        store = InMemorySecretStore(clock=clock)
        await store.put("k", "v", ttl_s=10)
        clock.now = 10.0
        with pytest.raises(SecretNotFoundError, match="expired"):
            await store.get("k")

    async def test_values_survive_until_they_expire(self):
        clock = Clock()
        store = InMemorySecretStore(clock=clock)
        await store.put("k", "v", ttl_s=10)
        clock.now = 9.999
        assert await store.get("k") == "v"

    async def test_delete_removes_the_value(self):
        store = InMemorySecretStore()
        await store.put("k", "v", ttl_s=60)
        await store.delete("k")
        with pytest.raises(SecretNotFoundError):
            await store.get("k")

    async def test_deleting_an_absent_key_is_not_an_error(self):
        """The worker deletes in a finally block; it must not mask the real failure."""
        await InMemorySecretStore().delete("never-existed")

    async def test_close_drops_everything(self):
        store = InMemorySecretStore()
        await store.put("k", "v", ttl_s=60)
        await store.aclose()
        with pytest.raises(SecretNotFoundError):
            await store.get("k")

    def test_keys_are_namespaced_by_scan(self):
        assert scan_secret_key("abc") != scan_secret_key("abd")
        assert "abc" in scan_secret_key("abc")


class TestSpecSerialization:
    def test_secrets_survive_the_round_trip(self):
        restored = deserialize_spec(serialize_with_secrets(SPEC))
        assert isinstance(restored, OpenAICompatibleTargetSpec)
        assert restored.api_key is not None
        assert restored.api_key.get_secret_value() == SECRET

    def test_the_rest_of_the_spec_survives_too(self):
        restored = deserialize_spec(serialize_with_secrets(SPEC))
        assert isinstance(restored, OpenAICompatibleTargetSpec)
        assert restored.model == "gpt-test"
        assert restored.system_prompt == "You are ACME support."

    def test_the_discriminated_union_is_preserved(self):
        restored = deserialize_spec(serialize_with_secrets(MockTargetSpec(quote_documents=True)))
        assert isinstance(restored, MockTargetSpec)
        assert restored.quote_documents is True

    def test_this_is_the_only_path_that_reveals_secrets(self):
        """Every other serialization must still redact."""
        assert SECRET not in SPEC.model_dump_json()
        assert SECRET not in json.dumps(SPEC.model_dump(mode="json"))
        assert SECRET not in repr(SPEC)
        assert SECRET in serialize_with_secrets(SPEC)

    def test_a_nested_secret_would_also_be_revealed(self):
        """Guards the walk: a SecretStr added anywhere later must not be dropped."""
        from pydantic import SecretStr

        from promptsentinel.targets.spec import _reveal

        nested = {"a": [{"b": SecretStr("inner")}]}
        assert _reveal(nested) == {"a": [{"b": "inner"}]}

    def test_malformed_payloads_are_rejected(self):
        """Validated on the way back in, not trusted because we wrote it."""
        with pytest.raises(ValidationError):
            deserialize_spec('{"kind": "telepathy"}')


class TestEndToEndHandoff:
    async def test_the_worker_can_recover_what_the_api_stored(self):
        store = InMemorySecretStore()
        key = scan_secret_key("scan-1")

        await store.put(key, serialize_with_secrets(SPEC), ttl_s=300)
        restored = deserialize_spec(await store.get(key))

        assert isinstance(restored, OpenAICompatibleTargetSpec)
        assert restored.api_key is not None
        assert restored.api_key.get_secret_value() == SECRET
