"""Settings, loaded the way they are actually loaded.

Constructing ``Settings(field=[...])`` in a test exercises a different code path from
reading the same field out of the environment, and the environment is the only path
production uses. These tests go through the environment.
"""

from __future__ import annotations

import pytest

from promptsentinel.config import Settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (
        "PROMPTSENTINEL_API_KEY_HASHES",
        "PROMPTSENTINEL_ALLOW_UNAUTHENTICATED",
        "PROMPTSENTINEL_DATABASE_URL",
        "PROMPTSENTINEL_AUTO_CREATE_SCHEMA",
    ):
        monkeypatch.delenv(name, raising=False)


class TestApiKeyHashesFromEnvironment:
    """Regression: this field used to fail to parse from a real environment variable.

    pydantic-settings JSON-decodes complex types before validators run, so a plain
    comma-separated value raised SettingsError at startup. The unit tests passed a
    Python list directly and never touched that path; a live server caught it.
    """

    def test_a_single_hash(self, monkeypatch):
        monkeypatch.setenv("PROMPTSENTINEL_API_KEY_HASHES", "abc123")
        assert Settings().api_key_hashes == ["abc123"]

    def test_several_comma_separated_hashes(self, monkeypatch):
        monkeypatch.setenv("PROMPTSENTINEL_API_KEY_HASHES", "aaa,bbb,ccc")
        assert Settings().api_key_hashes == ["aaa", "bbb", "ccc"]

    def test_whitespace_is_tolerated(self, monkeypatch):
        monkeypatch.setenv("PROMPTSENTINEL_API_KEY_HASHES", " aaa , bbb ")
        assert Settings().api_key_hashes == ["aaa", "bbb"]

    def test_empty_entries_are_dropped(self, monkeypatch):
        """A trailing comma must not admit an empty-string 'key'."""
        monkeypatch.setenv("PROMPTSENTINEL_API_KEY_HASHES", "aaa,,")
        assert Settings().api_key_hashes == ["aaa"]

    def test_unset_means_no_keys(self):
        assert Settings().api_key_hashes == []

    def test_json_is_not_special_cased(self, monkeypatch):
        """Comma-separated is the only supported form; JSON is split like any string.

        Documented rather than fixed: supporting both would mean guessing at the
        intent of a value, and a key list is the wrong place to guess.
        """
        monkeypatch.setenv("PROMPTSENTINEL_API_KEY_HASHES", '["aaa","bbb"]')
        assert Settings().api_key_hashes == ['["aaa"', '"bbb"]']


class TestSecurityDefaults:
    def test_authentication_is_required_by_default(self):
        assert Settings().allow_unauthenticated is False

    def test_the_opt_out_reads_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("PROMPTSENTINEL_ALLOW_UNAUTHENTICATED", "true")
        assert Settings().allow_unauthenticated is True

    def test_schema_creation_defaults_on_for_development(self):
        assert Settings().auto_create_schema is True

    def test_database_url_is_overridable(self, monkeypatch):
        monkeypatch.setenv("PROMPTSENTINEL_DATABASE_URL", "postgresql+asyncpg://x/y")
        assert Settings().database_url == "postgresql+asyncpg://x/y"
