"""Runtime configuration.

Settings come from the environment with a ``PROMPTSENTINEL_`` prefix, so the same
image runs locally against SQLite and in a container against Postgres with no code
change. Defaults are the *development* defaults; the production notes call out which
ones must be overridden.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process configuration."""

    model_config = SettingsConfigDict(
        env_prefix="PROMPTSENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite+aiosqlite:///./promptsentinel.db"
    """SQLAlchemy async URL. Swap for ``postgresql+asyncpg://...`` in production."""

    allow_mock_targets: bool = True
    """Set false in production. A mock target yields a clean report with nothing tested."""

    max_concurrent_scans: int = 2
    """In-process worker slots. Bounds load on this machine, not on the target."""

    max_concurrent_probes: int = 4
    """Probes running at once within one scan. This is the knob that throttles the
    request rate the target sees -- keep it low: PromptSentinel must never look like
    a denial-of-service against the operator's own application."""

    probe_timeout_s: float = 60.0
    """Wall clock per probe. A hung probe must not be able to stall a scan forever."""

    scan_timeout_s: float = 900.0
    """Wall clock per scan, including all probes."""

    webhook_timeout_s: float = 10.0
    webhook_max_attempts: int = 3

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Cached accessor. Overridden in tests via FastAPI dependency overrides."""
    return Settings()
