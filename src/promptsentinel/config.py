"""Runtime configuration.

Settings come from the environment with a ``PROMPTSENTINEL_`` prefix, so the same
image runs locally against SQLite and in a container against Postgres with no code
change. Defaults are the *development* defaults; the production notes call out which
ones must be overridden.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from promptsentinel.targets.rate_limit import RateLimit


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

    auto_create_schema: bool = True
    """Create tables from the ORM models at startup.

    A development convenience. Production deployments should set this false and run
    ``alembic upgrade head`` as an explicit deploy step: a process that silently
    reshapes a live schema on boot is a process that can silently lose data during a
    rollback. The migrations and the models are kept identical by a drift test, so the
    two paths produce the same schema."""

    api_key_hashes: Annotated[list[str], NoDecode] = []
    """SHA-256 hashes of accepted API keys, comma-separated in the environment.

    ``NoDecode`` is required, not decoration: pydantic-settings JSON-decodes complex
    types from the environment *before* field validators run, so without it a plain
    comma-separated value raises a parse error at startup rather than reaching the
    validator below.

    Generate a pair with ``promptsentinel keygen``. Only hashes are stored, so a
    leaked config file or image does not hand over working credentials."""

    allow_unauthenticated: bool = False
    """Serve the API with no authentication.

    False by default and the startup check refuses to run without either keys or this
    flag, because an unauthenticated instance is a machine that will attack any URL
    anyone posts to it, using the operator's credentials and network."""

    allow_mock_targets: bool = True
    """Set false in production. A mock target yields a clean report with nothing tested."""

    max_concurrent_scans: int = 2
    """In-process worker slots. Bounds load on this machine, not on the target."""

    max_concurrent_probes: int = 4
    """Probes running at once within one scan. This is the knob that throttles the
    request rate the target sees -- keep it low: PromptSentinel must never look like
    a denial-of-service against the operator's own application."""

    target_requests_per_second: float = 2.0
    """Sustained request rate allowed against the target.

    Deliberately low. This is someone's production application, and the default should
    be a rate a human could plausibly generate rather than one that needs a capacity
    review before the first scan."""

    target_burst: int = 4
    """Requests allowed back to back before pacing engages."""

    probe_timeout_s: float = 60.0
    """Wall clock per probe. A hung probe must not be able to stall a scan forever."""

    scan_timeout_s: float = 900.0
    """Wall clock per scan, including all probes."""

    target_secret_ttl_s: float = 1800.0
    """How long a queued scan's credentials stay retrievable.

    Long enough to survive a backlog, short enough that a credential for a scan that
    never ran does not sit in the store indefinitely. The worker deletes it as soon as
    the scan ends regardless."""

    webhook_timeout_s: float = 10.0
    webhook_max_attempts: int = 3

    log_level: str = "INFO"

    @field_validator("api_key_hashes", mode="before")
    @classmethod
    def _split_hashes(cls, value: object) -> object:
        """Accept a comma-separated string, which is how env vars carry lists."""
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @property
    def rate_limit(self) -> RateLimit:
        """Pacing for a scan's target."""
        return RateLimit(
            requests_per_second=self.target_requests_per_second, burst=self.target_burst
        )


@lru_cache
def get_settings() -> Settings:
    """Cached accessor. Overridden in tests via FastAPI dependency overrides."""
    return Settings()
