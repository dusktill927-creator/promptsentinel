"""API authentication.

PromptSentinel submits attacks against endpoints on the operator's behalf. An
unauthenticated instance is a machine that will attack any URL anyone posts to it, with
the operator's credentials and from the operator's network. That makes authentication a
correctness requirement, not a hardening step.

Keys are stored as **SHA-256 hashes**, so a leaked configuration file, environment dump
or container image does not hand over working credentials.

A fast hash is the right choice here, which is worth being explicit about because the
usual advice says otherwise. bcrypt, scrypt and Argon2 exist to make *guessing*
expensive, and guessing is only a threat when the secret has little entropy -- a human
password. These keys are 256 bits from ``secrets.token_urlsafe``; brute force is not on
the table, and a slow KDF on every request would only add latency and a DoS vector.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from typing import Final

from fastapi import Header, HTTPException, Request, status

logger = logging.getLogger(__name__)

KEY_BYTES: Final = 32
_SCHEME: Final = "Bearer"


def generate_key() -> tuple[str, str]:
    """Create a new API key. Returns ``(key, hash)``.

    The key is shown once, to be handed to the client; only the hash is ever stored.
    """
    key = f"ps_{secrets.token_urlsafe(KEY_BYTES)}"
    return key, hash_key(key)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _presented(authorization: str | None, x_api_key: str | None) -> str | None:
    """Accept either ``Authorization: Bearer ...`` or ``X-API-Key: ...``.

    Two headers because both are common in the tools that would call this: Bearer for
    HTTP clients and SDKs, X-API-Key for webhooks and CI runners with fixed header maps.
    """
    if authorization:
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() == _SCHEME.lower() and credential:
            return credential.strip()
    return x_api_key.strip() if x_api_key else None


def verify(presented: str, hashes: list[str]) -> bool:
    """Constant-time check of a presented key against the configured hashes.

    Every configured hash is compared even after a match, and the comparison is
    ``hmac.compare_digest``, so neither the number of configured keys nor which one
    matched is observable through response timing.
    """
    digest = hash_key(presented)
    matched = False
    for candidate in hashes:
        if hmac.compare_digest(digest, candidate):
            matched = True
    return matched


async def require_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> None:
    """Dependency guarding every ``/v1`` route.

    Health endpoints are deliberately not guarded: a liveness probe that needs a
    credential is a liveness probe that reports an outage when the credential rotates.
    """
    settings = request.app.state.settings
    if settings.allow_unauthenticated:
        return

    presented = _presented(authorization, x_api_key)
    if presented and verify(presented, settings.api_key_hashes):
        return

    # The reason is never disclosed: "missing" and "wrong" look identical to a caller,
    # so a probing client learns nothing about which keys exist.
    logger.warning(
        "rejected unauthenticated request to %s from %s",
        request.url.path,
        request.client.host if request.client else "unknown",
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="a valid API key is required",
        headers={"WWW-Authenticate": _SCHEME},
    )
