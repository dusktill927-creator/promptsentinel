"""Exception hierarchy.

Every error the engine raises inherits from :class:`PromptSentinelError`, so the API
layer can map the domain to HTTP without a bare ``except Exception``.
"""

from __future__ import annotations


class PromptSentinelError(Exception):
    """Base class for all PromptSentinel errors."""


class AuthorizationError(PromptSentinelError):
    """Raised when a scan is attempted without a valid authorization attestation.

    This is deliberately its own type: it is the one error that must never be
    swallowed, retried, or downgraded into a warning.
    """


class TargetError(PromptSentinelError):
    """The target application could not be reached or returned an unusable response."""


class ProbeError(PromptSentinelError):
    """A probe failed in a way that is the probe's fault, not the target's."""


class ConfigurationError(PromptSentinelError):
    """The scan request is internally inconsistent (unknown probe, bad target spec)."""
