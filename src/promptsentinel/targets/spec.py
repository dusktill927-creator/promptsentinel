"""Target specifications: the serializable description of a system under test.

A spec is data (it travels over HTTP, gets persisted with the scan, and is replayable);
a :class:`~promptsentinel.targets.base.Target` is a live object holding a connection
pool. Keeping them apart means a scan record stays readable long after the client is
gone, and the API layer never has to hold an open socket to validate a request.

Specs form a discriminated union on ``kind``, so adding a target type is one new class
plus one line in :data:`TargetSpec` -- FastAPI then documents it in OpenAPI for free.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class OpenAICompatibleTargetSpec(BaseModel):
    """Any endpoint speaking the OpenAI ``/chat/completions`` dialect.

    That covers OpenAI itself, vLLM, Ollama, LiteLLM, Together, and most in-house
    gateways -- which is why it is the first adapter rather than a vendor SDK.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["openai_compatible"] = "openai_compatible"
    base_url: str = Field(
        description="Root URL of the API, e.g. https://api.example.com/v1",
        examples=["http://localhost:8000/v1"],
    )
    model: str = Field(min_length=1, description="Model or deployment name to request.")
    api_key: SecretStr | None = Field(
        default=None,
        description="Sent as a Bearer token. SecretStr keeps it out of logs and reports.",
    )
    headers: dict[str, str] = Field(
        default_factory=dict, description="Extra headers, e.g. a gateway tenant ID."
    )
    system_prompt: str | None = Field(
        default=None,
        description=(
            "The application's own system prompt, if the operator wants probes to run "
            "against it. Probes that seed canaries append to this."
        ),
    )
    timeout_s: float = Field(default=30.0, gt=0, le=300)

    @field_validator("base_url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http:// or https:// URL")
        return normalized


class MockToolCall(BaseModel):
    """A tool call the mock should emit when its rule fires."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    arguments: dict[str, object] = Field(default_factory=dict)


class MockRule(BaseModel):
    """One scripted behaviour of the mock target."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str = Field(description="Python regex matched against the last user message.")
    response: str = ""
    tool_calls: list[MockToolCall] = Field(default_factory=list)


class MockTargetSpec(BaseModel):
    """An in-process fake target.

    Present so the full pipeline can be exercised in tests and demos without spending
    tokens or needing a real endpoint. Gated in the API by
    ``PROMPTSENTINEL_ALLOW_MOCK_TARGETS`` so a production deployment can refuse it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["mock"] = "mock"
    system_prompt: str | None = None
    default_response: str = "I'm a demo assistant. How can I help?"
    rules: list[MockRule] = Field(
        default_factory=list,
        description="Ordered regex rules; the first match decides the reply.",
    )
    leak_system_prompt_on: str | None = Field(
        default=None,
        description=(
            "Regex that makes the mock disclose its system prompt verbatim -- used to "
            "simulate a vulnerable application."
        ),
    )


TargetSpec = Annotated[
    OpenAICompatibleTargetSpec | MockTargetSpec,
    Field(discriminator="kind"),
]
"""The union accepted by the API. New target kinds are added here."""
