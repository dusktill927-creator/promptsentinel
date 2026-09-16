"""Target specifications: the serializable description of a system under test.

A spec is data (it travels over HTTP, gets persisted with the scan, and is replayable);
a :class:`~promptsentinel.targets.base.Target` is a live object holding a connection
pool. Keeping them apart means a scan record stays readable long after the client is
gone, and the API layer never has to hold an open socket to validate a request.

Specs form a discriminated union on ``kind``, so adding a target type is one new class
plus one line in :data:`TargetSpec` -- FastAPI then documents it in OpenAPI for free.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, TypeAdapter, field_validator

from promptsentinel.targets.base import ToolDefinition


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

    retrieval: RetrievalConfig | None = Field(
        default=None,
        description=(
            "Describe how your application injects retrieved documents. Supplying this "
            "marks the target as a RAG deployment and enables indirect-injection "
            "probes; omitting it makes them report SKIPPED rather than a clean pass."
        ),
    )
    tools: list[ToolDefinition] = Field(
        default_factory=list,
        description=(
            "Tools your application exposes, each marked restricted or not. Supplying "
            "these enables excessive-agency probes; omitting them makes those probes "
            "report SKIPPED rather than a clean pass."
        ),
    )

    @field_validator("base_url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http:// or https:// URL")
        return normalized


class HttpTargetSpec(BaseModel):
    """Any HTTP chat application, described by the operator.

    The OpenAI-compatible adapter covers a lot, but plenty of real deployments sit
    behind a bespoke endpoint that takes ``{"question": ...}`` and returns
    ``{"data": {"answer": ...}}``. Without this, those applications simply could not be
    tested -- which is a strange gap in a tool whose thesis is that the deployment is
    what matters.

    The operator supplies a request template with placeholders and JSON paths for
    reading the reply. The placeholders they use also *declare the target's
    capabilities*: a template that never references ``{{system}}`` cannot have a system
    prompt seeded into it, so probes that need one are skipped rather than run blind.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["http"] = "http"
    url: str = Field(description="Full URL of the chat endpoint.")
    method: Literal["POST", "PUT"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)

    api_key: SecretStr | None = None
    api_key_header: str = Field(
        default="Authorization", description="Header carrying the credential."
    )
    api_key_prefix: str = Field(
        default="Bearer ", description="Prefix before the key, e.g. 'Bearer '. May be empty."
    )

    request_template: dict[str, Any] = Field(
        description=(
            "JSON body to send. Placeholders are substituted anywhere they appear: "
            "{{prompt}} the latest user message, {{history}} the full exchange as a "
            "list of {role, content}, {{system}} the system prompt, {{documents}} the "
            "rendered retrieved context."
        ),
        examples=[{"question": "{{prompt}}", "session": "promptsentinel"}],
    )
    response_path: str = Field(
        description="Dotted path to the reply text, e.g. 'data.answer' or 'choices.0.text'.",
        examples=["data.answer"],
    )
    tools: list[ToolDefinition] = Field(
        default_factory=list,
        description=(
            "Tools your application exposes, each marked restricted or not. Needed "
            "alongside tool_calls_path for excessive-agency probes: one says what to "
            "offer, the other says where to read the answer."
        ),
    )
    tool_calls_path: str | None = Field(
        default=None, description="Dotted path to a list of tool calls, if the app returns them."
    )
    tool_name_field: str = "name"
    tool_arguments_field: str = "arguments"
    tool_call_filter: dict[str, str] | None = Field(
        default=None,
        description=(
            "Only treat entries matching these key/value pairs as tool calls. Needed "
            "when tool calls share a list with other content, as in Anthropic's "
            "messages API, where tool_use blocks sit alongside text blocks in the same "
            "'content' array."
        ),
        examples=[{"type": "tool_use"}],
    )

    document_template: str = Field(
        default="[{index}] {title} ({source})\n{content}",
        description="How each retrieved document renders into {{documents}}.",
    )
    system_prompt: str | None = Field(
        default=None, description="The application's own system prompt, if you have it."
    )
    timeout_s: float = Field(default=30.0, gt=0, le=300)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("url must be an http:// or https:// URL")
        return normalized

    @field_validator("request_template")
    @classmethod
    def _must_send_the_prompt(cls, value: dict[str, Any]) -> dict[str, Any]:
        """A template that never sends the prompt cannot test anything.

        Caught here rather than surfacing as a scan where every probe mysteriously
        finds nothing.
        """
        if "{{prompt}}" not in json.dumps(value) and "{{history}}" not in json.dumps(value):
            raise ValueError(
                "request_template must reference {{prompt}} or {{history}}, "
                "or the target never receives the probe's message"
            )
        return value


class RetrievalConfig(BaseModel):
    """How an application renders retrieved context into its prompt.

    Probes plant document *content*; this says how that content reaches the model, so
    the injected text sits exactly where the application's own retriever would put it.
    Testing an injection in the wrong position tests the wrong application.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["system", "user"] = Field(
        default="user", description="Message role carrying retrieved context."
    )
    document_template: str = Field(
        default="[{index}] {title} (source: {source})\n{content}",
        description="Per-document rendering. Placeholders: index, title, source, content.",
    )
    context_template: str = Field(
        default="Retrieved context:\n\n{documents}\n\nUse the context above to answer.",
        description="Wrapper around the rendered documents. Placeholder: documents.",
    )


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
    reveal_system_lines: str | None = Field(
        default=None,
        description=(
            "Regex selecting lines of the system message to append to the response. "
            "Lets a mock disclose one seeded record while withholding another, which "
            "is what simulates a working -- or broken -- access control."
        ),
    )


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
            "Regex that makes the mock disclose its system prompt -- used to simulate "
            "a vulnerable application."
        ),
    )
    retrieval: RetrievalConfig | None = Field(
        default=None, description="Present to make the mock behave as a RAG target."
    )
    tools: list[ToolDefinition] = Field(default_factory=list)
    document_tool_pattern: str | None = Field(
        default=None,
        description=(
            "Regex over retrieved document text with groups (tool, reference); a match "
            "makes the mock emit that tool call. Simulates an agent taking orders from "
            "its own retrieval context."
        ),
    )
    document_emit_pattern: str | None = Field(
        default=None,
        description=(
            "Regex applied to retrieved document text; every match is emitted in the "
            "reply. Simulates a model acting on document content -- correctly when the "
            "pattern selects the document's own data, as a vulnerability when it "
            "selects an injected directive."
        ),
    )
    document_emit_template: str | None = Field(
        default=None,
        description=(
            "Wrap each document_emit_pattern match, e.g. "
            "'![](https://host/p?ref={})'. Simulates a model that does not merely quote "
            "retrieved data but builds something out of it."
        ),
    )
    quote_documents: bool = Field(
        default=False,
        description="Reply with the retrieved documents verbatim, as a summariser would.",
    )
    leak_after_turns: int | None = Field(
        default=None,
        ge=1,
        description=(
            "Disclose the system prompt once this many turns have been sent. Simulates "
            "a target that refuses at first and gives way as context accumulates, "
            "which is the behaviour multi-turn probes exist to find."
        ),
    )
    leak_encoding: Literal["base64", "reversed"] | None = Field(
        default=None,
        description=(
            "Transform applied to the disclosed prompt. Simulates an application whose "
            "output filter is bypassed by asking for an encoded copy."
        ),
    )


TargetSpec = Annotated[
    OpenAICompatibleTargetSpec | HttpTargetSpec | MockTargetSpec,
    Field(discriminator="kind"),
]
"""The union accepted by the API. New target kinds are added here."""


def serialize_with_secrets(spec: TargetSpec) -> str:
    """Serialize a spec with its credentials intact, for the secret store.

    ``model_dump_json`` deliberately redacts ``SecretStr``, which is what protects the
    database and every report. This is the one place that must not redact, so it walks
    the dumped structure and reveals secrets explicitly rather than turning redaction
    off globally. Any ``SecretStr`` added to any spec in future is handled without a
    change here -- and, importantly, without being silently dropped.
    """
    return json.dumps(_reveal(spec.model_dump(mode="python")))


def deserialize_spec(raw: str) -> TargetSpec:
    """Rebuild a spec from :func:`serialize_with_secrets`, validating as it goes."""
    return _SPEC_ADAPTER.validate_python(json.loads(raw))


def _reveal(value: object) -> object:
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, dict):
        return {key: _reveal(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_reveal(item) for item in value]
    return value


_SPEC_ADAPTER: TypeAdapter[TargetSpec] = TypeAdapter(TargetSpec)


def parse_spec(data: object) -> TargetSpec:
    """Validate raw data as any supported target kind.

    Callers must go through this rather than picking a spec class by hand. An earlier
    version of the CLI dispatched on ``kind`` itself, fell through to the
    OpenAI-compatible class for anything it did not recognise, and so could not load an
    ``http`` target at all -- a whole adapter unreachable from the command line because
    one function had not been told it existed. Routing through the discriminated union
    means a new target kind works everywhere the moment it joins :data:`TargetSpec`.
    """
    return _SPEC_ADAPTER.validate_python(data)
