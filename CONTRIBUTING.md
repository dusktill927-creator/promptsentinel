# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Four gates, all run in CI and all expected to pass before a commit lands:

```bash
pytest --cov --cov-fail-under=90
ruff check . && ruff format --check .
mypy
```

Optional backends are skipped unless you point them at a service:

```bash
pip install -e ".[dev,postgres,redis]"
PROMPTSENTINEL_TEST_POSTGRES_URL=postgresql+asyncpg://postgres@localhost:5432/postgres pytest tests/integration/test_postgres.py
PROMPTSENTINEL_TEST_REDIS_URL=redis://localhost:6379 pytest tests/integration/test_redis_backend.py
```

## Adding a probe

Drop a file in `src/promptsentinel/probes/builtin/`. It is discovered automatically —
there is no registration list and no engine change. Read
[`builtin/diagnostic.py`](src/promptsentinel/probes/builtin/diagnostic.py) first; it is
the annotated reference implementation.

Out-of-tree probe packs register through the `promptsentinel.probes` entry-point group.

## The rules a probe must follow

These are the project's reason for existing. A change that weakens one needs a much
better argument than "the tests still pass".

**`CONFIRMED` requires machine-verifiable proof.** A seeded canary returned, or a
restricted tool actually invoked. Not a response that *reads* like a leak. The type
system enforces this — `Finding.suspicious()` has no `proof` parameter — but the
judgement about what counts as proof is yours.

**Prefer to under-claim.** Existing probes deliberately refuse `CONFIRMED` in cases
where the evidence is strong but explicable: a verbatim echo of the operator's system
prompt (which may be boilerplate the model knows), a customer's *name* without their
identifier (low entropy), an injected payload surrounded by the instruction's own
wording (quotation, not obedience). Each of those is a `SUSPICIOUS` signal on purpose.

**Distinguish "did not run" from "found nothing".** Return `ProbeResult.skipped()` with
a reason when a capability is missing, let target errors propagate so the engine can
mark the probe `ERRORED`, and add a control step if a clean result would otherwise be
indistinguishable from the target ignoring you. See `data_leakage` and
`indirect_injection` for the pattern.

**Ask plainly before you attack.** Where it applies, a baseline request separates "the
control was defeated" from "there was no control" — different findings with different
fixes. See `jailbreak`.

**Stop once you have proof.** Further attempts against someone's production application
establish nothing new.

## Tests

Every probe family has three cases at minimum: a proven finding, a
plausible-but-unproven one, and a clean refusal. Copy the shape from
[`tests/unit/test_diagnostic_probe.py`](tests/unit/test_diagnostic_probe.py).

Test names should state the property, not the mechanism —
`test_a_suspicious_high_is_not_an_error` rather than `test_sarif_level_2`.

## Commits

One change per commit, with a message that explains *why*. The existing history is the
style guide: several commits describe a wrong first attempt and why it failed, which is
usually the most useful thing in them.

## Scope

PromptSentinel tests applications you own or are authorized to test. Contributions that
add target discovery, autonomous scanning, or any way around the authorization gate will
be declined regardless of quality. See [SECURITY.md](SECURITY.md).
