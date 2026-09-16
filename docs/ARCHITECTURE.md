# Architecture

This document explains *why* the code is shaped the way it is. If you only read one
section, read [The confidence invariant](#the-confidence-invariant).

## Layering

```
api/      HTTP contract, dependency injection, error mapping
jobs/     job queue, worker, webhooks
engine/   orchestration: authorization, concurrency, timeouts, isolation
probes/   one class per attack technique
targets/  adapters for the systems under test
core/     domain models, canaries, heuristics, errors
```

Dependencies point strictly downward. `core/` imports nothing from the layers above
it. That is not aesthetic — it is what lets a probe be unit-tested with no database, no
event loop configuration, and no HTTP client:

```python
result = await CanaryEchoProbe().run(MockTarget(spec), ProbeContext(scan_id="s1"))
```

If a probe needed a `Session` or a `Request` to run, that test would need a fixture
stack, and probes would get written more slowly and tested less.

## Four model types, on purpose

| Layer | Module | Type |
|---|---|---|
| Wire | `api/schemas.py` | Pydantic |
| Domain | `core/models.py` | Frozen Pydantic |
| Persistence | `db/models.py` | SQLAlchemy ORM |
| Config | `targets/spec.py`, `config.py` | Pydantic |

The obvious objection is duplication: `Finding` and `FindingOut` have most of the same
fields. The reason to accept it:

- **The wire format is a promise to clients.** Renaming a database column should never
  break someone's CI integration. With one shared class, it always does.
- **The domain holds invariants the other layers must not weaken.** `Finding` refuses
  to exist in an invalid state. An ORM row cannot do that — SQLAlchemy has to be able
  to hydrate whatever is in the table, including rows written by an older version.
- **Serialization differs by destination.** A `SecretStr` must be redacted going to the
  database and to the API, but must be *live* going to the target. One class cannot
  have three serializers without conditional logic, which is where leaks come from.

Translation happens in exactly two places: `db/repository.py` (domain ↔ rows) and the
`from_row` constructors in `api/schemas.py` (rows → wire). Both are boring, explicit,
and easy to review — which is the point.

## The confidence invariant

The product claim is that `confirmed` means *proven*. Enforcing that with a code review
convention would not survive the tenth probe. So it is enforced by the type:

```python
class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    confidence: Confidence
    proof: Proof | None = None

    @model_validator(mode="after")
    def _check_confidence_invariant(self):
        if self.confidence is Confidence.CONFIRMED and self.proof is None:
            raise ValueError("a CONFIRMED finding requires proof")
        if self.confidence is not Confidence.CONFIRMED and self.proof is not None:
            raise ValueError("proof implies CONFIRMED")
        return self
```

Four defenses, because each one alone has a hole:

1. **The validator** rejects `CONFIRMED` without proof, and proof without `CONFIRMED`
   (so a probe cannot hedge by attaching proof to a suspicious finding).
2. **`frozen=True`** stops `finding.confidence = CONFIRMED` after construction.
3. **`model_copy` is overridden to re-validate.** Pydantic's `model_copy` skips
   validators by design; without the override,
   `finding.model_copy(update={"confidence": "confirmed"})` would be a silent upgrade —
   precisely the thing the class exists to prevent.
4. **Constructors encode intent.** `Finding.confirmed()` requires a `proof` argument.
   `Finding.suspicious()` has no `proof` parameter at all, so passing one is a
   `TypeError`.

### Proof vs. evidence

A distinction worth internalizing:

- **Evidence** is *what happened*: the prompt sent and the response received. Recorded
  for every finding at every tier.
- **Proof** is *a check that succeeded*: this exact 128-bit canary appeared in that
  response. Only proof unlocks `confirmed`.

`ProofKind` is a closed enum. A probe may not invent an ad-hoc proof reason — if a
claim isn't enumerable and mechanically checkable, it's `suspicious`.

### Why canaries

`core/canary.py` contains no scoring, no pattern matching against natural language, and
no thresholds. It mints 128-bit tokens and looks for exact matches. Heuristics live in
`core/heuristics.py`, which imports nothing from `canary.py`. Keeping them in separate
modules with no shared imports means no future refactor can accidentally let a fuzzy
score feed a `Proof`.

Detection normalizes away non-alphanumerics before matching, so a canary split across
lines or wrapped in backticks is still caught. With 128 bits of entropy, that
normalization cannot create a false positive.

## The authorization gate

Three independent enforcement points, because this is the one control that separates
the tool from a weapon:

1. **HTTP** — `POST /v1/scans` calls `require_authorization()` before it validates the
   target, resolves probes, or writes anything. An unauthorized request leaves no trace.
2. **The type system** — `ScanEngine.run()` takes an `Authorization`, and
   `Authorization` cannot be constructed in an invalid state ("parse, don't validate").
   An unauthorized scan is not something the engine can be *asked* to perform; it is
   unrepresentable as an argument.
3. **Runtime** — the engine calls `authorization.verify()` before the first probe,
   catching bypasses via `model_construct`, `pickle`, or a hand-edited database row.
   `tests/integration/test_worker_failure_paths.py` flips the column in SQL and asserts
   the scan refuses to run.

The attestation requires an exact sentence, not a boolean. A boolean is too easy to set
by accident — a client-library default, a copy-pasted script, a pre-ticked checkbox.
Requiring a specific sentence means a human typed it deliberately, and the stored
attestation is a real audit record naming who took responsibility.

## Plugin architecture

A probe is one class with one method. Registration is an explicit `@register`
decorator rather than `__init_subclass__` auto-registration. The trade:

- **Auto-registration** means a probe is registered by existing. It also means every
  abstract intermediate and every test double lands in the production registry.
- **Explicit registration** costs one line, and keeps `tests/` from polluting what ships.

Discovery has two paths, neither of which touches the engine:

- Any module under `probes/builtin/` is imported by `ProbeRegistry.discover()`.
- Third-party packages advertise the `promptsentinel.probes` entry-point group, so an
  organization can ship an internal probe pack for their own stack without forking.

`Probe.required_capabilities` plus `Target.capabilities` decide applicability. A probe
whose requirements a target doesn't meet is reported `SKIPPED` **with a reason** — never
silently omitted. An indirect-injection probe run against a target with no retrieval
pipeline would otherwise produce a clean bill of health it never earned.

## Async job model

`POST /v1/scans` returns `202` with a job ID. Scanning an LLM app means dozens of
round-trips to a slow endpoint; a synchronous API would be a timeout generator, and
retries would re-run attacks against production.

V1 uses `InProcessJobQueue` — asyncio tasks in the API process. It is honest about what
it is: **queued scans are lost on restart.** The `JobQueue` protocol exists so ARQ,
Celery or a Redis-backed worker drops in later without the API layer changing, because
the expensive part to retrofit is the *contract* (202 + polling + webhooks), not the
executor.

Two details worth copying:

- Tasks are held in a `set` with a `done_callback` to discard them. `asyncio` keeps only
  weak references to tasks; an unreferenced task can be garbage collected mid-run.
- The worker opens its **own** database session. Borrowing the request's session would
  fail, because the request is long gone by the time the scan finishes.

### Why credentials travel in memory

`InProcessJobQueue.enqueue()` takes the live `TargetSpec` rather than re-reading it from
the database, because the persisted copy is redacted. That means **no API key is ever
written to disk**, at the cost of the queue being in-process only. A distributed queue
would need a real secrets backend — a deliberate trade, recorded here rather than
discovered later.

## Failure honesty

The recurring theme across the engine, worker and report:

| Situation | What is reported |
|---|---|
| Probe ran, found nothing | `COMPLETED`, no findings |
| Probe crashed | `ERRORED` with the message |
| Probe exceeded its budget | `TIMED_OUT` |
| Target unreachable | `ERRORED` — never a clean pass |
| Probe not applicable | `SKIPPED` with a reason |
| Scan could not run | Scan `FAILED`, zero findings, error recorded |

`ScanSummary` puts `probes_errored` and `probes_skipped` next to the finding counts, so
"0 confirmed findings" is never readable without also seeing that three probes crashed.
A summary that hides that is a lie by omission, and a security tool that lies is worse
than no tool.

## Database notes

- **Enums stored as strings, not native DB enums.** Adding a probe category should not
  require a migration with a table lock on Postgres. The `StrEnum` is the source of
  truth; the column is text.
- **String UUID primary keys.** Portable across SQLite and Postgres, safe in URLs, and
  no auto-increment counter leaking how many scans have run.
- **SQLite foreign keys are enabled per connection** via a `PRAGMA` on connect. SQLite
  ignores `ON DELETE CASCADE` unless asked, so without this the cascade silently does
  nothing locally and works in production — the worst kind of environment difference.
- **Two paths to a schema, kept identical by a test.** Development creates tables from
  the ORM models; production runs `alembic upgrade head` with `auto_create_schema`
  false. `tests/integration/test_schema_migrations.py` runs every migration against an
  empty database and diffs the result against `Base.metadata`, so the two cannot drift.
  Migrations also use `render_as_batch` on SQLite, because SQLite cannot `ALTER` most
  things in place and a column change would otherwise work on Postgres and fail locally.

## Testing notes

One non-obvious thing, recorded because it cost time to diagnose:

**SQLAlchemy's asyncio support runs sync DB code inside greenlets, and coverage.py
loses its tracer across greenlet switches.** Every line following an
`await session.execute(...)` was reported as unexecuted — including lines that
demonstrably ran in passing tests. The fix is in `pyproject.toml`:

```toml
[tool.coverage.run]
concurrency = ["thread", "greenlet"]
```

Without it, coverage on this codebase under-reports by roughly seven points and points
at the wrong lines. Worth knowing before trusting a coverage number on any async
SQLAlchemy project.
