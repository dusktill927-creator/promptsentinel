"""Measurement for the heuristic tier, over a corpus of real model output.

The project's claim about its `suspicious` tier is that it was *measured*, not
intuited. That claim used to live in a number typed into a document by hand, derived
once and impossible to re-derive -- so a change that halved recall would not have
failed anything.

This turns it into something that can be recomputed. `python -m tests.corpus` prints
the table; `tests/unit/test_heuristic_measurement.py` asserts floors against it.

Every string in ``tests/fixtures/heuristic_corpus.json`` was produced by a model, not
invented. That is the point: patterns written from intuition and then tested against
examples from the same intuition will always agree with each other.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from promptsentinel.core.heuristics import disclosure_signals, is_deflection, is_refusal

CORPUS_PATH = Path(__file__).parent / "fixtures" / "heuristic_corpus.json"


@dataclass(frozen=True)
class Response:
    """One recorded response, its human labels, and the signals it is known to fire.

    ``signals`` exists because detector-level recall cannot see a single pattern
    breaking. The Qwen leak ``Internal configuration: support_api_key=...`` fires both
    ``emits_credential_label`` and ``names_internal_configuration``, so reintroducing
    the historical ``\\b`` anchor defect left aggregate recall unchanged at 5 of 7 --
    the second signal covered for the first. Pinning signals by name closes that gap.
    """

    text: str
    labels: frozenset[str]
    model: str | None = None
    known_miss: bool = False
    note: str | None = None
    signals: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class Score:
    """Confusion counts for one detector, and the rates derived from them."""

    label: str
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int

    @property
    def positives(self) -> int:
        return self.true_positive + self.false_negative

    @property
    def precision(self) -> float:
        """Of what fired, how much was real. 1.0 when nothing fired: it made no claims."""
        fired = self.true_positive + self.false_positive
        return 1.0 if fired == 0 else self.true_positive / fired

    @property
    def recall(self) -> float:
        """Of what was real, how much fired. 1.0 when there is nothing to find."""
        return 1.0 if self.positives == 0 else self.true_positive / self.positives


DETECTORS: dict[str, Callable[[str], bool]] = {
    "refusal": is_refusal,
    "disclosure": lambda text: bool(disclosure_signals(text)),
    "deflection": is_deflection,
}


def load_corpus(path: Path = CORPUS_PATH) -> list[Response]:
    raw = json.loads(path.read_text())["responses"]
    return [
        Response(
            text=r["text"],
            labels=frozenset(r["labels"]),
            model=r.get("model"),
            known_miss=r.get("known_miss", False),
            note=r.get("note"),
            signals={k: tuple(v) for k, v in r.get("signals", {}).items()},
        )
        for r in raw
    ]


def score(label: str, corpus: Sequence[Response]) -> Score:
    """Confusion counts for one detector across the whole corpus.

    Every response is a negative for every label it does not carry, so a refusal that
    trips the disclosure detector is counted as a false positive there. That is the
    interesting failure: the two mistakes this tier can make are calling a refusal a
    leak, and missing a leak entirely.
    """
    detect = DETECTORS[label]
    tp = fp = fn = tn = 0
    for response in corpus:
        expected = label in response.labels
        fired = detect(response.text)
        if expected and fired:
            tp += 1
        elif expected:
            fn += 1
        elif fired:
            fp += 1
        else:
            tn += 1
    return Score(
        label=label, true_positive=tp, false_positive=fp, false_negative=fn, true_negative=tn
    )


def score_all(corpus: Sequence[Response] | None = None) -> dict[str, Score]:
    resolved = load_corpus() if corpus is None else corpus
    return {label: score(label, resolved) for label in DETECTORS}


def report(corpus: Sequence[Response] | None = None) -> str:
    resolved = load_corpus() if corpus is None else corpus
    scores = score_all(resolved)
    models = sorted({r.model for r in resolved if r.model})

    lines = [
        f"Heuristic detectors over {len(resolved)} recorded responses.",
        f"Attributed to: {', '.join(models)} (the rest are unattributed).",
        "",
        f"{'detector':<12} {'precision':>10} {'recall':>8} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}",
        "-" * 52,
    ]
    for label, s in scores.items():
        lines.append(
            f"{label:<12} {s.precision:>10.2f} {s.recall:>8.2f} "
            f"{s.true_positive:>4} {s.false_positive:>4} {s.false_negative:>4} {s.true_negative:>4}"
        )

    misses = [r for r in resolved if r.known_miss]
    if misses:
        lines += ["", f"{len(misses)} known misses, counted against recall above:"]
        lines += [f"  - {r.text[:66]}" for r in misses]
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
