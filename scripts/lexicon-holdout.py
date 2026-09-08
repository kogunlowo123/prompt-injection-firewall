#!/usr/bin/env python3
"""Does leave-one-family-out hold out the technique, or only the technique?

The twelve attack families deliberately share slot vocabularies -- the same
LEADS, SCOPES, PIVOTS, TASKS, PREAMBLES and CLOSERS -- so that they differ by
*technique* rather than by wording. That is the right call for isolating a
technique, and it introduces a specific way for the headline to be wrong.

A fold removes the held-out family from training. It does **not** remove the
family's vocabulary, because eleven other families are built from the same
words. So a bag of hashed n-grams could recognise a held-out family from the
frame around its payload, report 0% bypass, and have generalised to nothing.

This script measures that. Two arms at identical scale:

    SHARED      training and evaluation attacks drawn from the same slots
    DISJOINT    training attacks from half A of every slot, evaluation from B

Benign generation is untouched in both arms, deliberately. Halving the benign
vocabulary too would move the calibration threshold for a second reason, and a
comparison with two things changed is not a comparison.

Run it directly; it is not part of ``tasks.py all`` because it trains six models
and takes a few minutes:

    python scripts/lexicon-holdout.py

The result is discussed in ``docs/evaluation.md``. It is a limitation probe
rather than a gate: it is not wired into CI, because what it measures is a
property of the corpus design, and the corpus design changes on the day somebody
edits ``src/pifw/corpus/attacks.py`` and not on any other day.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pifw.corpus import attacks
from pifw.corpus.build import Generation, Plan, generate
from pifw.detect import heuristic, patterns
from pifw.detect.ensemble import Detector, threshold_at_fpr
from pifw.detect.normalize import stages_for_fold
from pifw.evaluate.metrics import wilson
from pifw.model.features import FeatureSpec, build_matrix
from pifw.model.logistic import TrainConfig, train_on
from pifw.sample import Corpus

#: Every slot the attack grammar draws from. Splitting all six shrinks the
#: reachable string space by roughly 2**6, which risks reintroducing the grammar
#: exhaustion this corpus was rebuilt to avoid -- so the collision rate is
#: printed on every run rather than assumed, and --narrow splits fewer.
SLOTS = ("LEADS", "SCOPES", "PIVOTS", "TASKS", "PREAMBLES", "CLOSERS")
NARROW = ("SCOPES", "TASKS")

#: The three families that went from a high bypass rate under the rejected
#: ensemble to zero under the learned layer alone. If the learned layer is
#: reading the shared frame rather than generalising, it shows here first.
FOLDS = ("homoglyph", "hypothetical", "indirect")

TARGET_FPR = 0.01

#: Smaller than the shipped plans: two arms, three folds, one model trained per
#: fold per arm. The comparison is arm against arm at matched scale, so the
#: absolute level matters far less than the difference between the columns.
TRAIN = Plan(name="lexicon-train", seed=20260908, attacks_per_family=120, benign_total=1800)
EVAL = Plan(name="lexicon-eval", seed=771103, attacks_per_family=60, benign_total=1800)

ORIGINAL = {name: getattr(attacks, name) for name in SLOTS}


def set_half(split: tuple[str, ...], half: int | None) -> None:
    """Restrict the named slots to one alternating half, or restore them all."""
    for name in SLOTS:
        full = ORIGINAL[name]
        setattr(attacks, name, full if half is None or name not in split else full[half::2])


def build(
    split: tuple[str, ...], half: int | None, plan: Plan, exclude: frozenset[str]
) -> Generation:
    """Generate a corpus with the attack lexicon restricted, then put it back."""
    set_half(split, half)
    try:
        return generate(plan, exclude=exclude)
    finally:
        set_half(split, None)


def bypass(train_corpus: Corpus, eval_corpus: Corpus, family: str) -> tuple[float, float, int]:
    """Bypass rate, realised false-positive rate and sample count for one fold."""
    stages = stages_for_fold(family)
    probe = Detector(model=None, disabled_stages=stages)
    normalised = [probe.inspect(record.text).normalized.text for record in train_corpus.records]
    matrix = build_matrix(normalised, FeatureSpec())
    labels = [1 if record.is_attack else 0 for record in train_corpus.records]
    keep = np.array(
        [i for i, record in enumerate(train_corpus.records) if record.family != family],
        dtype=np.int64,
    )
    model = train_on(
        matrix.select(keep),
        [labels[int(index)] for index in keep],
        families=[name for name in train_corpus.families if name != family],
        config=TrainConfig(max_iterations=4000),
    )
    if not model.converged:
        raise SystemExit(f"{family}: training hit the iteration ceiling; no number is reportable")

    detector = Detector(
        model=model,
        disabled_stages=stages,
        disabled_rules=patterns.rules_for_fold(family),
        disabled_signals=heuristic.signals_for_fold(family),
    )
    benign = eval_corpus.benign
    held_out = [record.text for record in eval_corpus.only_family(family)]
    attack_scores = detector.scores(held_out)["decision"]
    threshold = threshold_at_fpr(
        detector.scores([record.text for record in benign[0::2]])["decision"], TARGET_FPR
    )
    measurement = detector.scores([record.text for record in benign[1::2]])["decision"]
    return (
        float((attack_scores < threshold).mean()),
        float((measurement >= threshold).mean()),
        len(held_out),
    )


def arm(
    label: str, split: tuple[str, ...], train_half: int | None, eval_half: int | None
) -> dict[str, tuple[float, int]]:
    """Generate both corpora for one arm and measure every fold in it."""
    train_gen = build(split, train_half, TRAIN, frozenset())
    eval_gen = build(
        split, eval_half, EVAL, frozenset(record.text for record in train_gen.corpus.records)
    )
    print(f"\n{label}")
    print(
        f"  collisions: training {train_gen.collision_rate:.2%}, "
        f"evaluation {eval_gen.collision_rate:.2%}"
    )
    results: dict[str, tuple[float, int]] = {}
    for family in FOLDS:
        rate, fpr, count = bypass(train_gen.corpus, eval_gen.corpus, family)
        interval = wilson(round(rate * count), count)
        results[family] = (rate, count)
        print(
            f"  {family:<14} bypass {rate:>7.2%}  [{interval.low:.2%}, {interval.high:.2%}]  "
            f"n={count}  realised fpr {fpr:>6.2%}"
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--narrow",
        action="store_true",
        help="Split only SCOPES and TASKS, if splitting all six exhausts the grammar.",
    )
    args = parser.parse_args()
    split = NARROW if args.narrow else SLOTS

    print(f"splitting: {', '.join(split)}")
    shared = arm("SHARED -- the same lexicon on both sides", split, None, None)
    disjoint = arm("DISJOINT -- training half A, evaluation half B", split, 0, 1)

    print(f"\n{'family':<14}{'shared':>10}{'disjoint':>10}{'delta':>10}")
    for family in FOLDS:
        change = disjoint[family][0] - shared[family][0]
        print(f"{family:<14}{shared[family][0]:>10.2%}{disjoint[family][0]:>10.2%}{change:>+10.2%}")
    print(
        "\nA delta near zero means the learned layer is generalising across the\n"
        "technique rather than memorising the frame around it. It does not mean\n"
        "the corpus holds nothing else back: both arms share the grammar that\n"
        "assembles these slots, and no synthetic corpus can hold that out.\n"
        "See docs/evaluation.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
