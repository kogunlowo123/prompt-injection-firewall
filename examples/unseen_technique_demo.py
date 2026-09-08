#!/usr/bin/env python
"""The argument of this repository, in one runnable script.

    python examples/unseen_technique_demo.py

Same corpus, same detector, same false-positive budget. The only thing that
changes is **how the evaluation set was chosen**, and the answer moves by tens
of points.

Split at random and every attack in the test set is a rewording of something the
detector was built against. Split by technique - and switch off the
countermeasures that technique motivated - and you are measuring what happens
the first time something genuinely new arrives.

Two caveats about the numbers this prints, both of which make them *worse* than
the repository's headline rather than better:

* It runs three folds, not twelve, on a corpus a third the size, so it finishes
  in under a minute. The three are named in the source and were chosen to span
  the range rather than picked after seeing the results — but one of them is the
  worst fold in the project, so the pooled figure here is well above the
  twelve-fold pooled figure in the README.
* The README's numbers come from `pifw evaluate` on the full corpus. This script
  is the argument, not the measurement.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pifw.corpus.build import PLANS, generate
from pifw.evaluate import lofo
from pifw.model.logistic import TrainConfig

#: Three folds rather than twelve, chosen to span the range: one the firewall
#: handles well, one it handles badly, one in between. Naming them here rather
#: than picking the best three afterwards.
FOLDS = ("direct_override", "indirect", "encoding_wrapper")


def heading(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}")


def main() -> int:
    small = replace(PLANS["main"], name="demo", attacks_per_family=90, benign_total=1000)
    holdout = replace(
        PLANS["holdout"], name="demo-holdout", attacks_per_family=60, benign_total=700
    )
    train_corpus = generate(small).corpus
    eval_corpus = generate(holdout, exclude=frozenset(r.text for r in train_corpus)).corpus

    print(f"training on {len(train_corpus)} samples, evaluating on {len(eval_corpus)}")
    print("the two corpora share no text: the holdout is generated with the")
    print("training corpus excluded, so disjointness is a property of how it was")
    print("built rather than something checked afterwards and hoped for.")

    evaluation = lofo.run(
        train_corpus,
        eval_corpus,
        families=FOLDS,
        config=TrainConfig(max_iterations=3000),
        progress=lambda message: print(f"  ... {message}", file=sys.stderr),
    )

    heading("The same firewall, measured two ways")
    pooled = evaluation.pooled_bypass
    control = evaluation.control.bypass
    print(f"  unseen technique (leave-one-family-out)  {pooled.point:>7.2%}")
    print(f"      95% interval                         [{pooled.low:.2%}, {pooled.high:.2%}]")
    print(f"  seen technique   (random split)          {control.point:>7.2%}")
    print(f"      95% interval                         [{control.low:.2%}, {control.high:.2%}]")
    print()
    print(f"  the gap                                  {evaluation.optimism_gap:>+7.2%}")

    heading("Per fold, and what each fold switched off")
    print(f"  {'family':<20} {'bypass':>8} {'auc':>7}  countermeasures removed")
    for fold in sorted(evaluation.folds, key=lambda item: item.bypass.point, reverse=True):
        removed = list(fold.disabled_rules) + list(fold.disabled_stages)
        print(
            f"  {fold.family:<20} {fold.bypass.point:>7.2%} {fold.auc:>7.3f}  "
            f"{', '.join(removed) if removed else 'none'}"
        )

    heading("Read the AUC column next to the bypass column")
    worst = evaluation.worst_fold
    print(f"  {worst.family} has an AUC of {worst.auc:.3f} and still lets")
    print(f"  {worst.bypass.point:.0%} of attacks through.")
    print()
    print("  Those are not in tension. AUC says the scores order attacks above")
    print("  benign traffic; the bypass rate says where the threshold had to go to")
    print("  keep the false-positive budget. A detector can rank well and still")
    print("  place every attack below the line that 1% of benign traffic already")
    print("  crosses. The bypass rate is the number a deployment lives with.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
