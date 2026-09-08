#!/usr/bin/env python
"""Where the false positives come from, and why the benign corpus is built this way.

    python examples/false_positive_demo.py

A guardrail's false-positive rate is usually quoted against benign traffic that
looks nothing like an attack, which makes it a formality: every detector passes
that test, and none of the complaints about guardrails in production are about
that test.

This scores each *kind* of benign traffic separately, at a threshold calibrated
to a 1% budget, and prints the rate per kind. The four kinds marked `hard` were
written to be difficult on purpose, and the one that matters most is
`security_docs`: a threat model quoting a payload is lexically the payload, and
the only thing that distinguishes it is the sentence around it.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pifw.corpus import benign
from pifw.corpus.build import PLANS, generate
from pifw.detect.ensemble import Detector, threshold_at_fpr
from pifw.evaluate.metrics import flag_rate_by_group
from pifw.model.logistic import TrainConfig, train

TARGET_FPR = 0.01


def heading(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}")


def main() -> int:
    plan = replace(PLANS["main"], name="fp-demo", attacks_per_family=90, benign_total=1200)
    corpus = generate(plan).corpus
    holdout = generate(
        replace(PLANS["holdout"], name="fp-holdout", attacks_per_family=60, benign_total=900),
        exclude=frozenset(record.text for record in corpus),
    ).corpus

    probe = Detector(model=None)
    model = train(
        [probe.inspect(record.text).normalized.text for record in corpus.records],
        [1 if record.is_attack else 0 for record in corpus.records],
        families=corpus.families,
        config=TrainConfig(max_iterations=3000),
    )
    detector = Detector(model=model)

    # Calibrate on one half of the held-out benign traffic and measure on the
    # other. Calibrating and measuring on the same samples would report the
    # target budget back at us no matter what the detector did.
    benign_samples = holdout.benign
    calibration, measurement = benign_samples[0::2], benign_samples[1::2]
    threshold = threshold_at_fpr(
        detector.scores([record.text for record in calibration])["decision"], TARGET_FPR
    )

    scores = detector.scores([record.text for record in measurement])["decision"]
    by_kind = flag_rate_by_group(scores, [record.kind for record in measurement], threshold)

    heading(f"False positives by kind, at a {TARGET_FPR:.0%} budget")
    print(f"  threshold {threshold:.4f}, measured on {len(measurement)} held-out benign samples")
    print()
    print(f"  {'kind':<20} {'hard':>5} {'flagged':>9}  95% interval")
    for kind, interval in sorted(by_kind.items(), key=lambda item: -item[1].point):
        hard = "yes" if kind in benign.HARD_KINDS else ""
        print(
            f"  {kind:<20} {hard:>5} {interval.point:>8.2%}  "
            f"[{interval.low:.2%}, {interval.high:.2%}]  n={interval.total}"
        )

    flagged = int((scores >= threshold).sum())
    print()
    print(f"  overall {flagged}/{len(measurement)} = {flagged / len(measurement):.2%}")

    heading("What the overall number hides")
    worst = max(by_kind.items(), key=lambda item: item[1].point)
    print(f"  The worst kind is `{worst[0]}` at {worst[1].point:.2%}.")
    print()
    print("  An overall rate of one percent that is several times that on one")
    print("  kind of traffic is a firewall that works fine until the team whose")
    print("  documents it flags is the security team. That is the group most")
    print("  likely to have the authority to switch it off, and the group whose")
    print("  documents most reliably contain attack strings.")
    print()
    print("  Reporting per kind is not a courtesy. It is the only form of the")
    print("  number that predicts whether the thing survives contact with users.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
