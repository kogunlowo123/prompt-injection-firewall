"""The committed baseline, and the regression gate that reads it.

A single absolute budget cannot gate this project. The measured bypass rates run
from 0.00% on eleven families to 25.00% on ``encoding_wrapper``, and any ceiling
high enough to admit the second is far too high to notice the first getting
worse. Setting ``max_family_bypass = 1.0`` would make the gate pass whatever
happened, which is the failure mode the whole repository is about.

So the gate is a **comparison against a recorded measurement**. ``baseline.json``
holds what this firewall actually did, per family, on a specific corpus at a
specific budget. CI re-measures and fails when a family gets meaningfully worse.
Improvements pass silently and are re-recorded deliberately, by a human running
``--update-baseline`` and committing the diff, because a gate that re-records
itself is a gate that ratchets its own standard downwards one run at a time.

Two properties that are easy to leave out and matter:

* A family in the evaluation that the baseline has never heard of is a
  **failure**, not a pass. New attack families arrive with no recorded
  expectation, and defaulting that to "fine" means the one technique nobody has
  measured is the one technique nothing checks.
* The random-split control is gated too. The headline is a *difference* between
  two arms, and a control that quietly degraded would shrink the gap while
  looking like an improvement in the firewall.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pifw.errors import ConfigError, GateError
from pifw.evaluate.lofo import Evaluation

#: How much worse a family may get before the build goes red. Five points is
#: wide enough to absorb the sampling noise on a 140-attack fold — the 95%
#: interval on a rate near 10% is already about six points wide — and narrow
#: enough that a real regression cannot hide inside it.
DEFAULT_TOLERANCE = 0.05

#: The one genuinely absolute budget. False positives are the cost side of the
#: trade and they are under our control in a way bypass rates are not.
DEFAULT_MAX_FALSE_POSITIVE_RATE = 0.03

#: Two budgets are the same budget if they agree to this. They are written
#: into a JSON file and read back, so exact equality is a round-trip question
#: rather than a semantic one.
BUDGET_EPSILON = 1e-9

FORMAT_VERSION = 1


@dataclass(frozen=True, slots=True)
class Baseline:
    """What this firewall measured, recorded so a later run can be compared to it."""

    pooled_bypass: float
    control_bypass: float
    family_bypass: dict[str, float]
    target_fpr: float
    corpus_digest: str = ""
    eval_digest: str = ""

    @classmethod
    def from_evaluation(
        cls, evaluation: Evaluation, *, corpus_digest: str = "", eval_digest: str = ""
    ) -> Baseline:
        """Record an evaluation as the new expectation."""
        return cls(
            pooled_bypass=evaluation.pooled_bypass.point,
            control_bypass=evaluation.control.bypass.point,
            family_bypass={fold.family: fold.bypass.point for fold in evaluation.folds},
            target_fpr=evaluation.target_fpr,
            corpus_digest=corpus_digest,
            eval_digest=eval_digest,
        )

    def save(self, path: str | Path) -> Path:
        """Write the baseline as JSON, sorted so a diff is readable."""
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(
            json.dumps(
                {
                    "format": FORMAT_VERSION,
                    "pooled_bypass": self.pooled_bypass,
                    "control_bypass": self.control_bypass,
                    "family_bypass": dict(sorted(self.family_bypass.items())),
                    "target_false_positive_rate": self.target_fpr,
                    "corpus_digest": self.corpus_digest,
                    "eval_digest": self.eval_digest,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return file

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        """Read a committed baseline."""
        file = Path(path)
        if not file.exists():
            raise ConfigError(
                f"no baseline at {file}",
                remedy=(
                    "Record one with 'pifw evaluate ... --baseline <path> "
                    "--update-baseline' and commit it on its own."
                ),
            )
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{file} is not valid JSON: {exc}") from exc
        if data.get("format") != FORMAT_VERSION:
            raise ConfigError(
                f"{file} is format {data.get('format')!r}, this build reads {FORMAT_VERSION}",
                remedy="Re-record the baseline with --update-baseline.",
            )
        return cls(
            pooled_bypass=float(data["pooled_bypass"]),
            control_bypass=float(data["control_bypass"]),
            family_bypass={str(k): float(v) for k, v in data["family_bypass"].items()},
            target_fpr=float(data["target_false_positive_rate"]),
            corpus_digest=str(data.get("corpus_digest", "")),
            eval_digest=str(data.get("eval_digest", "")),
        )


def enforce(
    evaluation: Evaluation,
    baseline: Baseline,
    *,
    tolerance: float = DEFAULT_TOLERANCE,
    max_false_positive_rate: float = DEFAULT_MAX_FALSE_POSITIVE_RATE,
) -> list[str]:
    """Compare a fresh evaluation to the baseline. Raise on a regression.

    Returns the list of *improvements* when it passes, so the run says what got
    better rather than only printing that nothing got worse. An improvement is
    not a failure, but it is a reason to re-record the baseline, and a gate that
    never mentions them lets the recorded numbers drift years out of date.
    """
    if abs(evaluation.target_fpr - baseline.target_fpr) > BUDGET_EPSILON:
        raise GateError(
            f"this run used a {evaluation.target_fpr:.2%} false-positive budget and the "
            f"baseline was recorded at {baseline.target_fpr:.2%}",
            remedy=(
                "Bypass rates at different budgets are not comparable. Re-run at the "
                "recorded budget, or re-record the baseline at the new one."
            ),
        )

    failures: list[str] = []
    improvements: list[str] = []

    if evaluation.pooled_bypass.point > baseline.pooled_bypass + tolerance:
        failures.append(
            f"pooled bypass rate rose from {baseline.pooled_bypass:.2%} to "
            f"{evaluation.pooled_bypass.point:.2%}"
        )
    elif evaluation.pooled_bypass.point < baseline.pooled_bypass - tolerance:
        improvements.append(
            f"pooled bypass rate fell from {baseline.pooled_bypass:.2%} to "
            f"{evaluation.pooled_bypass.point:.2%}"
        )

    if evaluation.control.bypass.point > baseline.control_bypass + tolerance:
        failures.append(
            f"the random-split control regressed from {baseline.control_bypass:.2%} to "
            f"{evaluation.control.bypass.point:.2%}; the headline is a difference "
            "between the two arms, so a worse control shrinks the gap without the "
            "firewall having improved"
        )

    for fold in evaluation.folds:
        recorded = baseline.family_bypass.get(fold.family)
        if recorded is None:
            failures.append(
                f"family {fold.family!r} is not in the baseline, so there is nothing to "
                f"compare its {fold.bypass.point:.2%} against"
            )
            continue
        if fold.bypass.point > recorded + tolerance:
            failures.append(
                f"family {fold.family!r} regressed from {recorded:.2%} to {fold.bypass.point:.2%}"
            )
        elif fold.bypass.point < recorded - tolerance:
            improvements.append(
                f"family {fold.family!r} improved from {recorded:.2%} to {fold.bypass.point:.2%}"
            )

    missing = sorted(set(baseline.family_bypass) - {fold.family for fold in evaluation.folds})
    if missing:
        failures.append(
            f"the baseline records {', '.join(missing)} but this run did not measure "
            "them; a fold that stops running is a gate that stops gating"
        )

    worst_fpr = max(
        (fold.confusion.false_positive_rate.point for fold in evaluation.folds), default=0.0
    )
    if worst_fpr > max_false_positive_rate:
        failures.append(
            f"false-positive rate {worst_fpr:.2%} exceeds the {max_false_positive_rate:.2%} budget"
        )

    if failures:
        raise GateError(
            "; ".join(failures),
            remedy=(
                "Either the detection stack regressed, or the baseline is out of date. "
                "Re-record with --update-baseline only after saying in CHANGELOG.md what "
                "changed and why the new numbers are the right ones."
            ),
        )
    return improvements
