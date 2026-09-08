"""Counting, and saying honestly how much the count is worth.

The headline number of this project is a **bypass rate**: the share of attacks
that scored below the threshold and would have reached the model. It is the same
arithmetic as recall, pointed the other way, and the direction is the point. A
detector advertised at "96% recall" and one advertised at "4% of attacks get
through" are the same detector, and only one of those sentences makes a reader
ask whether 4% is acceptable for their application.

Every rate here is reported with a **Wilson score interval**. A fold has 140
attacks in it, and 0 out of 140 is not "0%" — it is zero with a 95% upper bound
of 2.6%. Publishing the point estimate alone from a sample that size is the most
common way a security evaluation overstates itself, and the interval costs four
lines of arithmetic.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

#: 1.96 is the two-sided 95% normal quantile. Hard-coded rather than
#: parameterised: every interval in this project is a 95% one, and a confidence
#: level that varies between tables is a confidence level nobody can compare.
Z = 1.959963984540054


@dataclass(frozen=True, slots=True)
class Interval:
    """A Wilson score interval, and the point estimate it surrounds."""

    point: float
    low: float
    high: float
    total: int

    def __str__(self) -> str:
        return f"{self.point:.2%} [{self.low:.2%}, {self.high:.2%}] n={self.total}"


def wilson(successes: int, total: int) -> Interval:
    """A 95% Wilson score interval for a binomial proportion.

    Wilson rather than the normal approximation because the normal one is wrong
    exactly where this project needs it to be right: at zero and at one, on
    samples of a hundred-odd, which is every fold.
    """
    if total <= 0:
        return Interval(point=0.0, low=0.0, high=1.0, total=0)
    if successes < 0 or successes > total:
        raise ValueError(f"{successes} successes out of {total} is not a proportion")
    proportion = successes / total
    denominator = 1.0 + Z * Z / total
    centre = (proportion + Z * Z / (2 * total)) / denominator
    spread = (
        Z
        * math.sqrt(proportion * (1 - proportion) / total + Z * Z / (4 * total * total))
        / denominator
    )
    # At the endpoints the bound is exactly 0 or exactly 1, and the arithmetic
    # above leaves a few ulps of residue there (3.5e-18 rather than 0). Snapped
    # rather than tolerated: an interval printed as "0.00% [0.00%, 3.70%]" whose
    # lower bound is not actually zero invites a reader to wonder what else in
    # the table is approximate.
    low = 0.0 if successes == 0 else max(0.0, centre - spread)
    high = 1.0 if successes == total else min(1.0, centre + spread)
    return Interval(point=proportion, low=low, high=high, total=total)


@dataclass(frozen=True, slots=True)
class Confusion:
    """The four counts, and the rates worth deriving from them."""

    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def attacks(self) -> int:
        """How many attack samples were scored."""
        return self.true_positive + self.false_negative

    @property
    def benign(self) -> int:
        """How many benign samples were scored."""
        return self.true_negative + self.false_positive

    @property
    def recall(self) -> Interval:
        """The share of attacks caught."""
        return wilson(self.true_positive, self.attacks)

    @property
    def bypass(self) -> Interval:
        """The share of attacks that got through. The headline."""
        return wilson(self.false_negative, self.attacks)

    @property
    def false_positive_rate(self) -> Interval:
        """The share of benign traffic flagged. The cost of the headline."""
        return wilson(self.false_positive, self.benign)

    @property
    def precision(self) -> float:
        """Of everything flagged, the share that was an attack."""
        flagged = self.true_positive + self.false_positive
        return self.true_positive / flagged if flagged else 0.0

    def to_dict(self) -> dict[str, object]:
        """As JSON, intervals included."""
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "bypass_rate": self.bypass.point,
            "bypass_ci": [self.bypass.low, self.bypass.high],
            "false_positive_rate": self.false_positive_rate.point,
            "false_positive_ci": [
                self.false_positive_rate.low,
                self.false_positive_rate.high,
            ],
            "precision": self.precision,
        }


def confusion(attack_scores: np.ndarray, benign_scores: np.ndarray, threshold: float) -> Confusion:
    """The four counts at a threshold.

    ``>=`` is the flagging comparison, matching :meth:`Detector.decide`. The two
    have to agree: a metric computed with ``>`` while the deployed path uses
    ``>=`` differs by exactly the samples sitting on the boundary, which for a
    threshold calibrated *to* a boundary is not a rounding error.
    """
    caught = int(np.count_nonzero(attack_scores >= threshold))
    flagged_benign = int(np.count_nonzero(benign_scores >= threshold))
    return Confusion(
        true_positive=caught,
        false_negative=int(attack_scores.size) - caught,
        false_positive=flagged_benign,
        true_negative=int(benign_scores.size) - flagged_benign,
    )


def bypass_by_group(scores: np.ndarray, groups: list[str], threshold: float) -> dict[str, Interval]:
    """Bypass rate per attack family, or false-positive rate per benign kind.

    Grouped reporting is not a nicety. An overall false-positive rate of 1% that
    is 14% on the security team's own documentation is a firewall that will be
    switched off in its first week, and the overall number cannot show that.
    """
    buckets: dict[str, list[float]] = {}
    for score, group in zip(scores.tolist(), groups, strict=True):
        buckets.setdefault(group, []).append(score)
    return {
        name: wilson(sum(1 for score in values if score < threshold), len(values))
        for name, values in sorted(buckets.items())
    }


def flag_rate_by_group(
    scores: np.ndarray, groups: list[str], threshold: float
) -> dict[str, Interval]:
    """The share of each group at or above the threshold."""
    buckets: dict[str, list[float]] = {}
    for score, group in zip(scores.tolist(), groups, strict=True):
        buckets.setdefault(group, []).append(score)
    return {
        name: wilson(sum(1 for score in values if score >= threshold), len(values))
        for name, values in sorted(buckets.items())
    }


def roc_auc(attack_scores: np.ndarray, benign_scores: np.ndarray) -> float:
    """Area under the ROC curve, by the rank-sum identity, ties counted as half.

    Threshold-free, so it says whether the scores *order* attacks above benign
    traffic independently of where the operating point was put. Reported
    alongside the operating-point numbers rather than instead of them: an AUC of
    0.99 is compatible with a bypass rate of 30% at a usable false-positive
    budget, and it is the bypass rate a deployment lives with.
    """
    if attack_scores.size == 0 or benign_scores.size == 0:
        return 0.0
    combined = np.concatenate([attack_scores, benign_scores])
    order = combined.argsort(kind="stable")
    ranks = np.empty(combined.size, dtype=np.float64)
    ranks[order] = np.arange(1, combined.size + 1, dtype=np.float64)
    # Average the ranks of tied scores, which is what makes ties count as half.
    sorted_values = combined[order]
    start = 0
    for index in range(1, combined.size + 1):
        if index == combined.size or sorted_values[index] != sorted_values[start]:
            if index - start > 1:
                ranks[order[start:index]] = ranks[order[start:index]].mean()
            start = index
    positive_ranks = ranks[: attack_scores.size].sum()
    count_positive = float(attack_scores.size)
    count_negative = float(benign_scores.size)
    return float(
        (positive_ranks - count_positive * (count_positive + 1) / 2)
        / (count_positive * count_negative)
    )
