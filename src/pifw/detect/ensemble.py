"""Turning three layers into one score, and one score into a decision.

**The decision score is the learned layer alone, and that was measured rather
than assumed.** This module began by combining all three layers with a noisy-OR,
which is the obvious design and the one most guardrails ship. The twelve-fold
evaluation says it is worse than one of its own inputs:

===================  ==============  ============
arm                  unseen bypass   realised FPR
===================  ==============  ============
rules alone          93.75%          0.68%
structure alone      83.69%          1.16%
**model alone**      **2.08%**       1.84%
all three, noisy-OR  20.89%          1.25%
===================  ==============  ============

At a 1% false-positive budget the rule and structural layers carry almost no
usable signal against a technique they were not written for -- and because they
fire on benign traffic, mixing them in pushes the combined threshold from 0.11
up to 0.79, above attacks the learned layer had ranked correctly. Eleven of the
twelve folds go from 0% bypass to non-zero purely by adding them.

The obvious objection is that the model simply bought its result with a looser
operating point, since it realises 1.84% against a 1% budget where the ensemble
realises 1.25%. Re-measuring the model at the ensemble's *realised* rate leaves
every fold unchanged, so it did not: see ``docs/detection.md``.

So the rule and structural layers stay, and they are still computed, reported
and recorded -- as **evidence, not as score**. A verdict naming
``exfil.reveal_prompt`` tells an on-call engineer something a probability of 0.94
does not, and that value is real. It is just not detection lift, and this module
no longer spends detection accuracy to pretend otherwise.

``layers["combined"]`` is still computed and still written to the audit record,
because a claim of this kind should stay falsifiable by whoever deploys it
rather than resting on a table in a README.

Noisy-OR rather than a sum, where combination still happens -- for the
model-less fallback and for the reported ``combined`` diagnostic. A sum lets
three rules that all fired on the same clause reach a confident total from one
observation, and the message that says "ignore previous instructions" in a
sentence matching three overlapping patterns is not three times as suspicious as
the one matching one. Noisy-OR treats each layer as independent evidence,
saturates towards one, and cannot exceed it.

Layer reliabilities are constants, set once, and never fitted per family. The
temptation after the table above is to keep the ensemble and tune the rule and
signal reliabilities towards zero until it stops hurting. That is fitting
constants to held-out families -- the exact failure this evaluation exists to
detect -- and it is why the fix here is to drop the layers from the score
outright rather than to shrink their coefficients.

The **default mode is monitor, not enforce.** A firewall with a measured bypass
rate above zero — which is every firewall in this field — that blocks by default
is a firewall that teaches its operator to stop checking. Enforcement is
available and is a deliberate choice with a threshold the operator picks, and
:mod:`pifw.firewall` records what was allowed through either way, so the bypass
rate keeps being measured after deployment rather than only before it.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

import numpy as np

from pifw.detect import heuristic, patterns
from pifw.detect.normalize import Normalized, normalize
from pifw.model.logistic import Model

Decision = Literal["allow", "flag", "block"]
Mode = Literal["monitor", "enforce"]

#: How much each layer's own score is believed, used by the model-less fallback
#: and by the reported ``combined`` diagnostic. These began as judgements about
#: precision; the evaluation then measured them. The rule layer is *not* precise
#: and narrow: at its own 1% budget its threshold sits at 0.84, because it fires
#: on documentation, code and imperative English as readily as on attacks. These
#: numbers are kept as first written, unfitted and fixed across every fold, so
#: that the ``combined`` column keeps measuring the design this project rejected
#: rather than a version quietly tuned to look better.
RULE_RELIABILITY = 0.90
SIGNAL_RELIABILITY = 0.65
MODEL_RELIABILITY = 0.95

DEFAULT_FLAG = 0.5
DEFAULT_BLOCK = 0.9

#: A structural signal below this is not named in the verdict. Listing every
#: signal that fired at all buries the two that mattered in five that did not.
MIN_REPORTED_SIGNAL = 0.2


def decision_score(
    rule_score: float, signal_score: float, model_score: float, *, has_model: bool
) -> float:
    """The score the firewall actually acts on.

    With a learned layer loaded, that is the learned layer alone. Without one,
    it falls back to the non-learned layers -- which is a real configuration,
    since the package ships no weights and ``pifw scan`` runs without a model
    unless told otherwise, but it is a **much weaker** one. The 93.75% and
    83.69% in this module's docstring are what that fallback is worth against a
    technique nobody wrote a rule for, and ``pifw doctor`` says so at startup.
    """
    if has_model:
        return model_score
    return noisy_or((rule_score * RULE_RELIABILITY, signal_score * SIGNAL_RELIABILITY))


def noisy_or(values: Sequence[float]) -> float:
    """Combine independent evidence. Monotone, bounded by one, order-free."""
    remaining = 1.0
    for value in values:
        remaining *= 1.0 - max(0.0, min(1.0, value))
    return 1.0 - remaining


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Where allow becomes flag, and flag becomes block."""

    flag: float = DEFAULT_FLAG
    block: float = DEFAULT_BLOCK

    def __post_init__(self) -> None:
        if not 0.0 <= self.flag <= 1.0 or not 0.0 <= self.block <= 1.0:
            raise ValueError("thresholds are probabilities and must lie in [0, 1]")
        if self.block < self.flag:
            raise ValueError("the block threshold cannot be below the flag threshold")


@dataclass(frozen=True, slots=True)
class Verdict:
    """What the firewall thought, and why.

    ``layers`` carries every layer's score, the ``combined`` noisy-OR this
    project measured and rejected, and ``decision`` -- the one ``score`` was
    taken from. Reporting all of them lets the evaluation produce the per-layer
    table from a single pass, and lets an operator check the rejection against
    their own traffic instead of taking it on trust.
    """

    text: str
    score: float
    decision: Decision
    layers: dict[str, float]
    reasons: tuple[str, ...]
    normalized: Normalized

    @property
    def allowed(self) -> bool:
        """Would this message have reached the model unchanged?"""
        return self.decision == "allow"

    def explain(self) -> str:
        """One line naming the score, the decision and the evidence."""
        why = ", ".join(self.reasons) if self.reasons else "no named evidence"
        return f"{self.decision} at {self.score:.3f} ({why})"


@dataclass(frozen=True, slots=True)
class Detector:
    """The three layers, wired together, with everything switchable.

    ``disabled_*`` exist for the leave-one-family-out evaluation, which switches
    off the countermeasures a held-out family motivated. They are not a
    deployment feature, and nothing in :mod:`pifw.firewall` sets them.
    """

    model: Model | None = None
    thresholds: Thresholds = field(default_factory=Thresholds)
    mode: Mode = "monitor"
    disabled_stages: frozenset[str] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    disabled_signals: frozenset[str] = frozenset()

    def inspect(self, text: str) -> Verdict:
        """Score one message and decide what to do with it."""
        seen: Normalized = normalize(text, disabled=self.disabled_stages)
        rule_hits = patterns.match_rules(seen.text, disabled=self.disabled_rules)
        signal_hits = heuristic.measure(text, seen.text, disabled=self.disabled_signals)

        rule_score = noisy_or([hit.weight for hit in rule_hits])
        signal_score = noisy_or([hit.weight * hit.value for hit in signal_hits])
        model_score = self.model.probability(seen.text) if self.model is not None else 0.0

        combined = noisy_or(
            (
                rule_score * RULE_RELIABILITY,
                signal_score * SIGNAL_RELIABILITY,
                model_score * MODEL_RELIABILITY,
            )
        )
        score = decision_score(
            rule_score, signal_score, model_score, has_model=self.model is not None
        )
        reasons = tuple(
            [hit.rule_id for hit in rule_hits]
            + [
                f"{hit.name}={hit.value:.2f}"
                for hit in signal_hits
                if hit.value >= MIN_REPORTED_SIGNAL
            ]
        )
        return Verdict(
            text=text,
            score=score,
            decision=self.decide(score),
            layers={
                "rules": rule_score,
                "signals": signal_score,
                "model": model_score,
                "combined": combined,
                "decision": score,
            },
            reasons=reasons,
            normalized=seen,
        )

    def decide(self, score: float) -> Decision:
        """Turn a score into an action, respecting the mode.

        In monitor mode the answer is never ``block``, whatever the score and
        whatever the block threshold says. A mode that can be overridden by a
        threshold is not a mode.
        """
        if self.mode == "enforce" and score >= self.thresholds.block:
            return "block"
        if score >= self.thresholds.flag:
            return "flag"
        return "allow"

    def scores(self, texts: Sequence[str]) -> dict[str, np.ndarray]:
        """Score many messages, returning one array per layer.

        Batched because the learned layer is the expensive part and featurising
        a few thousand messages one at a time costs more than the training run
        that produced the weights.
        """
        rule_scores = np.empty(len(texts), dtype=np.float64)
        signal_scores = np.empty(len(texts), dtype=np.float64)
        normalized: list[str] = []
        for index, text in enumerate(texts):
            seen = normalize(text, disabled=self.disabled_stages)
            normalized.append(seen.text)
            rule_scores[index] = noisy_or(
                [
                    hit.weight
                    for hit in patterns.match_rules(seen.text, disabled=self.disabled_rules)
                ]
            )
            signal_scores[index] = noisy_or(
                [
                    hit.weight * hit.value
                    for hit in heuristic.measure(text, seen.text, disabled=self.disabled_signals)
                ]
            )
        if self.model is not None:
            model_scores = self.model.probabilities(normalized)
        else:
            model_scores = np.zeros(len(texts), dtype=np.float64)

        combined = 1.0 - (
            (1.0 - rule_scores * RULE_RELIABILITY)
            * (1.0 - signal_scores * SIGNAL_RELIABILITY)
            * (1.0 - model_scores * MODEL_RELIABILITY)
        )
        if self.model is not None:
            decision = model_scores
        else:
            decision = 1.0 - (
                (1.0 - rule_scores * RULE_RELIABILITY) * (1.0 - signal_scores * SIGNAL_RELIABILITY)
            )
        return {
            "rules": rule_scores,
            "signals": signal_scores,
            "model": model_scores,
            "combined": combined,
            "decision": decision,
        }

    def with_fold(self, held_out: str | None) -> Detector:
        """A copy of this detector with the held-out family's countermeasures off.

        The learned layer is *not* removed here; the caller supplies a model
        trained without the held-out family. Removing a component is not the
        same as never having had it, and only the caller knows which of the two
        it wants.
        """
        from pifw.detect.normalize import stages_for_fold  # noqa: PLC0415 - avoids a cycle

        return Detector(
            model=self.model,
            thresholds=self.thresholds,
            mode=self.mode,
            disabled_stages=stages_for_fold(held_out),
            disabled_rules=patterns.rules_for_fold(held_out),
            disabled_signals=heuristic.signals_for_fold(held_out),
        )


def threshold_at_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """The lowest threshold whose false-positive rate is at most *target_fpr*.

    Calibrating on benign traffic and then reporting recall — rather than
    picking a threshold that makes recall look good and reporting the resulting
    false-positive rate as a footnote — is the only ordering under which the two
    numbers can be compared with anybody else's.

    Ties matter and are handled explicitly: with many identical scores at the
    boundary, the quantile is not the threshold. This walks up to the first
    distinct score whose false-positive rate is within budget.
    """
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("a target false-positive rate must lie in [0, 1]")
    if benign_scores.size == 0:
        raise ValueError("cannot calibrate a threshold without benign scores")
    allowed = math.floor(target_fpr * benign_scores.size)
    ordered = np.sort(benign_scores)[::-1]
    if allowed >= ordered.size:
        return 0.0
    # The (allowed+1)-th highest benign score is the first one that must not be
    # flagged, so the threshold sits immediately above it. Anything tied with it
    # is also below the threshold, which is why the count of flagged benign
    # samples can come in under budget rather than exactly on it.
    boundary = float(ordered[allowed])
    return math.nextafter(boundary, math.inf)
