"""Leave-one-family-out evaluation: what happens against a technique nobody had seen.

The argument, in one paragraph.

A detector is built by people who have a list of attacks. They write rules
against that list, add normalisation stages against the tricks on that list, and
train a classifier on that list. Then they split the list at random, measure,
and publish a bypass rate. Every attack in that test set is an attack of a kind
the detector was built against, so the number describes how well the detector
recognises rewordings of things it already knows. Real traffic contains
techniques that were not on the list, and the published number says nothing at
all about those.

So this harness holds out an entire **family** — a technique, not a wording —
and, critically, holds out the countermeasures that family motivated as well.
The rules written against ``delimiter_escape`` are switched off in the
``delimiter_escape`` fold, and so are the normalisation stages and structural
signals that exist because of it. What is left is the detector somebody would
have built if that technique had never occurred to them, evaluated against it.

Both numbers are reported side by side: the leave-one-family-out bypass rate and
the random-split bypass rate, on the same corpus, from the same benign
calibration set, at the same false-positive budget. The gap between them is the
size of the mistake in the conventional methodology.

Thresholds are calibrated on **benign traffic at a fixed false-positive budget**
and the bypass rate is then read off. That ordering is not negotiable. Choosing
a threshold that makes the bypass rate look good and reporting the resulting
false-positive rate underneath it is how two detectors become incomparable.

**The two arms share a budget, not a threshold**, and the distinction is worth
being exact about. Each fold's detector and the control's detector are different
detectors — different training data, different countermeasures enabled — so each
gets the threshold that costs *it* 1% of benign traffic. Holding the numeric
threshold fixed across them instead would mean the two arms were paying
different false-positive prices, and comparing bypass rates at different prices
is the thing the calibration step exists to prevent. Every fold's threshold and
the control's are in the report so the difference is visible rather than
asserted.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import numpy as np

from pifw.detect import heuristic, patterns
from pifw.detect.ensemble import Detector, threshold_at_fpr
from pifw.detect.normalize import stages_for_fold
from pifw.errors import RefusalError
from pifw.evaluate.metrics import (
    Confusion,
    Interval,
    confusion,
    flag_rate_by_group,
    roc_auc,
    wilson,
)
from pifw.model.features import FeatureSpec, Matrix, build_matrix
from pifw.model.logistic import Model, TrainConfig, train_on
from pifw.sample import Corpus, Sample, build_corpus

#: The false-positive budget every threshold in this project is calibrated to.
#: 1% of benign traffic flagged. Higher is easy to justify on paper and hard to
#: live with: an assistant handling ten thousand messages a day at 5% is
#: interrupting five hundred people who did nothing wrong.
DEFAULT_TARGET_FPR = 0.01

#: Every arm, scored independently at its own calibrated threshold, so a reader
#: can see which one is carrying the result and which is decoration. This is the
#: table that decided what this project ships: ``combined`` -- the noisy-OR of
#: all three layers -- measures worse against unseen techniques than ``model``
#: alone, so ``decision`` is the learned layer and the other two are evidence.
#: ``combined`` is still measured every run, because the finding should keep
#: being re-checked rather than be inherited from a README.
LAYERS: tuple[str, ...] = ("rules", "signals", "model", "combined", "decision")

#: The arm the headline bypass rate is quoted from: whatever the firewall would
#: actually act on. Quoting a number from an arm the shipped code does not use
#: is how an evaluation ends up describing something nobody deployed.
HEADLINE: str = "decision"

Progress = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class FoldResult:
    """One fold: one family held out, or one random subset held out."""

    #: The held-out family, or ``"__random__"`` for the random-split control.
    family: str
    held_out_families: tuple[str, ...]
    threshold: float
    confusion: Confusion
    auc: float
    layer_bypass: dict[str, Interval]
    layer_threshold: dict[str, float]
    layer_fpr: dict[str, Interval]
    #: What the fold switched off. Empty for the control, which switches off
    #: nothing because in a random split every technique has been seen.
    disabled_stages: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    disabled_signals: tuple[str, ...] = ()

    @property
    def bypass(self) -> Interval:
        """The share of held-out attacks that scored below the threshold."""
        return self.confusion.bypass

    def to_dict(self) -> dict[str, object]:
        """As JSON."""
        return {
            "family": self.family,
            "threshold": self.threshold,
            "auc": self.auc,
            "confusion": self.confusion.to_dict(),
            "layers": {
                name: {
                    "threshold": self.layer_threshold[name],
                    "bypass_rate": self.layer_bypass[name].point,
                    "bypass_ci": [self.layer_bypass[name].low, self.layer_bypass[name].high],
                    "false_positive_rate": self.layer_fpr[name].point,
                }
                for name in LAYERS
            },
            "disabled": {
                "stages": list(self.disabled_stages),
                "rules": list(self.disabled_rules),
                "signals": list(self.disabled_signals),
            },
        }


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Every fold, the control, and the aggregate."""

    target_fpr: float
    folds: tuple[FoldResult, ...]
    control: FoldResult
    benign_flag_rate_by_kind: dict[str, Interval]
    train_size: int
    eval_size: int
    #: Evaluation samples removed because the training corpus contained the same
    #: text. Reported rather than absorbed: it is a fact about how much headroom
    #: the grammars have, and a run where it grew would be a run whose evaluation
    #: set had quietly shrunk.
    dropped_shared: int = 0
    feature_spec: FeatureSpec = field(default_factory=FeatureSpec)

    @property
    def pooled_bypass(self) -> Interval:
        """Bypass rate over every held-out attack in every fold.

        Pooled rather than averaged over folds. Averaging rates weights a family
        with 140 attacks the same as one with 12, and the families are not the
        same size once the grammar has dropped its collisions.
        """
        missed = sum(fold.confusion.false_negative for fold in self.folds)
        total = sum(fold.confusion.attacks for fold in self.folds)
        return wilson(missed, total)

    @property
    def worst_fold(self) -> FoldResult:
        """The family the firewall does worst against."""
        return max(self.folds, key=lambda fold: fold.bypass.point)

    @property
    def optimism_gap(self) -> float:
        """How much better the random split looks, in points of bypass rate.

        The single number this repository exists to produce.
        """
        return self.pooled_bypass.point - self.control.bypass.point

    def to_dict(self) -> dict[str, object]:
        """As JSON, for the report and the baseline."""
        return {
            "target_false_positive_rate": self.target_fpr,
            "train_size": self.train_size,
            "eval_size": self.eval_size,
            "dropped_shared": self.dropped_shared,
            "feature_spec": self.feature_spec.to_dict(),
            "pooled_bypass_rate": self.pooled_bypass.point,
            "pooled_bypass_ci": [self.pooled_bypass.low, self.pooled_bypass.high],
            "random_split_bypass_rate": self.control.bypass.point,
            "optimism_gap": self.optimism_gap,
            "worst_family": self.worst_fold.family,
            "worst_family_bypass_rate": self.worst_fold.bypass.point,
            "folds": [fold.to_dict() for fold in self.folds],
            "control": self.control.to_dict(),
            "benign_flag_rate_by_kind": {
                name: interval.point for name, interval in self.benign_flag_rate_by_kind.items()
            },
        }


def _labels(records: Sequence[Sample]) -> list[int]:
    return [1 if record.is_attack else 0 for record in records]


class _Featuriser:
    """Featurises the training corpus once per distinct normalisation setting.

    Only four settings ever arise — no stages disabled, plus the three folds
    that disable one each — so twelve folds need four featurisation passes
    rather than twelve. The first implementation did twelve and spent nine
    tenths of the evaluation's runtime recomputing identical hashes.
    """

    def __init__(self, records: Sequence[Sample], spec: FeatureSpec) -> None:
        self._records = records
        self._spec = spec
        self._cache: dict[frozenset[str], Matrix] = {}

    def matrix(self, disabled_stages: frozenset[str]) -> Matrix:
        if disabled_stages not in self._cache:
            probe = Detector(model=None, disabled_stages=disabled_stages)
            texts = [probe.inspect(record.text).normalized.text for record in self._records]
            self._cache[disabled_stages] = build_matrix(texts, self._spec)
        return self._cache[disabled_stages]


# Both helpers below take the evaluation's state as arguments rather than
# bundling it into an object that would exist only to reduce an argument
# count. Every parameter is a distinct thing the caller already holds, and a
# `_FoldInputs` wrapper would add a name without adding a concept.
def _score_fold(
    detector: Detector,
    attacks: Sequence[Sample],
    calibration_benign: Sequence[Sample],
    measurement_benign: Sequence[Sample],
    target_fpr: float,
) -> tuple[dict[str, float], dict[str, Interval], dict[str, Interval], Confusion, float]:
    """Calibrate on one benign half, measure on the other and on the attacks."""
    attack_scores = detector.scores([record.text for record in attacks])
    calibration_scores = detector.scores([record.text for record in calibration_benign])
    measurement_scores = detector.scores([record.text for record in measurement_benign])

    thresholds: dict[str, float] = {}
    bypass: dict[str, Interval] = {}
    false_positive: dict[str, Interval] = {}
    for layer in LAYERS:
        threshold = threshold_at_fpr(calibration_scores[layer], target_fpr)
        counts = confusion(attack_scores[layer], measurement_scores[layer], threshold)
        thresholds[layer] = threshold
        bypass[layer] = counts.bypass
        false_positive[layer] = counts.false_positive_rate

    headline = confusion(
        attack_scores[HEADLINE], measurement_scores[HEADLINE], thresholds[HEADLINE]
    )
    auc = roc_auc(attack_scores[HEADLINE], measurement_scores[HEADLINE])
    return thresholds, bypass, false_positive, headline, auc


def _benign_halves(corpus: Corpus) -> tuple[tuple[Sample, ...], tuple[Sample, ...]]:
    """Split benign samples into a calibration half and a measurement half.

    Alternating indices, not a shuffle. Benign samples come out of the generator
    grouped by kind, so taking every other one splits every kind evenly without
    needing a seed — and a split that needs no seed cannot be accidentally
    reseeded into a different answer.
    """
    benign = corpus.benign
    return benign[0::2], benign[1::2]


def run(  # noqa: PLR0913
    train_corpus: Corpus,
    eval_corpus: Corpus,
    *,
    target_fpr: float = DEFAULT_TARGET_FPR,
    config: TrainConfig | None = None,
    families: Sequence[str] | None = None,
    drop_shared: bool = False,
    progress: Progress | None = None,
) -> Evaluation:
    """Run the whole evaluation: one fold per family, plus the random-split control.

    ``train_corpus`` and ``eval_corpus`` must be disjoint. Different seeds make
    them *almost* disjoint, but not entirely: two seeded walks over the same
    grammar do sometimes emit the same sentence, and the smaller benign kinds
    have only a few thousand distinct outputs between them. Measured on the
    shipped corpora, 568 of 3,480 evaluation samples also appear in training.

    Left alone, those samples would be scored by a detector fitted to them, and
    every bypass rate here would be a little too good. The default is therefore
    to **refuse** — no number at all — and ``drop_shared`` is the explicit
    alternative: remove them, count them, and say in the report how many went.
    """
    settings = config or TrainConfig()
    trained_text = {record.text for record in train_corpus}
    shared = [record for record in eval_corpus if record.text in trained_text]
    dropped = 0
    if shared:
        if not drop_shared:
            raise RefusalError(
                f"the training and evaluation corpora share {len(shared)} sample(s)",
                remedy=(
                    "Pass drop_shared=True (or --drop-shared) to remove them from the "
                    "evaluation set and have the count reported. A bypass rate measured "
                    "on text the detector was fitted to is not a bypass rate."
                ),
            )
        dropped = len(shared)
        eval_corpus = build_corpus(
            record for record in eval_corpus if record.text not in trained_text
        )

    wanted = tuple(families) if families is not None else eval_corpus.families
    missing = [name for name in wanted if name not in train_corpus.families]
    if missing:
        raise RefusalError(
            f"the training corpus has no attacks from: {', '.join(missing)}",
            remedy="Regenerate both corpora from the same plan family list.",
        )

    say = progress or (lambda _message: None)
    featuriser = _Featuriser(train_corpus.records, settings.spec)
    labels = _labels(train_corpus.records)
    calibration_benign, measurement_benign = _benign_halves(eval_corpus)

    folds: list[FoldResult] = []
    for family in wanted:
        say(f"fold {family}")
        stages = stages_for_fold(family)
        rules = patterns.rules_for_fold(family)
        signals = heuristic.signals_for_fold(family)

        keep = np.array(
            [index for index, record in enumerate(train_corpus.records) if record.family != family],
            dtype=np.int64,
        )
        matrix = featuriser.matrix(stages)
        model = train_on(
            matrix.select(keep),
            [labels[int(index)] for index in keep],
            families=[name for name in train_corpus.families if name != family],
            config=settings,
        )
        detector = Detector(
            model=model,
            disabled_stages=stages,
            disabled_rules=rules,
            disabled_signals=signals,
        )
        _assert_fold_is_blind(model, family)

        attacks = eval_corpus.only_family(family).records
        thresholds, bypass, false_positive, counts, auc = _score_fold(
            detector, attacks, calibration_benign, measurement_benign, target_fpr
        )
        folds.append(
            FoldResult(
                family=family,
                held_out_families=(family,),
                threshold=thresholds[HEADLINE],
                confusion=counts,
                auc=auc,
                layer_bypass=bypass,
                layer_threshold=thresholds,
                layer_fpr=false_positive,
                disabled_stages=tuple(sorted(stages)),
                disabled_rules=tuple(sorted(rules)),
                disabled_signals=tuple(sorted(signals)),
            )
        )

    say("control (random split)")
    control, control_detector = _random_split_control(
        train_corpus,
        eval_corpus,
        featuriser,
        labels,
        calibration_benign,
        measurement_benign,
        target_fpr,
        settings,
    )

    by_kind = flag_rate_by_group(
        control_detector.scores([record.text for record in measurement_benign])[HEADLINE],
        [record.kind for record in measurement_benign],
        control.threshold,
    )

    return Evaluation(
        target_fpr=target_fpr,
        folds=tuple(folds),
        control=control,
        benign_flag_rate_by_kind=by_kind,
        train_size=len(train_corpus),
        eval_size=len(eval_corpus),
        dropped_shared=dropped,
        feature_spec=settings.spec,
    )


def _assert_fold_is_blind(model: Model, family: str) -> None:
    """The invariants the whole result rests on, checked rather than assumed.

    The convergence check is here because of a measured mistake rather than a
    theoretical worry. With a fixed 400 steps of plain gradient descent the
    pooled bypass rate came out at 40%; the same code trained to convergence
    gives a sixth of that. Both numbers look equally like a result, and nothing
    in the report distinguished them. Now one of them cannot be produced.
    """
    if family in model.trained_families:
        raise RefusalError(
            f"the model for the {family!r} fold was trained on {family!r} attacks",
            remedy="This is a bug in the harness, not a configuration problem.",
        )
    if not model.converged:
        raise RefusalError(
            f"the model for the {family!r} fold stopped at {model.iterations} iterations "
            "without reaching its gradient tolerance",
            remedy=(
                "A bypass rate measured from an undertrained model describes the "
                "optimiser, not the firewall. Raise TrainConfig.max_iterations, or "
                "loosen TrainConfig.tolerance if the looser criterion is defensible."
            ),
        )


def _random_split_control(  # noqa: PLR0913, PLR0917
    train_corpus: Corpus,
    eval_corpus: Corpus,
    featuriser: _Featuriser,
    labels: list[int],
    calibration_benign: Sequence[Sample],
    measurement_benign: Sequence[Sample],
    target_fpr: float,
    settings: TrainConfig,
) -> tuple[FoldResult, Detector]:
    """The number the conventional methodology would have produced.

    Every family is in training, nothing is switched off, and the evaluation set
    is a stride sample across all families rather than one family. The attacks
    are still unseen *text* — they come from the disjoint corpus — so this is
    not a contaminated measurement. It is an honest random split, which is
    precisely the point: the difference between it and the folds is a property
    of the split, not of a mistake.
    """
    matrix = featuriser.matrix(frozenset())
    model = train_on(
        matrix,
        labels,
        families=train_corpus.families,
        config=settings,
    )
    detector = Detector(model=model)

    # A stride of one-per-family walks the attack list — which is ordered family
    # by family — taking an even share of each. The result is the same size as a
    # single fold, so the two intervals are comparable; striding by the *fold
    # size* instead gave twelve samples and a control whose 95% interval ran to
    # 22%, which is not a number anything can be compared against.
    all_attacks = eval_corpus.attacks
    stride = max(1, len(eval_corpus.families))
    attacks = all_attacks[::stride]

    thresholds, bypass, false_positive, counts, auc = _score_fold(
        detector, attacks, calibration_benign, measurement_benign, target_fpr
    )
    return (
        FoldResult(
            family="__random__",
            held_out_families=eval_corpus.families,
            threshold=thresholds[HEADLINE],
            confusion=counts,
            auc=auc,
            layer_bypass=bypass,
            layer_threshold=thresholds,
            layer_fpr=false_positive,
        ),
        detector,
    )
