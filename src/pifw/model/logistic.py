"""The learned layer: L2-regularised logistic regression, trained in NumPy.

Deliberately the simplest thing that could work, for three reasons that all
point the same way.

It is **convex**, so training has one answer and reaching it does not depend on
an initialisation, a shuffle order or a seed. Weights start at zero. The
previous project in this series spent real time discovering that
``standard_normal`` is not bit-reproducible across platforms; the cheapest fix
for that class of problem is a model that needs no random numbers at all.

It is **inspectable**. ``model.top_features(...)`` names the n-grams carrying
the decision, which matters for a component whose output a person has to act on
at three in the morning.

It is **weak in a known way**. A linear model over hashed n-grams generalises to
paraphrase and does not generalise to a technique it has never seen, and the
evaluation is built to show exactly that. A larger model would move the numbers
and obscure the finding, which for this repository would be the wrong trade.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from pifw.errors import ModelError
from pifw.model.features import FeatureSpec, Matrix, build_matrix, features_of

#: Training runs to a **convergence criterion**, not to an iteration count, and
#: a model that hits the ceiling without converging is reported as such rather
#: than used. This is not fastidiousness. The first version of this file ran a
#: fixed 400 steps of plain gradient descent, and the headline bypass rate it
#: produced was 40%; the same model trained to convergence gives 6%. A number
#: measured from an unconverged model is a statement about the optimiser, and it
#: is indistinguishable from a statement about the firewall.
DEFAULT_MAX_ITERATIONS = 4000
DEFAULT_LEARNING_RATE = 8.0

#: Heavy-ball momentum. The design matrix is hashed n-grams with wildly
#: different feature frequencies, so the problem is badly conditioned and plain
#: gradient descent crawls along the flat directions. Momentum reached in 400
#: steps what plain descent had not reached in 1,200.
DEFAULT_MOMENTUM = 0.9

DEFAULT_L2 = 1e-4

#: Converged when no coordinate of the gradient exceeds this. An absolute
#: criterion on the gradient rather than a relative one on the loss: the loss
#: flattens long before the weights stop moving, so a loss-change test declares
#: victory early and does it most confidently on the runs that need the most
#: iterations.
DEFAULT_TOLERANCE = 1e-6

#: Model files carry this. A file from an older layout is rejected on load
#: rather than reinterpreted, because a weight vector read against the wrong
#: featuriser produces scores, not errors.
#: Labels are 0 and 1, so anything above this is the positive class. Named
#: because 0.5 appearing in a training loop reads like a probability.
_POSITIVE = 0.5

FORMAT_VERSION = 1


def sigmoid(values: np.ndarray) -> np.ndarray:
    """Logistic function, computed without overflowing on either tail."""
    out = np.empty_like(values)
    positive = values >= 0
    out[positive] = 1.0 / (1.0 + np.exp(-values[positive]))
    exp_negative = np.exp(values[~positive])
    out[~positive] = exp_negative / (1.0 + exp_negative)
    return out


@dataclass(frozen=True, slots=True)
class TrainConfig:
    """Hyperparameters, all of them, in one place."""

    spec: FeatureSpec = field(default_factory=FeatureSpec)
    max_iterations: int = DEFAULT_MAX_ITERATIONS
    learning_rate: float = DEFAULT_LEARNING_RATE
    momentum: float = DEFAULT_MOMENTUM
    l2: float = DEFAULT_L2
    tolerance: float = DEFAULT_TOLERANCE

    def to_dict(self) -> dict[str, object]:
        """As JSON, for the model file."""
        return {
            "spec": self.spec.to_dict(),
            "max_iterations": self.max_iterations,
            "learning_rate": self.learning_rate,
            "momentum": self.momentum,
            "l2": self.l2,
            "tolerance": self.tolerance,
        }


@dataclass(frozen=True, slots=True)
class Model:
    """Trained weights plus everything needed to interpret them."""

    weights: np.ndarray
    bias: float
    spec: FeatureSpec
    #: The attack families present in the training data. Carried so the
    #: evaluation can refuse to report a bypass rate for a family this model
    #: has already been fitted to.
    trained_families: tuple[str, ...]
    final_loss: float
    #: Did training reach its gradient tolerance, or run out of iterations?
    #: Carried on the model rather than logged, because the caller that needs
    #: to know is the evaluation, and it needs to refuse rather than to warn.
    converged: bool = True
    iterations: int = 0

    def raw_scores(self, texts: Sequence[str]) -> np.ndarray:
        """The linear scores, before the logistic squash."""
        matrix = build_matrix(list(texts), self.spec)
        return matrix.dot(self.weights) + self.bias

    def probabilities(self, texts: Sequence[str]) -> np.ndarray:
        """P(attack) for each message."""
        return sigmoid(self.raw_scores(texts))

    def probability(self, text: str) -> float:
        """P(attack) for one message."""
        return float(self.probabilities([text])[0])

    def top_features(self, text: str, limit: int = 5) -> tuple[tuple[int, float], ...]:
        """The buckets contributing most to this message's score.

        Buckets, not words: hashing is one-way, so the honest answer is an
        index and a contribution. Naming a word would mean keeping a reverse
        map, and a reverse map for a hashed featuriser is a guess.
        """
        counts = features_of(text, self.spec)
        if not counts:
            return ()
        contributions = [
            (index, float(value * self.weights[index])) for index, value in counts.items()
        ]
        contributions.sort(key=lambda item: abs(item[1]), reverse=True)
        return tuple(contributions[:limit])

    def config_digest(self) -> str:
        """A content address over the *configuration*, not the weights.

        The weights are floats produced by an accumulation whose order depends
        on the BLAS build, so they differ in the last couple of bits between
        platforms and cannot be compared by equality. The configuration is
        integers and strings, and can. See ``docs/reproducibility.md``.
        """
        payload = json.dumps(
            {
                "format": FORMAT_VERSION,
                "spec": self.spec.to_dict(),
                "families": list(self.trained_families),
                "size": int(self.weights.size),
            },
            sort_keys=True,
        )
        return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"

    def save(self, path: str | Path) -> Path:
        """Write the model as JSON."""
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(
            json.dumps(
                {
                    "format": FORMAT_VERSION,
                    "spec": self.spec.to_dict(),
                    "bias": self.bias,
                    "weights": self.weights.tolist(),
                    "trained_families": list(self.trained_families),
                    "final_loss": self.final_loss,
                    "converged": self.converged,
                    "iterations": self.iterations,
                    "config_digest": self.config_digest(),
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
    def load(cls, path: str | Path) -> Model:
        """Read a model, refusing anything whose layout does not match."""
        file = Path(path)
        if not file.exists():
            raise ModelError(
                f"no model at {file}",
                remedy="Train one with 'pifw train --corpus <path> --out <path>'.",
            )
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ModelError(
                f"{file} is not valid JSON: {exc}",
                remedy="Retrain rather than editing a model file by hand.",
            ) from exc
        if data.get("format") != FORMAT_VERSION:
            raise ModelError(
                f"{file} is format {data.get('format')!r}, this build reads {FORMAT_VERSION}",
                remedy="Retrain with 'pifw train'.",
            )
        spec = FeatureSpec.from_dict(data["spec"])
        weights = np.array(data["weights"], dtype=np.float64)
        if weights.size != spec.buckets:
            raise ModelError(
                f"{file} has {weights.size} weights for {spec.buckets} buckets",
                remedy="Retrain; the file and its featuriser do not agree.",
            )
        model = cls(
            weights=weights,
            bias=float(data["bias"]),
            spec=spec,
            trained_families=tuple(data.get("trained_families", ())),
            final_loss=float(data.get("final_loss", 0.0)),
            converged=bool(data.get("converged", True)),
            iterations=int(data.get("iterations", 0)),
        )
        stored = data.get("config_digest")
        if stored is not None and stored != model.config_digest():
            raise ModelError(
                f"{file} does not match its own configuration digest",
                remedy="The file was edited or truncated. Retrain.",
            )
        return model


def train(
    texts: Sequence[str],
    labels: Sequence[int],
    *,
    families: Sequence[str] = (),
    config: TrainConfig | None = None,
) -> Model:
    """Fit the model on raw text. Full-batch gradient descent, no randomness."""
    settings = config or TrainConfig()
    if len(texts) != len(labels):
        raise ModelError(f"{len(texts)} texts against {len(labels)} labels")
    if not texts:
        raise ModelError("cannot train on an empty corpus")
    return train_on(
        build_matrix(list(texts), settings.spec),
        labels,
        families=families,
        config=settings,
    )


def train_on(
    matrix: Matrix,
    labels: Sequence[int],
    *,
    families: Sequence[str] = (),
    config: TrainConfig | None = None,
) -> Model:
    """Fit the model on an already-featurised matrix.

    Separated from :func:`train` so the leave-one-family-out harness can
    featurise the corpus once and fit twelve models against views of it.

    Classes are weighted by inverse frequency. Not for accuracy — the corpus is
    roughly balanced — but so that the operating point does not move when a fold
    removes a twelfth of the attacks. A threshold calibrated on one fold has to
    mean the same thing on the next.
    """
    settings = config or TrainConfig()
    if matrix.rows != len(labels):
        raise ModelError(f"{matrix.rows} rows against {len(labels)} labels")
    if matrix.rows == 0:
        raise ModelError("cannot train on an empty corpus")

    target = np.array(labels, dtype=np.float64)
    if set(np.unique(target).tolist()) != {0.0, 1.0}:
        raise ModelError(
            "training needs both classes present",
            remedy="Check that the corpus contains attack and benign samples.",
        )

    rows = matrix.rows
    positives = float(target.sum())
    negatives = float(rows - positives)
    sample_weight = np.where(target > _POSITIVE, rows / (2.0 * positives), rows / (2.0 * negatives))
    weight_total = float(sample_weight.sum())

    # numpy's overflow warnings are redundant here and, under this project's
    # `filterwarnings = ["error"]`, would raise before the check below could
    # produce a useful message. The explicit isfinite test that follows is
    # strictly stronger: it catches a diverged run whether or not any single
    # operation happened to warn.
    with np.errstate(over="ignore", invalid="ignore"):
        weights, bias, loss, converged, used = _descend(
            matrix, target, sample_weight, weight_total, settings
        )

    return Model(
        weights=weights,
        bias=bias,
        spec=settings.spec,
        trained_families=tuple(sorted(set(families))),
        final_loss=loss,
        converged=converged,
        iterations=used,
    )


def _descend(
    matrix: Matrix,
    target: np.ndarray,
    sample_weight: np.ndarray,
    weight_total: float,
    settings: TrainConfig,
) -> tuple[np.ndarray, float, float, bool, int]:
    """The loop itself. Heavy-ball descent to a gradient tolerance."""
    weights = np.zeros(settings.spec.buckets, dtype=np.float64)
    velocity = np.zeros_like(weights)
    bias = 0.0
    bias_velocity = 0.0
    loss = 0.0
    converged = False
    used = 0

    for step in range(1, settings.max_iterations + 1):
        used = step
        predicted = sigmoid(matrix.dot(weights) + bias)
        residual = (predicted - target) * sample_weight
        gradient = matrix.transpose_dot(residual) / weight_total + settings.l2 * weights
        bias_gradient = float(residual.sum()) / weight_total

        worst = max(float(np.max(np.abs(gradient))), abs(bias_gradient))
        if worst < settings.tolerance:
            converged = True
            break

        velocity = settings.momentum * velocity - settings.learning_rate * gradient
        bias_velocity = settings.momentum * bias_velocity - settings.learning_rate * bias_gradient
        weights = weights + velocity
        bias = bias + bias_velocity

        clipped = np.clip(predicted, 1e-12, 1.0 - 1e-12)
        loss = (
            float(
                np.sum(
                    -sample_weight * (target * np.log(clipped) + (1 - target) * np.log(1 - clipped))
                )
            )
            / weight_total
        )
        if not np.isfinite(loss) or not np.all(np.isfinite(weights)):
            raise ModelError(
                f"training diverged at step {step}",
                remedy=(
                    f"The learning rate ({settings.learning_rate}) is too high for this "
                    "data. Lower it, or lower the momentum."
                ),
            )

    return weights, bias, loss, converged, used
