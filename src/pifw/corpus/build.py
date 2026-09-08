"""Turning the grammars into a corpus, reproducibly.

One seeded :class:`random.Random` per bucket rather than one for the whole run.
That is not a stylistic choice: with a single stream, adding a family or nudging
one weight shifts every draw after it and the entire corpus changes. Per-bucket
streams mean a change to the ``markup`` builder changes the markup samples and
nothing else, so a diff of the regenerated corpus shows what was actually
edited.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass, field

from pifw.corpus import attacks, benign
from pifw.errors import ConfigError
from pifw.sample import Corpus, Sample, build_corpus

#: How many times a builder may be asked again after producing a string the
#: corpus already contains. The grammars are large enough that collisions are
#: rare; a builder that cannot produce a fresh string in this many attempts has
#: exhausted its space, and the honest response is to report a short corpus
#: rather than to loop.
MAX_RETRIES = 40


@dataclass(frozen=True, slots=True)
class Plan:
    """Everything needed to regenerate a corpus byte for byte."""

    name: str
    seed: int
    attacks_per_family: int
    benign_total: int
    families: tuple[str, ...] = field(default=attacks.FAMILY_NAMES)

    def __post_init__(self) -> None:
        if self.attacks_per_family < 1:
            raise ConfigError("attacks_per_family must be at least 1")
        if self.benign_total < len(benign.KINDS):
            raise ConfigError(
                f"benign_total must be at least {len(benign.KINDS)}, one per benign kind"
            )
        unknown = set(self.families) - set(attacks.FAMILY_NAMES)
        if unknown:
            raise ConfigError(f"unknown attack families: {', '.join(sorted(unknown))}")
        if not self.families:
            raise ConfigError("a plan needs at least one attack family")


PLANS: dict[str, Plan] = {
    # The shipped corpus. 12 families x 260 = 3,120 attacks against 3,600
    # benign samples: roughly balanced, because the leave-one-family-out
    # evaluation trains on eleven families and a class ratio that swings with
    # the fold would make the folds incomparable.
    "main": Plan(name="main", seed=20260908, attacks_per_family=260, benign_total=3600),
    # A second corpus from the same grammars with a different seed. Disjoint by
    # construction, which is what makes it an instrument: it measures what this
    # firewall scores on data it provably has not been fitted to, and every
    # threshold in the project is calibrated against it rather than guessed.
    "holdout": Plan(name="holdout", seed=771103, attacks_per_family=140, benign_total=1800),
    # Small and fast, for the test suite. Not shipped.
    "tiny": Plan(name="tiny", seed=5, attacks_per_family=12, benign_total=48),
}


@dataclass(frozen=True, slots=True)
class Generation:
    """A generated corpus and what happened while generating it."""

    corpus: Corpus
    requested: int
    collisions: int

    @property
    def collision_rate(self) -> float:
        """The share of draws that repeated a string already in the corpus."""
        return self.collisions / self.requested if self.requested else 0.0

    def summary(self) -> str:
        """One line, for a terminal."""
        return (
            f"{len(self.corpus)} samples "
            f"({len(self.corpus.attacks)} attack, {len(self.corpus.benign)} benign); "
            f"{self.collisions} collision(s) at {self.collision_rate:.2%}"
        )


def _benign_quota(total: int, kinds: Sequence[benign.Kind]) -> dict[str, int]:
    """Split *total* across kinds by weight, giving every kind at least one.

    Largest-remainder rather than rounding each share independently: rounding
    each share loses or gains samples depending on the weights, and a corpus
    whose size depends on the weight vector cannot be compared across plans.
    """
    weights = [kind.weight for kind in kinds]
    scale = sum(weights)
    exact = [total * weight / scale for weight in weights]
    quota = {kind.name: max(1, int(value)) for kind, value in zip(kinds, exact, strict=True)}
    shortfall = total - sum(quota.values())
    order = sorted(
        range(len(kinds)),
        key=lambda index: (exact[index] - int(exact[index]), weights[index]),
        reverse=True,
    )
    position = 0
    while shortfall > 0:
        quota[kinds[order[position % len(order)]].name] += 1
        shortfall -= 1
        position += 1
    while shortfall < 0:
        name = kinds[order[position % len(order)]].name
        if quota[name] > 1:
            quota[name] -= 1
            shortfall += 1
        position += 1
    return quota


def _draw(
    build: attacks.Builder,
    rng: random.Random,
    count: int,
    seen: set[str],
) -> tuple[list[str], int]:
    """Draw *count* distinct strings, counting how often a draw repeated."""
    drawn: list[str] = []
    collisions = 0
    for _ in range(count):
        for _attempt in range(MAX_RETRIES):
            text = build(rng)
            if text not in seen:
                seen.add(text)
                drawn.append(text)
                break
            collisions += 1
        else:
            break
    return drawn, collisions


def generate(plan: Plan, *, exclude: frozenset[str] = frozenset()) -> Generation:
    """Build a corpus from a plan.

    Exact duplicates are dropped rather than kept, and the number dropped is
    reported. A duplicate that survives into the corpus lands on both sides of a
    split and turns into contamination that no later step can see.

    ``exclude`` is how the holdout corpus is made **disjoint by construction**
    rather than disjoint by hope. Two seeded walks over the same grammar do
    collide: measured before this existed, 568 of 3,480 holdout samples also
    appeared in the training corpus, and the collisions were badly skewed —
    ``credential_hygiene`` lost 65% of its samples and ``markup`` 47%, while
    every attack family lost under 20%. Dropping them afterwards left the
    benign side quietly easier than it was designed to be, and every
    false-positive rate measured on it correspondingly quietly better.
    """
    seen: set[str] = set(exclude)
    records: list[Sample] = []
    requested = 0
    collisions = 0

    for family in attacks.families_for(plan.families):
        rng = random.Random(f"{plan.seed}:attack:{family.name}")  # noqa: S311  # nosec B311
        requested += plan.attacks_per_family
        drawn, hit = _draw(family.build, rng, plan.attacks_per_family, seen)
        collisions += hit
        records.extend(
            Sample(
                sample_id=f"a-{family.name}-{index:05d}",
                text=text,
                label="attack",
                family=family.name,
                meta={"plan": plan.name},
            )
            for index, text in enumerate(drawn)
        )

    quota = _benign_quota(plan.benign_total, benign.KINDS)
    for kind in benign.KINDS:
        rng = random.Random(f"{plan.seed}:benign:{kind.name}")  # noqa: S311  # nosec B311
        requested += quota[kind.name]
        drawn, hit = _draw(kind.build, rng, quota[kind.name], seen)
        collisions += hit
        records.extend(
            Sample(
                sample_id=f"b-{kind.name}-{index:05d}",
                text=text,
                label="benign",
                kind=kind.name,
                meta={"plan": plan.name, "hard": kind.hard},
            )
            for index, text in enumerate(drawn)
        )

    return Generation(corpus=build_corpus(records), requested=requested, collisions=collisions)


def plan_named(name: str) -> Plan:
    """Look up a shipped plan, listing the alternatives when there is no match."""
    try:
        return PLANS[name]
    except KeyError:
        known = ", ".join(sorted(PLANS))
        raise ConfigError(
            f"no plan named {name!r}",
            remedy=f"Known plans: {known}.",
        ) from None
