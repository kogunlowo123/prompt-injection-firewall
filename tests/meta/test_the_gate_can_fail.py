"""Negative controls for the gates themselves.

A gate that has only ever been observed passing is indistinguishable from
``true`` in a shell script. Each test here breaks exactly one thing and asserts
the corresponding gate goes red — and, where it matters, that a *control* with
nothing broken goes green, because a gate that fails on everything is no better
than one that passes on everything.

Two of these guard mistakes this project actually made:

* an unconverged model was reported as a 40% bypass rate with nothing in the
  output distinguishing it from a measurement;
* an evaluation corpus that shared text with training was scored anyway.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from pifw.corpus.build import PLANS, generate
from pifw.errors import GateError, RefusalError
from pifw.evaluate import lofo
from pifw.evaluate.baseline import Baseline, enforce
from pifw.model.logistic import TrainConfig

pytestmark = pytest.mark.meta

FOLDS = ("direct_override", "indirect")


@pytest.fixture(scope="module")
def corpora():
    train = generate(PLANS["tiny"]).corpus
    holdout = generate(
        replace(PLANS["tiny"], seed=8191),
        exclude=frozenset(record.text for record in train),
    ).corpus
    return train, holdout


@pytest.fixture(scope="module")
def evaluation(corpora):
    train, holdout = corpora
    return lofo.run(train, holdout, families=FOLDS, config=TrainConfig(max_iterations=2000))


class TestTheHarnessRefuses:
    def test_the_control_runs_at_all(self, evaluation):
        # Without this every refusal below could be the harness being broken.
        assert len(evaluation.folds) == len(FOLDS)
        assert 0.0 <= evaluation.pooled_bypass.point <= 1.0

    def test_it_refuses_when_the_corpora_overlap(self, corpora):
        train, _ = corpora
        with pytest.raises(RefusalError, match="share") as caught:
            lofo.run(train, train, families=FOLDS, config=TrainConfig(max_iterations=200))
        assert "drop_shared" in caught.value.remedy

    def test_drop_shared_is_an_explicit_opt_in_that_reports_the_count(self, corpora):
        # A *partial* overlap, not a total one: passing the training corpus as
        # its own evaluation set leaves nothing to calibrate on once the
        # overlap is dropped, which is a different failure.
        train, holdout = corpora
        from pifw.sample import build_corpus

        polluted = build_corpus(
            [
                *holdout.records,
                *(
                    record.model_copy(update={"sample_id": f"leaked-{index:04d}"})
                    for index, record in enumerate(train.records[:20])
                ),
            ]
        )
        result = lofo.run(
            train,
            polluted,
            families=("direct_override",),
            drop_shared=True,
            config=TrainConfig(max_iterations=2000),
        )
        assert result.dropped_shared == 20

    def test_it_refuses_a_model_that_did_not_converge(self, corpora):
        # The failure that produced a 40% headline. An undertrained model still
        # scores; nothing about its output says the number is about the
        # optimiser rather than the firewall.
        train, holdout = corpora
        with pytest.raises(RefusalError, match="without reaching its gradient tolerance"):
            lofo.run(
                train,
                holdout,
                families=("direct_override",),
                config=TrainConfig(max_iterations=3),
            )

    def test_it_refuses_a_family_the_training_corpus_lacks(self, corpora):
        _train, holdout = corpora
        smaller = generate(
            replace(PLANS["tiny"], families=("direct_override", "indirect")),
        ).corpus
        with pytest.raises(RefusalError, match="no attacks from"):
            lofo.run(
                smaller,
                holdout,
                families=("homoglyph",),
                config=TrainConfig(max_iterations=200),
            )


class TestTheBaselineGateFires:
    def test_an_unchanged_run_passes(self, evaluation):
        # The control for this whole class.
        assert enforce(evaluation, Baseline.from_evaluation(evaluation)) == []

    def test_a_worse_pooled_rate_fails(self, evaluation):
        recorded = Baseline.from_evaluation(evaluation)
        stricter = replace(recorded, pooled_bypass=max(0.0, recorded.pooled_bypass - 0.5))
        with pytest.raises(GateError, match="pooled bypass rate rose"):
            enforce(evaluation, stricter)

    def test_a_worse_family_fails_even_when_the_pool_is_fine(self, evaluation):
        # Eleven families at 2% and one at 90% pools to about 10%. The per-family
        # check is what stops the pool hiding the one that matters.
        recorded = Baseline.from_evaluation(evaluation)
        family = FOLDS[0]
        stricter = replace(
            recorded,
            pooled_bypass=1.0,
            family_bypass={**recorded.family_bypass, family: 0.0},
        )
        measured = next(f for f in evaluation.folds if f.family == family)
        if measured.bypass.point <= 0.05:
            pytest.skip("this fold already bypasses at zero, so it cannot be made worse")
        with pytest.raises(GateError, match=f"family '{family}' regressed"):
            enforce(evaluation, stricter)

    def test_a_family_missing_from_the_baseline_fails(self, evaluation):
        recorded = Baseline.from_evaluation(evaluation)
        without = replace(recorded, family_bypass={FOLDS[0]: recorded.family_bypass[FOLDS[0]]})
        with pytest.raises(GateError, match="not in the baseline"):
            enforce(evaluation, without)

    def test_a_fold_that_stopped_running_fails(self, evaluation):
        # A gate that stops gating is worse than a gate that fails: it is
        # indistinguishable from one that passed.
        recorded = Baseline.from_evaluation(evaluation)
        extra = replace(
            recorded,
            family_bypass={**recorded.family_bypass, "a_family_nobody_ran": 0.0},
        )
        with pytest.raises(GateError, match="did not measure"):
            enforce(evaluation, extra)

    def test_a_degraded_control_fails(self, evaluation):
        recorded = Baseline.from_evaluation(evaluation)
        if evaluation.control.bypass.point <= 0.05:
            stricter = replace(recorded, control_bypass=0.0)
            # The measured control is at or near zero, so it cannot regress
            # against its own recording. Push the recording below zero-minus-
            # tolerance by asserting through the other direction instead.
            with pytest.raises(GateError, match="random-split control regressed"):
                enforce(evaluation, replace(stricter, control_bypass=-0.5))
        else:
            with pytest.raises(GateError, match="random-split control regressed"):
                enforce(evaluation, replace(recorded, control_bypass=0.0))

    def test_a_false_positive_budget_can_fail(self, evaluation):
        # Fabricated rather than measured. On a corpus this small the measured
        # false-positive rate is legitimately zero, and a test that can only
        # fire when the fixture happens to be noisy is a test that reports the
        # fixture. The gate's arithmetic is what is under examination here.
        from dataclasses import replace as replace_field

        from pifw.evaluate.metrics import Confusion

        noisy = replace_field(
            evaluation,
            folds=(
                replace_field(
                    evaluation.folds[0],
                    confusion=Confusion(
                        true_positive=90,
                        false_negative=10,
                        false_positive=20,
                        true_negative=80,
                    ),
                ),
            ),
        )
        with pytest.raises(GateError, match="exceeds the"):
            enforce(
                noisy,
                Baseline.from_evaluation(noisy),
                max_false_positive_rate=0.05,
            )

    def test_comparing_across_budgets_is_refused(self, evaluation):
        # Bypass rates at different false-positive budgets are not comparable,
        # and silently comparing them is how a gate turns into decoration.
        recorded = replace(Baseline.from_evaluation(evaluation), target_fpr=0.05)
        with pytest.raises(GateError, match="budget"):
            enforce(evaluation, recorded)

    def test_an_improvement_is_reported_rather_than_ignored(self, evaluation):
        recorded = replace(
            Baseline.from_evaluation(evaluation),
            pooled_bypass=min(1.0, evaluation.pooled_bypass.point + 0.5),
        )
        improvements = enforce(evaluation, recorded)
        assert any("pooled bypass rate fell" in line for line in improvements)


class TestTheCountermeasuresAreLoadBearing:
    def test_a_fold_actually_removes_something(self, evaluation):
        # If a fold disabled nothing, its result would be identical to the
        # random-split control and the whole comparison would be vacuous.
        for fold in evaluation.folds:
            removed = fold.disabled_rules + fold.disabled_stages + fold.disabled_signals
            assert removed, f"{fold.family} removed no countermeasure"

    def test_the_control_removes_nothing(self, evaluation):
        control = evaluation.control
        assert not (control.disabled_rules + control.disabled_stages + control.disabled_signals)
