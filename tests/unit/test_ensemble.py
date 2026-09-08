"""Combining evidence, deciding, and calibrating a threshold to a budget."""

from __future__ import annotations

import numpy as np
import pytest

from pifw.detect.ensemble import (
    RULE_RELIABILITY,
    SIGNAL_RELIABILITY,
    Detector,
    Thresholds,
    decision_score,
    noisy_or,
    threshold_at_fpr,
)

pytestmark = pytest.mark.unit


class TestNoisyOr:
    def test_bounded_by_one(self):
        # Twenty rules at 0.9 leave 1e-20 of doubt, which float64 rounds away.
        # Saturating at exactly one is correct; exceeding it would not be, and
        # a sum would.
        assert noisy_or([0.9] * 20) == 1.0
        assert noisy_or([0.6] * 4) < 1.0

    def test_order_free(self):
        assert noisy_or([0.2, 0.7, 0.4]) == pytest.approx(noisy_or([0.7, 0.4, 0.2]))

    def test_monotone(self):
        assert noisy_or([0.5]) < noisy_or([0.5, 0.1])

    def test_no_evidence_is_zero(self):
        assert noisy_or([]) == 0.0

    def test_certainty_saturates(self):
        assert noisy_or([1.0, 0.3]) == 1.0

    def test_three_weak_rules_do_not_become_a_sum(self):
        # The property that made noisy-OR the choice. Three rules at 0.3 each
        # summing would reach 0.9; as independent evidence they reach 0.657.
        assert noisy_or([0.3, 0.3, 0.3]) == pytest.approx(0.657)


class TestThresholds:
    def test_block_below_flag_is_refused(self):
        with pytest.raises(ValueError, match="cannot be below"):
            Thresholds(flag=0.8, block=0.2)

    def test_out_of_range_is_refused(self):
        with pytest.raises(ValueError, match=r"\[0, 1\]"):
            Thresholds(flag=1.5)


class TestDecide:
    def test_monitor_mode_never_blocks(self):
        # A mode that a threshold can override is not a mode.
        detector = Detector(mode="monitor", thresholds=Thresholds(flag=0.1, block=0.2))
        assert detector.decide(0.99) == "flag"

    def test_enforce_mode_blocks_above_the_block_threshold(self):
        detector = Detector(mode="enforce", thresholds=Thresholds(flag=0.1, block=0.2))
        assert detector.decide(0.99) == "block"
        assert detector.decide(0.15) == "flag"
        assert detector.decide(0.05) == "allow"

    def test_the_boundary_is_inclusive(self):
        detector = Detector(thresholds=Thresholds(flag=0.5))
        assert detector.decide(0.5) == "flag"


class TestCalibration:
    def test_a_budget_is_respected(self):
        scores = np.linspace(0.0, 1.0, 1000)
        threshold = threshold_at_fpr(scores, 0.01)
        assert np.count_nonzero(scores >= threshold) <= 10

    def test_ties_at_the_boundary_come_in_under_budget_not_over(self):
        # Three hundred identical scores at the top and a 1% budget: the
        # quantile lands inside the tie, and flagging *at* it would flag 30% of
        # the corpus. The threshold has to step above the tie.
        scores = np.concatenate([np.full(300, 0.8), np.zeros(700)])
        threshold = threshold_at_fpr(scores, 0.01)
        assert np.count_nonzero(scores >= threshold) == 0

    def test_a_budget_of_one_flags_everything(self):
        scores = np.linspace(0.1, 1.0, 50)
        assert np.count_nonzero(scores >= threshold_at_fpr(scores, 1.0)) == 50

    def test_no_benign_scores_is_an_error_not_a_guess(self):
        with pytest.raises(ValueError, match="without benign scores"):
            threshold_at_fpr(np.array([]), 0.01)

    def test_an_impossible_budget_is_refused(self):
        with pytest.raises(ValueError, match=r"\[0, 1\]"):
            threshold_at_fpr(np.array([0.5]), 1.5)


class TestDecisionScore:
    """Which layer the firewall acts on, and why it is only one of them.

    The noisy-OR of all three layers measures *worse* against unseen techniques
    than the learned layer alone -- 20.89% pooled bypass against 2.08%, at a
    matched realised false-positive rate. These tests pin the resulting
    contract, because it is the kind of decision a later refactor would
    helpfully undo.
    """

    def test_with_a_model_the_score_is_the_model(self):
        # Not "close to" the model: equal to it. If the rule and structural
        # layers re-enter the score by any amount, they re-enter the threshold
        # too, and the ensemble result comes back with them.
        assert decision_score(0.99, 0.99, 0.42, has_model=True) == 0.42

    def test_the_evidence_layers_cannot_move_the_score(self):
        loud = decision_score(1.0, 1.0, 0.3, has_model=True)
        silent = decision_score(0.0, 0.0, 0.3, has_model=True)
        assert loud == silent == 0.3

    def test_without_a_model_it_falls_back_to_the_other_layers(self):
        assert decision_score(0.4, 0.2, 0.0, has_model=False) == pytest.approx(
            noisy_or((0.4 * RULE_RELIABILITY, 0.2 * SIGNAL_RELIABILITY))
        )

    def test_the_fallback_ignores_a_model_score_it_was_told_not_to_have(self):
        # has_model is the authority, not the value. A caller that passes a
        # stale model score with has_model=False gets the fallback, rather than
        # a silent third behaviour that appears only when both disagree.
        assert decision_score(0.4, 0.2, 0.9, has_model=False) == decision_score(
            0.4, 0.2, 0.0, has_model=False
        )

    def test_the_verdict_score_is_the_model_layer(self, trained_detector, obvious_attack):
        verdict = trained_detector.inspect(obvious_attack)
        assert verdict.score == verdict.layers["model"] == verdict.layers["decision"]

    def test_the_rejected_ensemble_is_still_reported(self, trained_detector, obvious_attack):
        # The finding should stay falsifiable by whoever deploys this, rather
        # than resting on a table in a README, so the combination this project
        # rejected keeps being computed and recorded next to the one it ships.
        layers = trained_detector.inspect(obvious_attack).layers
        assert "combined" in layers
        assert layers["combined"] >= layers["model"] - 1e-12

    def test_the_evidence_survives_being_dropped_from_the_score(
        self, trained_detector, obvious_attack
    ):
        # Rules earn their place as explanation. If dropping them from the score
        # had also dropped them from the verdict, the trade would have been a
        # loss rather than a reallocation.
        assert "override.verb_scope" in trained_detector.inspect(obvious_attack).reasons


class TestInspect:
    def test_an_obvious_payload_outscores_ordinary_traffic(
        self, bare_detector, obvious_attack, obvious_benign
    ):
        assert (
            bare_detector.inspect(obvious_attack).score
            > bare_detector.inspect(obvious_benign).score
        )

    def test_the_verdict_names_its_evidence(self, bare_detector, obvious_attack):
        verdict = bare_detector.inspect(obvious_attack)
        assert verdict.reasons
        assert "override.verb_scope" in verdict.reasons
        assert verdict.explain().startswith(verdict.decision)

    def test_every_layer_is_reported(self, trained_detector, obvious_attack):
        layers = trained_detector.inspect(obvious_attack).layers
        assert set(layers) == {"rules", "signals", "model", "combined", "decision"}
        assert all(0.0 <= value <= 1.0 for value in layers.values())

    def test_without_a_model_the_learned_layer_is_zero(self, bare_detector, obvious_attack):
        assert bare_detector.inspect(obvious_attack).layers["model"] == 0.0

    def test_batch_scoring_agrees_with_single_scoring(self, trained_detector, tiny_corpus):
        texts = [record.text for record in tiny_corpus.records[:40]]
        batched = trained_detector.scores(texts)["decision"]
        single = np.array([trained_detector.inspect(text).score for text in texts])
        np.testing.assert_allclose(batched, single, rtol=1e-12)

    def test_with_fold_disables_all_three_layers_countermeasures(self, bare_detector):
        folded = bare_detector.with_fold("homoglyph")
        assert folded.disabled_stages == frozenset({"nfkc", "zero_width", "confusables"})
        assert folded.disabled_signals
        assert bare_detector.with_fold(None).disabled_stages == frozenset()
