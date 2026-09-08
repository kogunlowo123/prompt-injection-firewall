"""Counting, intervals, and the ordering conventions the whole project depends on."""

from __future__ import annotations

import numpy as np
import pytest

from pifw.evaluate import metrics

pytestmark = pytest.mark.unit


class TestWilson:
    def test_zero_out_of_a_hundred_is_not_zero(self):
        # The reason the intervals are here at all. A fold that misses nothing
        # has not proved the bypass rate is zero; it has bounded it.
        interval = metrics.wilson(0, 100)
        assert interval.point == 0.0
        assert interval.low == 0.0
        assert 0.02 < interval.high < 0.05

    def test_all_out_of_a_hundred_is_not_one(self):
        interval = metrics.wilson(100, 100)
        assert interval.point == 1.0
        assert interval.high == 1.0
        assert 0.95 < interval.low < 0.99

    def test_the_interval_narrows_with_more_data(self):
        small = metrics.wilson(5, 50)
        large = metrics.wilson(100, 1000)
        assert small.point == pytest.approx(large.point)
        assert (small.high - small.low) > (large.high - large.low)

    def test_the_point_estimate_is_inside_its_own_interval(self):
        for successes in range(0, 41):
            interval = metrics.wilson(successes, 40)
            assert interval.low <= interval.point <= interval.high

    def test_no_data_is_reported_as_total_ignorance(self):
        interval = metrics.wilson(0, 0)
        assert (interval.low, interval.high) == (0.0, 1.0)

    def test_impossible_counts_are_refused(self):
        with pytest.raises(ValueError, match="not a proportion"):
            metrics.wilson(11, 10)


class TestConfusion:
    def test_the_flagging_comparison_is_inclusive(self):
        # This has to match Detector.decide. A metric computed with `>` while
        # the deployed path uses `>=` differs by exactly the samples sitting on
        # the boundary — and the threshold is calibrated *to* a boundary.
        counts = metrics.confusion(np.array([0.5]), np.array([0.5]), 0.5)
        assert counts.true_positive == 1
        assert counts.false_positive == 1

    def test_bypass_and_recall_are_complements(self):
        counts = metrics.confusion(np.array([0.9, 0.8, 0.1, 0.05]), np.array([0.0, 0.1]), 0.5)
        assert counts.bypass.point == pytest.approx(1 - counts.recall.point)
        assert counts.false_negative == 2

    def test_precision_with_nothing_flagged_is_zero_not_an_error(self):
        counts = metrics.confusion(np.array([0.1]), np.array([0.1]), 0.9)
        assert counts.precision == 0.0


class TestGrouping:
    def test_bypass_is_reported_per_group(self):
        scores = np.array([0.9, 0.1, 0.9, 0.9])
        groups = ["a", "a", "b", "b"]
        result = metrics.bypass_by_group(scores, groups, 0.5)
        assert result["a"].point == 0.5
        assert result["b"].point == 0.0

    def test_flag_rate_is_the_other_side_of_the_same_count(self):
        scores = np.array([0.9, 0.1])
        groups = ["a", "a"]
        bypass = metrics.bypass_by_group(scores, groups, 0.5)["a"]
        flagged = metrics.flag_rate_by_group(scores, groups, 0.5)["a"]
        assert bypass.point + flagged.point == pytest.approx(1.0)


class TestAuc:
    def test_perfect_separation(self):
        assert metrics.roc_auc(np.array([0.9, 0.8]), np.array([0.1, 0.2])) == 1.0

    def test_reversed_separation(self):
        assert metrics.roc_auc(np.array([0.1, 0.2]), np.array([0.9, 0.8])) == 0.0

    def test_all_ties_is_a_coin_flip(self):
        # The case a naive rank-sum gets wrong. A detector that gives every
        # message the same score has no discriminative power, and 0.5 is the
        # only honest answer.
        assert metrics.roc_auc(np.ones(10), np.ones(10)) == pytest.approx(0.5)

    def test_partial_ties_land_between(self):
        auc = metrics.roc_auc(np.array([1.0, 0.5]), np.array([0.5, 0.0]))
        assert 0.5 < auc < 1.0

    def test_empty_input_is_zero_rather_than_an_exception(self):
        assert metrics.roc_auc(np.array([]), np.array([1.0])) == 0.0
