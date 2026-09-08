"""The three report formats, and that they carry the same numbers."""

from __future__ import annotations

import json
from dataclasses import replace
from xml.etree import ElementTree

import pytest

from pifw.corpus.build import PLANS, generate
from pifw.evaluate import lofo
from pifw.evaluate.report import to_json, to_junit, to_markdown, write_reports
from pifw.model.logistic import TrainConfig

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def evaluation():
    train = generate(PLANS["tiny"]).corpus
    holdout = generate(
        replace(PLANS["tiny"], seed=4099),
        exclude=frozenset(record.text for record in train),
    ).corpus
    return lofo.run(
        train,
        holdout,
        families=("direct_override", "encoding_wrapper"),
        config=TrainConfig(max_iterations=2000),
    )


class TestJson:
    def test_is_valid_and_carries_the_headline(self, evaluation):
        payload = json.loads(to_json(evaluation))
        assert payload["pooled_bypass_rate"] == pytest.approx(evaluation.pooled_bypass.point)
        assert payload["random_split_bypass_rate"] == pytest.approx(evaluation.control.bypass.point)
        assert payload["optimism_gap"] == pytest.approx(evaluation.optimism_gap)
        assert len(payload["folds"]) == 2

    def test_every_fold_records_what_it_disabled(self, evaluation):
        for fold in json.loads(to_json(evaluation))["folds"]:
            disabled = fold["disabled"]
            assert disabled["rules"] or disabled["stages"] or disabled["signals"]

    def test_it_is_stable_across_calls(self, evaluation):
        assert to_json(evaluation) == to_json(evaluation)


class TestMarkdown:
    def test_the_uncomfortable_number_comes_first(self, evaluation):
        body = to_markdown(evaluation)
        unseen = body.index("Unseen technique")
        seen = body.index("Seen technique")
        assert unseen < seen

    def test_it_shows_thresholds_rather_than_claiming_they_match(self, evaluation):
        body = to_markdown(evaluation)
        assert "share a **budget**, not a threshold" in body
        assert f"{evaluation.control.threshold:.3f}" in body

    def test_every_family_appears(self, evaluation):
        body = to_markdown(evaluation)
        for fold in evaluation.folds:
            assert f"`{fold.family}`" in body

    def test_the_per_layer_table_names_every_layer(self, evaluation):
        body = to_markdown(evaluation)
        for layer in lofo.LAYERS:
            assert f"`{layer}`" in body


class TestJunit:
    def test_a_passing_run_has_no_failures(self, evaluation):
        suite = ElementTree.fromstring(to_junit(evaluation, max_family_bypass=1.0))
        assert suite.get("failures") == "0"
        assert len(suite.findall("testcase")) == len(evaluation.folds)

    def test_an_over_budget_family_becomes_a_failing_case(self, evaluation):
        # The reason JUnit is here: a failing fold shows up in a pull request as
        # a named case rather than a line in a log somebody has to open.
        suite = ElementTree.fromstring(to_junit(evaluation, max_family_bypass=-0.01))
        assert int(suite.get("failures") or 0) == len(evaluation.folds)
        failure = suite.find("testcase/failure")
        assert failure is not None
        assert failure.get("type") == "BypassRateExceeded"
        assert "got" in (failure.get("message") or "")

    def test_the_failure_body_names_what_the_fold_removed(self, evaluation):
        suite = ElementTree.fromstring(to_junit(evaluation, max_family_bypass=-0.01))
        bodies = [element.text or "" for element in suite.findall("testcase/failure")]
        assert any("rules disabled" in body for body in bodies)


class TestWriting:
    def test_writes_only_what_it_is_asked_for(self, evaluation, tmp_path):
        written = write_reports(
            evaluation,
            json_out=tmp_path / "e.json",
            markdown_out=None,
            junit_out=tmp_path / "e.xml",
            max_family_bypass=1.0,
        )
        assert {path.name for path in written} == {"e.json", "e.xml"}
        assert not (tmp_path / "e.md").exists()

    def test_creates_missing_directories(self, evaluation, tmp_path):
        target = tmp_path / "reports" / "nested" / "e.json"
        write_reports(evaluation, json_out=target, max_family_bypass=1.0)
        assert target.exists()

    def test_nothing_asked_for_writes_nothing(self, evaluation):
        assert write_reports(evaluation, max_family_bypass=1.0) == []
