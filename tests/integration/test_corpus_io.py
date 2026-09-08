"""Corpora on disk: round trips, digests, gzip, and the refusals."""

from __future__ import annotations

import gzip
import json

import pytest

from pifw.corpus.build import PLANS, generate, plan_named
from pifw.errors import ConfigError, CorpusError
from pifw.sample import MAX_CORPUS_BYTES, Sample, build_corpus, read_corpus

pytestmark = pytest.mark.integration


class TestRoundTrip:
    def test_plain_jsonl(self, tiny_corpus, tmp_path):
        path = tiny_corpus.write(tmp_path / "corpus.jsonl")
        assert read_corpus(path).digest() == tiny_corpus.digest()

    def test_gzip_by_suffix(self, tiny_corpus, tmp_path):
        path = tiny_corpus.write(tmp_path / "corpus.jsonl.gz")
        assert path.read_bytes()[:2] == b"\x1f\x8b"
        assert read_corpus(path).digest() == tiny_corpus.digest()

    def test_gzip_is_smaller(self, tiny_corpus, tmp_path):
        plain = tiny_corpus.write(tmp_path / "a.jsonl").stat().st_size
        packed = tiny_corpus.write(tmp_path / "a.jsonl.gz").stat().st_size
        assert packed < plain

    def test_the_bytes_do_not_depend_on_when_they_were_written(self, tiny_corpus, tmp_path):
        # mtime=0 in the gzip header. Without it the same corpus written twice
        # has different bytes, and the committed digest cannot be checked.
        first = tiny_corpus.write(tmp_path / "a.jsonl.gz").read_bytes()
        second = tiny_corpus.write(tmp_path / "b.jsonl.gz").read_bytes()
        assert first == second


class TestDeterminism:
    def test_the_same_plan_gives_the_same_digest(self):
        assert generate(PLANS["tiny"]).corpus.digest() == generate(PLANS["tiny"]).corpus.digest()

    def test_a_different_seed_gives_a_different_corpus(self):
        from dataclasses import replace

        other = replace(PLANS["tiny"], seed=PLANS["tiny"].seed + 1)
        assert generate(other).corpus.digest() != generate(PLANS["tiny"]).corpus.digest()

    def test_exclusion_makes_the_second_corpus_disjoint(self):
        from dataclasses import replace

        first = generate(PLANS["tiny"]).corpus
        second = generate(
            replace(PLANS["tiny"], seed=99),
            exclude=frozenset(record.text for record in first),
        ).corpus
        assert not ({r.text for r in first} & {r.text for r in second})

    def test_without_exclusion_the_two_do_overlap(self):
        # The measurement that made exclusion necessary. Two seeded walks over
        # the same grammar are not disjoint, and hoping they are is how an
        # evaluation set quietly becomes training data.
        #
        # Sized so the effect is reliable rather than lucky: the smaller benign
        # kinds have a few thousand distinct outputs, so two corpora each taking
        # a hundred-odd samples from one of them collide by the birthday
        # argument. At the `tiny` plan's scale they do not, which is why this
        # test builds its own plan instead of reusing that fixture.
        from dataclasses import replace

        plan = replace(PLANS["tiny"], attacks_per_family=5, benign_total=2400)
        first = generate(plan).corpus
        second = generate(replace(plan, seed=99)).corpus
        overlap = {r.text for r in first} & {r.text for r in second}
        assert overlap, "if this ever passes, the grammars grew and exclusion got cheaper"


class TestRefusals:
    def test_a_missing_corpus_says_how_to_make_one(self, tmp_path):
        with pytest.raises(CorpusError, match="no corpus at") as caught:
            read_corpus(tmp_path / "absent.jsonl")
        assert "pifw synth" in caught.value.remedy

    def test_a_bad_line_names_its_line_number(self, tmp_path):
        path = tmp_path / "corpus.jsonl"
        path.write_text('{"sample_id": "a", "text": "x", "label": "attack", "family": "f"}\n{\n')
        with pytest.raises(CorpusError, match=r"corpus\.jsonl:2"):
            read_corpus(path)

    def test_an_empty_corpus_is_refused(self, tmp_path):
        path = tmp_path / "corpus.jsonl"
        path.write_text("\n\n")
        with pytest.raises(CorpusError, match="no samples"):
            read_corpus(path)

    def test_duplicate_ids_are_refused(self):
        record = Sample(sample_id="a", text="x", label="attack", family="direct_override")
        with pytest.raises(ValueError, match="duplicate sample_id"):
            build_corpus([record, record])

    def test_an_attack_without_a_family_is_refused(self):
        with pytest.raises(ValueError, match="must name the family"):
            Sample(sample_id="a", text="x", label="attack")

    def test_a_benign_sample_carrying_a_family_is_refused(self):
        # A benign sample with no kind is rejected for the missing kind first,
        # so this supplies one: the point under test is that the two taxonomies
        # do not mix, not that `kind` is required.
        with pytest.raises(ValueError, match="has a kind, not a family"):
            Sample(
                sample_id="a",
                text="x",
                label="benign",
                kind="ordinary",
                family="direct_override",
            )

    def test_an_unknown_plan_lists_the_known_ones(self):
        with pytest.raises(ConfigError, match="no plan named") as caught:
            plan_named("nonexistent")
        assert "main" in caught.value.remedy

    def test_a_decompression_bomb_is_refused(self, tmp_path):
        # The guard has to be on the decompressed stream: the size on disk and
        # the size declared in the gzip trailer are both the writer's choice.
        path = tmp_path / "bomb.jsonl.gz"
        line = json.dumps(
            {
                "sample_id": "a",
                "text": "x" * 10_000,
                "label": "benign",
                "kind": "ordinary",
                "meta": {},
            }
        )
        with gzip.open(path, "wt", encoding="utf-8") as sink:
            for _ in range((MAX_CORPUS_BYTES // 10_000) + 20):
                sink.write(line + "\n")
        assert path.stat().st_size < MAX_CORPUS_BYTES
        with pytest.raises(CorpusError, match="expands past"):
            read_corpus(path)


class TestShippedCorpora:
    def test_they_match_their_plans(self, repo_root):
        for plan, name, exclude_from in (
            ("main", "corpus.jsonl.gz", None),
            ("holdout", "holdout.jsonl.gz", "corpus.jsonl.gz"),
        ):
            path = repo_root / "examples" / name
            if not path.exists():
                pytest.skip(f"{name} has not been generated in this checkout")
            exclude = (
                frozenset(r.text for r in read_corpus(repo_root / "examples" / exclude_from))
                if exclude_from
                else frozenset()
            )
            rebuilt = generate(plan_named(plan), exclude=exclude).corpus
            assert read_corpus(path).digest() == rebuilt.digest(), name

    def test_the_two_shipped_corpora_are_disjoint(self, repo_root):
        main = repo_root / "examples" / "corpus.jsonl.gz"
        holdout = repo_root / "examples" / "holdout.jsonl.gz"
        if not (main.exists() and holdout.exists()):
            pytest.skip("corpora have not been generated in this checkout")
        assert not ({r.text for r in read_corpus(main)} & {r.text for r in read_corpus(holdout)})
