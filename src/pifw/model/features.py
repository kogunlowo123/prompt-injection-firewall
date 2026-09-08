"""Hashed n-gram features, in a form that is the same on every machine.

Two decisions here are about reproducibility rather than accuracy.

**The hash is BLAKE2b, not Python's :func:`hash`.** ``hash("ignore")`` is salted
per process by default, so a model trained in one interpreter and loaded in
another indexes different buckets and produces different scores from the same
weights. Nothing crashes. The accuracy just quietly drops, in a way that
reproduces on no machine and looks like a bad model rather than a bad hash.
BLAKE2b is in the standard library, is specified rather than implementation-
defined, and — unlike the FNV-1a loop this started as — runs in C, which matters
when the evaluation featurises the corpus several times over.

**The vocabulary is a fixed number of buckets, not a fitted dictionary.** A
fitted vocabulary has to be shipped, versioned and matched to the weights, and a
mismatch is the same silent failure as above. Hashing trades a little accuracy
from collisions for a featuriser that is fully described by three integers.

The sign trick — a second bit of the same hash decides whether a feature adds or
subtracts — makes collisions cancel in expectation instead of accumulating.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

import numpy as np

#: 2^14 buckets for a few thousand samples. Larger is not better: with 16,384
#: buckets and roughly 30,000 distinct n-grams the collision rate is already
#: what the sign trick is there to absorb, and a wider space mostly adds
#: parameters that see one example each.
DEFAULT_BUCKETS = 1 << 14

DEFAULT_CHAR_GRAM = 4

_TOKEN_RE = re.compile(r"[^\W\d_]+|\d+|[^\s\w]", re.UNICODE)


def stable_hash(text: str) -> int:
    """64 bits of BLAKE2b over the UTF-8 bytes.

    Stable across processes, interpreters, platforms and releases. Not a
    security property here — nothing is authenticated by it — but a
    reproducibility one: the bucket a token lands in has to be the same
    tomorrow as it was when the weights were fitted.
    """
    return int.from_bytes(
        hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(),
        "big",
    )


def tokenize(text: str) -> list[str]:
    """Words, numbers and single punctuation marks.

    Punctuation is kept as its own token because several families are partly
    punctuation: ``</system>`` and ``<|im_end|>`` are not words, and a tokeniser
    that drops them hands the delimiter family a free pass.
    """
    return _TOKEN_RE.findall(text.lower())


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    """Everything needed to reproduce the featuriser, as three numbers."""

    buckets: int = DEFAULT_BUCKETS
    char_gram: int = DEFAULT_CHAR_GRAM
    word_gram: int = 2

    def to_dict(self) -> dict[str, int]:
        """The spec as plain JSON, to be stored beside the weights."""
        return {
            "buckets": self.buckets,
            "char_gram": self.char_gram,
            "word_gram": self.word_gram,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> FeatureSpec:
        """Rebuild a spec from what was stored."""
        return cls(
            buckets=int(data["buckets"]),
            char_gram=int(data["char_gram"]),
            word_gram=int(data["word_gram"]),
        )


def features_of(text: str, spec: FeatureSpec) -> dict[int, float]:
    """The hashed feature counts for one message.

    Word n-grams up to ``word_gram`` catch phrasing; character n-grams catch the
    pieces of a word that survived an obfuscation the normaliser did not undo,
    which is the only reason the learned layer has any purchase at all on a
    family whose countermeasure has been switched off.
    """
    counts: dict[int, float] = {}
    tokens = tokenize(text)

    def add(key: str) -> None:
        digest = stable_hash(key)
        index = digest % spec.buckets
        sign = 1.0 if (digest >> 63) & 1 else -1.0
        counts[index] = counts.get(index, 0.0) + sign

    for size in range(1, spec.word_gram + 1):
        for start in range(len(tokens) - size + 1):
            add("w{}:{}".format(size, " ".join(tokens[start : start + size])))

    padded = f" {' '.join(tokens)} "
    width = spec.char_gram
    for start in range(len(padded) - width + 1):
        add(f"c:{padded[start : start + width]}")

    return counts


@dataclass(frozen=True, slots=True)
class Matrix:
    """A sparse design matrix in compressed-row form.

    Written out rather than pulled from scipy: three integer arrays and a float
    array are the whole data structure, the two operations the training loop
    needs are four lines each, and adding a 40 MB dependency to avoid writing
    them would be the largest thing in this project's dependency tree.
    """

    indptr: np.ndarray
    indices: np.ndarray
    data: np.ndarray
    buckets: int

    @property
    def rows(self) -> int:
        """How many samples."""
        return int(self.indptr.size - 1)

    def dot(self, weights: np.ndarray) -> np.ndarray:
        """``X @ w`` for every row."""
        if self.indices.size == 0:
            return np.zeros(self.rows, dtype=np.float64)
        contributions = self.data * weights[self.indices]
        lengths = np.diff(self.indptr)
        out = np.zeros(self.rows, dtype=np.float64)
        nonempty = lengths > 0
        if nonempty.any():
            sums = np.add.reduceat(contributions, self.indptr[:-1][nonempty])
            out[nonempty] = sums
        return out

    def select(self, rows: np.ndarray) -> Matrix:
        """The sub-matrix for the given row indices, in the order given.

        This exists so the leave-one-family-out harness can featurise the
        corpus once and then take twelve views of it. Featurising per fold was
        the first implementation and it spent about nine tenths of the
        evaluation's runtime recomputing identical hashes.
        """
        starts = self.indptr[rows]
        lengths = np.diff(self.indptr)[rows]
        offsets = np.zeros(rows.size + 1, dtype=np.int64)
        np.cumsum(lengths, out=offsets[1:])
        # For output position j inside row i the source index is
        # starts[i] + (j - offsets[i]), so one repeat and one arange gather the
        # whole sub-matrix without a Python-level loop over rows.
        shift = np.repeat(starts - offsets[:-1], lengths)
        picks = shift + np.arange(int(offsets[-1]), dtype=np.int64)
        return Matrix(
            indptr=offsets,
            indices=self.indices[picks],
            data=self.data[picks],
            buckets=self.buckets,
        )

    def transpose_dot(self, residual: np.ndarray) -> np.ndarray:
        """``X.T @ r``, accumulated into the bucket space."""
        if self.indices.size == 0:
            return np.zeros(self.buckets, dtype=np.float64)
        lengths = np.diff(self.indptr)
        spread = np.repeat(residual, lengths)
        return np.bincount(self.indices, weights=self.data * spread, minlength=self.buckets)


def build_matrix(texts: list[str], spec: FeatureSpec) -> Matrix:
    """Featurise a list of messages into one sparse matrix.

    Rows are L2-normalised. Without it a long document contributes a gradient
    proportional to its length, and the ``indirect`` family — which is a whole
    document — would dominate training simply by being longer than everything
    else in the corpus.
    """
    indptr = [0]
    indices: list[int] = []
    data: list[float] = []
    for text in texts:
        counts = features_of(text, spec)
        if counts:
            keys = sorted(counts)
            values = np.array([counts[key] for key in keys], dtype=np.float64)
            norm = float(np.sqrt(np.sum(values * values)))
            if norm > 0.0:
                values = values / norm
            indices.extend(keys)
            data.extend(values.tolist())
        indptr.append(len(indices))
    return Matrix(
        indptr=np.array(indptr, dtype=np.int64),
        indices=np.array(indices, dtype=np.int64),
        data=np.array(data, dtype=np.float64),
        buckets=spec.buckets,
    )
