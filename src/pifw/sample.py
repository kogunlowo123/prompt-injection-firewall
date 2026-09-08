"""The unit of everything here: one piece of text, labelled, with its provenance.

A :class:`Sample` is either an attack or benign. Attacks carry the *family* they
were built from, and that field is load-bearing rather than decorative: the
evaluation in :mod:`pifw.evaluate.lofo` splits on it, and a detector's score on
a family it has seen means something entirely different from its score on one it
has not.

Benign samples carry a ``kind`` instead, because "benign" is not one thing. A
firewall that never sees benign text *about* prompt injection will flag the
security team's own documentation, and the only way to know whether it does is
to keep those samples separable from ordinary traffic and report them apart.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pifw.errors import CorpusError

#: Refuse to read a corpus larger than this once decompressed. A 620 KB gzip
#: file can expand to gigabytes, and the check has to be on the decompressed
#: stream: checking the file size on disk measures the wrong number.
MAX_CORPUS_BYTES = 256 * 1024 * 1024

MAX_TEXT_CHARS = 20_000

Label = Literal["attack", "benign"]


class Sample(BaseModel):
    """One labelled piece of text.

    ``text`` is stored exactly as generated. Normalisation happens in the
    detector, never on the way in: a corpus that has already had its zero-width
    characters stripped cannot be used to test whether stripping them helps.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)
    label: Label
    #: For attacks, the technique family. For benign samples, empty.
    family: str = ""
    #: For benign samples, which sort of benign. For attacks, empty.
    kind: str = ""
    #: Free-form provenance: the grammar frame used, the seed, the decoys.
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("text")
    @classmethod
    def _no_bare_newline_abuse(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a sample's text cannot be only whitespace")
        return value

    @model_validator(mode="after")
    def _label_matches_taxonomy(self) -> Self:
        if self.label == "attack" and not self.family:
            raise ValueError("an attack sample must name the family it came from")
        if self.label == "benign" and not self.kind:
            raise ValueError("a benign sample must name its kind")
        if self.label == "attack" and self.kind:
            raise ValueError("an attack sample has a family, not a kind")
        if self.label == "benign" and self.family:
            raise ValueError("a benign sample has a kind, not a family")
        return self

    @property
    def is_attack(self) -> bool:
        """Is this sample something the firewall is meant to catch?"""
        return self.label == "attack"

    @property
    def group(self) -> str:
        """The taxonomy bucket, whichever side of the label it comes from."""
        return self.family or self.kind


class Corpus(BaseModel):
    """An ordered, duplicate-free collection of samples.

    Order is preserved because every downstream split is seeded, and a seeded
    split over an unordered collection is only reproducible by accident.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    records: tuple[Sample, ...]

    @field_validator("records")
    @classmethod
    def _ids_are_unique(cls, value: tuple[Sample, ...]) -> tuple[Sample, ...]:
        seen: set[str] = set()
        for record in value:
            if record.sample_id in seen:
                raise ValueError(f"duplicate sample_id {record.sample_id!r}")
            seen.add(record.sample_id)
        return value

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[Sample]:  # type: ignore[override]
        return iter(self.records)

    @property
    def attacks(self) -> tuple[Sample, ...]:
        """Every attack sample, in corpus order."""
        return tuple(record for record in self.records if record.is_attack)

    @property
    def benign(self) -> tuple[Sample, ...]:
        """Every benign sample, in corpus order."""
        return tuple(record for record in self.records if not record.is_attack)

    @property
    def families(self) -> tuple[str, ...]:
        """The attack families present, sorted."""
        return tuple(sorted({record.family for record in self.attacks}))

    @property
    def kinds(self) -> tuple[str, ...]:
        """The benign kinds present, sorted."""
        return tuple(sorted({record.kind for record in self.benign}))

    def counts(self) -> dict[str, int]:
        """How many samples in each taxonomy bucket."""
        tally: dict[str, int] = {}
        for record in self.records:
            tally[record.group] = tally.get(record.group, 0) + 1
        return dict(sorted(tally.items()))

    def without_family(self, family: str) -> Corpus:
        """This corpus with one attack family removed. Benign samples are kept."""
        return build_corpus(r for r in self.records if r.family != family)

    def only_family(self, family: str) -> Corpus:
        """Just the attacks from one family."""
        return build_corpus(r for r in self.records if r.family == family)

    def digest(self) -> str:
        """A content address over the samples, stable across platforms.

        Every field feeding this is an integer or a string, so unlike the
        trained weights it is genuinely bit-identical everywhere and can be
        gated by equality rather than by tolerance.
        """
        hasher = hashlib.sha256()
        for record in self.records:
            hasher.update(
                json.dumps(
                    record.model_dump(mode="json"), sort_keys=True, ensure_ascii=False
                ).encode("utf-8")
            )
            hasher.update(b"\n")
        return f"sha256:{hasher.hexdigest()}"

    def write(self, path: str | Path) -> Path:
        """Write to JSONL, gzipped if the path says so."""
        return write_jsonl(path, [record.model_dump(mode="json") for record in self.records])


Records = Annotated[Iterable[Sample], "any iterable of samples"]


def build_corpus(records: Records) -> Corpus:
    """Build a corpus, giving pydantic a tuple rather than a generator."""
    return Corpus(records=tuple(records))


def is_compressed(path: Path) -> bool:
    """Is this path a gzip file?

    By suffix, never by sniffing the contents. Sniffing means opening a file to
    decide how to open it, and a corpus named ``.jsonl`` that happens to start
    with the gzip magic bytes is a mislabelled file, not a compressed one.
    """
    return path.suffix == ".gz"


class _Bounded(io.RawIOBase):
    """A reader that refuses to hand over more than ``limit`` bytes.

    Wraps the *decompressed* stream. A gzip member declares its uncompressed
    size in a trailer the writer chose, so believing it is believing the file.
    """

    def __init__(self, stream: gzip.GzipFile, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._seen = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        chunk = self._stream.read(len(buffer))
        if not chunk:
            return 0
        self._seen += len(chunk)
        if self._seen > self._limit:
            raise CorpusError(
                f"the corpus expands past {self._limit} bytes and was not read to the end",
                remedy="Split the corpus, or raise MAX_CORPUS_BYTES if this size is expected.",
            )
        buffer[: len(chunk)] = chunk
        return len(chunk)


def open_corpus_text(path: Path) -> io.TextIOWrapper:
    """Open a corpus for reading as text, compressed or not, size-bounded."""
    if is_compressed(path):
        raw = gzip.GzipFile(filename=str(path), mode="rb")
        return io.TextIOWrapper(
            io.BufferedReader(_Bounded(raw, MAX_CORPUS_BYTES)), encoding="utf-8"
        )
    if path.stat().st_size > MAX_CORPUS_BYTES:
        raise CorpusError(
            f"{path} is larger than {MAX_CORPUS_BYTES} bytes",
            remedy="Split the corpus, or raise MAX_CORPUS_BYTES if this size is expected.",
        )
    return path.open("r", encoding="utf-8")


def write_jsonl(path: str | Path, rows: Sequence[dict[str, Any]]) -> Path:
    """Write rows as JSONL. The only writer in this package.

    Gzip is chosen by suffix and stamped with ``mtime=0`` so the bytes depend
    only on the content: a corpus regenerated tomorrow from the same seed has
    the same digest as the one committed today, which is what makes the
    committed digest checkable at all.
    """
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows) + "\n"
    if is_compressed(file):
        with (
            file.open("wb") as sink,
            gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0) as raw,
        ):
            raw.write(body.encode("utf-8"))
    else:
        file.write_text(body, encoding="utf-8", newline="\n")
    return file


def read_corpus(path: str | Path) -> Corpus:
    """Read a corpus from JSONL, reporting the line number of a bad record."""
    file = Path(path)
    if not file.exists():
        raise CorpusError(
            f"no corpus at {file}",
            remedy="Generate one with 'pifw synth --out <path>'.",
        )
    records: list[Sample] = []
    with open_corpus_text(file) as stream:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                records.append(Sample.model_validate_json(line))
            except ValueError as exc:
                raise CorpusError(
                    f"{file}:{number} is not a valid sample: {exc}",
                    remedy="Regenerate the corpus rather than editing it by hand.",
                ) from exc
    if not records:
        raise CorpusError(
            f"{file} contains no samples",
            remedy="Generate one with 'pifw synth --out <path>'.",
        )
    return build_corpus(records)
