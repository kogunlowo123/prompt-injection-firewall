"""Structural signals: properties of the message rather than words in it.

The rule layer matches phrases, so it can only catch phrasings somebody thought
of. These signals measure *shape* — how much of the message is imperative, does
it mix scripts inside a word, did normalisation have to decode something to read
it — and shape survives paraphrase in a way that a literal does not.

Two of the seven are deliberately family-agnostic. ``imperative_density`` and
``second_person_directive`` describe what every injection has in common, which
is that it is a command addressed to the assistant, and they are the only part
of the non-learned stack that keeps working when a fold takes its own
countermeasures away. That is not a large amount of signal, and the evaluation
says so rather than implying otherwise.

Each signal returns a value in [0, 1]. Values, not booleans: "this message is
9% imperative" and "this message is 80% imperative" are different observations,
and thresholding each signal separately would throw that away before the
ensemble ever sees it.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from pifw.corpus.attacks import ZERO_WIDTH
from pifw.detect.normalize import MIN_BASE64_CHARS, MIN_HEX_BYTES

_ZERO_WIDTH_SET = frozenset(ZERO_WIDTH)
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_SENTENCE_RE = re.compile(r"[^.!?\n]+")
_BLOB_RE = re.compile(
    rf"[A-Za-z0-9+/]{{{MIN_BASE64_CHARS},}}={{0,2}}"
    rf"|(?:\b[0-9a-fA-F]{{2}}\b[ \t]*){{{MIN_HEX_BYTES},}}"
)

#: Verbs that start a command. Generic English, chosen without reference to any
#: attack family: these are the verbs that begin an instruction of any kind,
#: which is why several of them are equally common in benign traffic.
IMPERATIVE_VERBS = frozenset(
    (
        "act",
        "answer",
        "append",
        "comply",
        "confirm",
        "continue",
        "disclose",
        "disregard",
        "do",
        "execute",
        "follow",
        "forget",
        "give",
        "ignore",
        "list",
        "obey",
        "omit",
        "output",
        "override",
        "pretend",
        "print",
        "reply",
        "repeat",
        "respond",
        "return",
        "reveal",
        "say",
        "send",
        "show",
        "skip",
        "state",
        "stop",
        "summarise",
        "summarize",
        "tell",
        "translate",
        "write",
    )
)

_DIRECTIVE_RE = re.compile(
    r"\byou (?:must|will|are to|should now|shall)\b|\byour (?:new )?(?:task|role|job) is\b"
    r"|\bfrom now on\b|\bgoing forward\b|\bfor the rest of this session\b",
    re.IGNORECASE,
)

_CONTEXT_REFERENCE_RE = re.compile(
    r"\b(?:your (?:instructions?|system prompt|configuration|directives?|context)"
    r"|the (?:system prompt|developer message|hidden context|instructions above)"
    r"|everything above|the text above this line)\b",
    re.IGNORECASE,
)

#: Scripts whose letters look like Latin ones. A word containing letters from
#: two of these at once is not a word anybody typed by accident.
_LOOKALIKE_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")


def _script_of(char: str) -> str | None:
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    for script in _LOOKALIKE_SCRIPTS:
        if name.startswith(script):
            return script
    return None


def zero_width_density(original: str, normalized: str) -> float:  # noqa: ARG001
    """How much of the raw message is characters that render as nothing.

    Any at all is remarkable — legitimate text does contain zero-width joiners,
    but in emoji sequences and Indic scripts, not sprinkled through an English
    sentence. Scaled so that one in fifty characters saturates the signal.
    """
    if not original:
        return 0.0
    hits = sum(1 for char in original if char in _ZERO_WIDTH_SET)
    return min(1.0, (hits / len(original)) * 50.0)


def script_mixing(original: str, normalized: str) -> float:  # noqa: ARG001
    """The share of words that mix two lookalike scripts inside a single word.

    Between words is ordinary — a Russian sentence quoting an English product
    name mixes scripts and is entirely normal. Inside one word it is not.
    """
    words = _WORD_RE.findall(original)
    if not words:
        return 0.0
    mixed = 0
    for word in words:
        scripts = {script for script in map(_script_of, word) if script is not None}
        if len(scripts) > 1:
            mixed += 1
    return min(1.0, (mixed / len(words)) * 4.0)


def encoded_blob(original: str, normalized: str) -> float:  # noqa: ARG001
    """How much of the message is one undifferentiated encoded run."""
    if not original:
        return 0.0
    covered = sum(len(match.group(0)) for match in _BLOB_RE.finditer(original))
    return min(1.0, (covered / len(original)) * 3.0)


def normalisation_expansion(original: str, normalized: str) -> float:
    """How much text normalisation had to surface that was not literally present.

    Decoding and fragment-reassembly append to the normalised form, so this is
    the fraction by which the readable message grew. A message that gets 60%
    longer when you read what it was carrying is carrying something.
    """
    if not original:
        return 0.0
    growth = (len(normalized) - len(original)) / len(original)
    return max(0.0, min(1.0, growth * 2.0))


def imperative_density(original: str, normalized: str) -> float:  # noqa: ARG001
    """The share of sentences that begin with a bare command verb.

    Family-agnostic by construction. An injection is a command; so is half of
    ordinary technical traffic, which is why this signal is worth a little and
    not a lot.
    """
    sentences = [s.strip() for s in _SENTENCE_RE.findall(normalized) if s.strip()]
    if not sentences:
        return 0.0
    commands = 0
    for sentence in sentences:
        words = _WORD_RE.findall(sentence.lower())
        if words and words[0] in IMPERATIVE_VERBS:
            commands += 1
    # The raw fraction, unscaled. An earlier version multiplied by two, which
    # meant any message half made of commands saturated the signal — turning
    # the value this function exists to produce back into the boolean it was
    # written to avoid. The signal's *weight* is where its influence is set.
    return commands / len(sentences)


def second_person_directive(original: str, normalized: str) -> float:  # noqa: ARG001
    """How often the message tells the reader what it now is or must do.

    Also family-agnostic. "You must", "your new task is", "from now on" — the
    grammar of reassignment, independent of what is being reassigned.
    """
    hits = len(_DIRECTIVE_RE.findall(normalized))
    return min(1.0, hits / 2.0)


def context_reference(original: str, normalized: str) -> float:  # noqa: ARG001
    """Does the message talk about the conversation's own hidden parts?

    Ordinary traffic has no reason to refer to the system prompt. Traffic
    written by a security team discussing one does, which is why the benign
    corpus contains that case and why this signal is worth less than it looks.
    """
    hits = len(_CONTEXT_REFERENCE_RE.findall(normalized))
    return min(1.0, hits / 2.0)


@dataclass(frozen=True, slots=True)
class Signal:
    """One structural measurement, its weight, and the families that motivated it."""

    name: str
    summary: str
    weight: float
    motivated_by: frozenset[str]
    score: Callable[[str, str], float]


SIGNALS: tuple[Signal, ...] = (
    Signal(
        "structure.zero_width",
        "Characters that render as nothing, sprinkled through the text.",
        0.55,
        frozenset({"homoglyph"}),
        zero_width_density,
    ),
    Signal(
        "structure.script_mixing",
        "Two lookalike scripts inside a single word.",
        0.55,
        frozenset({"homoglyph"}),
        script_mixing,
    ),
    Signal(
        "structure.encoded_blob",
        "A long undifferentiated base64 or hex run.",
        0.30,
        frozenset({"encoding_wrapper"}),
        encoded_blob,
    ),
    Signal(
        "structure.expansion",
        "How much readable text normalisation had to decode or reassemble.",
        0.45,
        frozenset({"encoding_wrapper", "payload_splitting"}),
        normalisation_expansion,
    ),
    Signal(
        "structure.imperative",
        "The share of sentences that are bare commands.",
        0.25,
        frozenset(),
        imperative_density,
    ),
    Signal(
        "structure.directive",
        "The grammar of reassignment: you must, your new task is, from now on.",
        0.30,
        frozenset(),
        second_person_directive,
    ),
    Signal(
        "structure.context_reference",
        "References to the conversation's own hidden parts.",
        0.30,
        frozenset({"exfiltration"}),
        context_reference,
    ),
)

SIGNAL_NAMES: tuple[str, ...] = tuple(signal.name for signal in SIGNALS)
BY_NAME: dict[str, Signal] = {signal.name: signal for signal in SIGNALS}

#: The signals that no single family motivated, and which therefore survive
#: every fold. Named so the documentation can point at them.
FAMILY_AGNOSTIC: tuple[str, ...] = tuple(
    signal.name for signal in SIGNALS if not signal.motivated_by
)


@dataclass(frozen=True, slots=True)
class SignalHit:
    """One signal's value on one message."""

    name: str
    value: float
    weight: float


def measure(
    original: str, normalized: str, *, disabled: frozenset[str] = frozenset()
) -> tuple[SignalHit, ...]:
    """Every enabled signal, with its value. Zero-valued signals are dropped."""
    hits = []
    for signal in SIGNALS:
        if signal.name in disabled:
            continue
        value = signal.score(original, normalized)
        if value > 0.0:
            hits.append(SignalHit(name=signal.name, value=value, weight=signal.weight))
    return tuple(hits)


def signals_for_fold(held_out: str | None) -> frozenset[str]:
    """Which signals must be switched off when *held_out* is the unseen family."""
    if held_out is None:
        return frozenset()
    return frozenset(signal.name for signal in SIGNALS if held_out in signal.motivated_by)
