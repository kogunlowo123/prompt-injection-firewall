"""Normalisation: making obfuscated text comparable before anything matches on it.

Every stage declares the attack families that motivated it. That field is not
documentation — :mod:`pifw.evaluate.lofo` reads it, and when the ``homoglyph``
family is held out the confusable-folding stage is switched off along with it.

This is the part of the design that is easy to get wrong and easy to hide.
Leaving the countermeasure on while holding the family out measures a firewall
built by someone who had already seen the technique, then reports the number as
if they had not. Turning it off measures the thing the number claims to be: what
happens the first time a technique arrives.

The predictable consequence is that the obfuscation families score badly under
their own fold, and that result is on the front page rather than buried. It is
the honest form of the only reliable finding in this field: **you do not defend
against a technique you have not seen.**

A second point worth stating plainly, because pipelines get it wrong: **NFKC is
not a confusable defence.** Unicode normalisation folds compatibility variants,
so it does undo the fullwidth block, but Cyrillic ``е`` and Latin ``e`` are
different letters in different scripts and NFKC leaves them alone by design.
Folding them needs an explicit table, which is what :data:`FOLD` is.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from pifw.corpus.attacks import CONFUSABLES, ZERO_WIDTH

#: Never decode more than this many bytes out of one message, across all
#: rounds. Decoding is attacker-controlled expansion — a short base64 string can
#: carry a long one — and an unbounded decoder is a denial-of-service surface
#: sitting in front of the thing it protects.
MAX_DECODE_BYTES = 64 * 1024

#: How many times to decode a decode. Two rounds catch base64-inside-base64,
#: which is common; beyond that the cost is real and the yield is not.
MAX_DECODE_ROUNDS = 2

MIN_BASE64_CHARS = 24
MIN_HEX_BYTES = 8

#: A decoded blob has to be this printable before it is believed to be text.
MIN_PRINTABLE_RATIO = 0.9

#: Words needed before the function-word density means anything. Below this
#: one word swings the ratio by a quarter and every transformation looks
#: like a decode.
MIN_WORDS_FOR_DENSITY = 4

#: How much a transformation must raise function-word density to be believed.
MIN_DENSITY_GAIN = 0.15

#: Quoted assignments needed before reassembly is worth attempting.
MIN_FRAGMENTS = 2

#: Latin letter for each confusable, the inverse of the attack-side table.
FOLD: dict[str, str] = {glyph: latin for latin, glyph in CONFUSABLES.items()}

#: A handful of Greek letters that are also common substitutions.
FOLD.update({"ο": "o", "ι": "i", "ν": "v", "ρ": "p", "τ": "t", "α": "a", "ε": "e"})

_ZERO_WIDTH_RE = re.compile(f"[{''.join(ZERO_WIDTH)}]")
_WHITESPACE_RE = re.compile(r"[^\S\n]+")
_BLANK_LINES_RE = re.compile(r"\n{3,}")
_BASE64_RE = re.compile(rf"[A-Za-z0-9+/]{{{MIN_BASE64_CHARS},}}={{0,2}}")
_HEX_RE = re.compile(rf"(?:\b[0-9a-fA-F]{{2}}\b[ \t]*){{{MIN_HEX_BYTES},}}")
_ASSIGNMENT_RE = re.compile(
    r"""^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['"])(?P<value>.*?)(?P=quote)\s*$""",
    re.MULTILINE,
)

#: Function words. Their density is a cheap, language-blind test for "did that
#: transformation turn noise into English", which is how ROT13 and reversal are
#: detected without needing the attacker to have left a hint.
_STOPWORDS = frozenset(
    (
        "the",
        "and",
        "you",
        "your",
        "all",
        "any",
        "are",
        "for",
        "from",
        "have",
        "not",
        "now",
        "this",
        "that",
        "with",
        "instructions",
        "instruction",
        "ignore",
        "previous",
        "above",
        "system",
        "prompt",
        "must",
        "should",
        "reply",
        "output",
        "print",
        "answer",
        "text",
        "before",
        "them",
        "then",
        "what",
        "which",
        "who",
        "was",
        "were",
        "will",
        "would",
        "can",
        "do",
        "does",
    )
)

_WORD_RE = re.compile(r"[A-Za-z']+")


def _stopword_density(text: str) -> float:
    """The share of alphabetic words that are function words."""
    words = _WORD_RE.findall(text.lower())
    if len(words) < MIN_WORDS_FOR_DENSITY:
        return 0.0
    return sum(1 for word in words if word in _STOPWORDS) / len(words)


def _is_more_english(candidate: str, original: str) -> bool:
    """Did a transformation raise the function-word density enough to believe it?

    The margin matters. Any transformation of a short string moves this number
    around, and decoding on a small improvement adds a second attacker-supplied
    surface to every message for no benefit.
    """
    return _stopword_density(candidate) >= _stopword_density(original) + MIN_DENSITY_GAIN


def _printable_ratio(text: str) -> float:
    """The share of characters that are printable, ordinary whitespace, or invisible.

    Unicode format characters (category ``Cf`` — the zero-width space, the
    joiners, the byte-order mark) count as printable here, and that is not a
    detail. ``str.isprintable()`` says they are not, which is correct for its
    purpose and wrong for this one: the decoder uses this ratio to tell text
    from binary, and an attacker who sprinkles zero-width characters *inside*
    the payload before encoding it pushes the ratio under the threshold and the
    decoder discards the whole blob.

    That is a one-character bypass of the entire decoding stage, and it was
    live until a test combined two obfuscations that each passed on their own.
    Every layer worked; the composition did not.
    """
    if not text:
        return 0.0
    readable = sum(
        1
        for char in text
        if char.isprintable() or char in "\n\t" or unicodedata.category(char) == "Cf"
    )
    return readable / len(text)


# --------------------------------------------------------------------------
# The stages.
# --------------------------------------------------------------------------


def apply_nfkc(text: str) -> str:
    """Unicode compatibility normalisation. Undoes fullwidth forms and ligatures."""
    return unicodedata.normalize("NFKC", text)


def strip_zero_width(text: str) -> str:
    """Remove characters that occupy no space and split words for a matcher."""
    return _ZERO_WIDTH_RE.sub("", text)


def fold_confusables(text: str) -> str:
    """Map script-confusable letters onto their Latin equivalents.

    Deliberately one-directional and small. A full Unicode confusables table
    folds far more aggressively, and folding aggressively on the *benign* side
    is how a firewall starts flagging Cyrillic text for being Cyrillic.
    """
    return "".join(FOLD.get(char, char) for char in text)


def collapse_whitespace(text: str) -> str:
    """Normalise line endings and runs of spaces, keeping paragraph structure."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _WHITESPACE_RE.sub(" ", text)
    return _BLANK_LINES_RE.sub("\n\n", text).strip()


def _decode_base64(text: str, budget: int) -> list[str]:
    found: list[str] = []
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)
        if len(blob) % 4:
            blob = blob[: len(blob) - len(blob) % 4]
        if len(blob) < MIN_BASE64_CHARS or sum(len(f) for f in found) > budget:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) > budget:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(decoded) > MIN_PRINTABLE_RATIO and _WORD_RE.search(decoded):
            found.append(decoded)
    return found


def _decode_hex(text: str, budget: int) -> list[str]:
    found: list[str] = []
    for match in _HEX_RE.finditer(text):
        blob = "".join(match.group(0).split())
        if len(blob) % 2 or len(blob) // 2 > budget:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > MIN_PRINTABLE_RATIO and _WORD_RE.search(decoded):
            found.append(decoded)
    return found


def _decode_substitution(text: str) -> list[str]:
    """ROT13 and reversal, accepted only when they make the text more English."""
    found = []
    rotated = str(codecs.encode(text, "rot_13"))
    if _is_more_english(rotated, text):
        found.append(rotated)
    backwards = text[::-1]
    if _is_more_english(backwards, text):
        found.append(backwards)
    return found


def expand_encodings(text: str) -> str:
    """Append anything the text was carrying in an encoding.

    Appended rather than substituted. The carrier matters: a message whose
    base64 blob decodes to an override is suspicious *because* it wrapped it,
    and replacing the blob with its contents throws that signal away.
    """
    rounds: list[str] = []
    frontier = [text]
    budget = MAX_DECODE_BYTES
    for _ in range(MAX_DECODE_ROUNDS):
        discovered: list[str] = []
        for chunk in frontier:
            discovered.extend(_decode_base64(chunk, budget))
            discovered.extend(_decode_hex(chunk, budget))
            discovered.extend(_decode_substitution(chunk))
        discovered = [item for item in discovered if item not in rounds and item != text]
        if not discovered:
            break
        spent = sum(len(item) for item in discovered)
        budget -= spent
        rounds.extend(discovered)
        if budget <= 0:
            break
        frontier = discovered
    if not rounds:
        return text
    return text + "\n" + "\n".join(rounds)


def reassemble_fragments(text: str) -> str:
    """Concatenate quoted assignments, so split payloads are visible as one string.

    ``a = 'ignore all previous'`` next to ``b = 'instructions'`` is two harmless
    fragments to anything matching on a line. Joined, it is the payload. The
    join is appended, not substituted, for the same reason as the decoder.
    """
    values = [match.group("value") for match in _ASSIGNMENT_RE.finditer(text)]
    values = [value for value in values if value.strip()]
    if len(values) < MIN_FRAGMENTS:
        return text
    joined = " ".join(values)
    if joined in text:
        return text
    return f"{text}\n{joined}"


def casefold(text: str) -> str:
    """Lowercase, once, at the end."""
    return text.casefold()


@dataclass(frozen=True, slots=True)
class Stage:
    """One normalisation step, and the attack families that justify its existence."""

    name: str
    summary: str
    #: Empty means generic hygiene that no single family motivated, and which is
    #: therefore never disabled by a leave-one-family-out fold.
    motivated_by: frozenset[str]
    apply: Callable[[str], str]


STAGES: tuple[Stage, ...] = (
    Stage(
        "nfkc",
        "Unicode compatibility normalisation; undoes fullwidth and ligature forms.",
        frozenset({"homoglyph"}),
        apply_nfkc,
    ),
    Stage(
        "zero_width",
        "Removes zero-width characters used to split words.",
        frozenset({"homoglyph"}),
        strip_zero_width,
    ),
    Stage(
        "confusables",
        "Folds script-confusable letters onto Latin. NFKC does not do this.",
        frozenset({"homoglyph"}),
        fold_confusables,
    ),
    Stage(
        "whitespace",
        "Normalises line endings and collapses runs of spaces.",
        frozenset(),
        collapse_whitespace,
    ),
    Stage(
        "decode",
        "Appends base64, hex, ROT13 and reversed content carried inside the message.",
        frozenset({"encoding_wrapper"}),
        expand_encodings,
    ),
    Stage(
        "reassemble",
        "Appends the concatenation of quoted assignments.",
        frozenset({"payload_splitting"}),
        reassemble_fragments,
    ),
    Stage(
        "casefold",
        "Lowercases, after every stage that depends on case.",
        frozenset(),
        casefold,
    ),
)

STAGE_NAMES: tuple[str, ...] = tuple(stage.name for stage in STAGES)

#: Stages that *add* text: they append what the message was carrying rather than
#: rewriting what it already said.
EXPANDING_STAGES: frozenset[str] = frozenset({"decode", "reassemble"})

#: Stages that rewrite characters. These have to run again after an expanding
#: stage, and finding that out is what the security test layer is for.
#:
#: The bug: a payload that is confusable-folded *and then* base64-wrapped
#: arrives as ASCII, so the character stages see nothing to do; the decoder then
#: appends the Cyrillic original, and by that point the folding stages have
#: already run. One line of base64 defeated the entire homoglyph defence, and
#: every individual stage passed its own unit test throughout.
CHARACTER_STAGES: tuple[str, ...] = ("nfkc", "zero_width", "confusables", "casefold")

BY_NAME: dict[str, Stage] = {stage.name: stage for stage in STAGES}


@dataclass(frozen=True, slots=True)
class Normalized:
    """The result of normalising one message."""

    original: str
    text: str
    applied: tuple[str, ...]
    skipped: tuple[str, ...]

    @property
    def expanded(self) -> bool:
        """Did normalisation surface content that was not literally present?"""
        return len(self.text) > len(collapse_whitespace(self.original).casefold())


def normalize(text: str, *, disabled: frozenset[str] = frozenset()) -> Normalized:
    """Run the stages in order, then run the character stages again if anything grew.

    ``disabled`` names *stages*, not families. The translation from a held-out
    family to the stages it motivated lives in :func:`stages_for_fold`, so that
    the mapping is in one place and can be tested on its own.

    **The second pass is not an optimisation.** Decoding appends text that the
    character stages have never seen, because it did not exist when they ran.
    Without the second pass, wrapping a homoglyph payload in base64 defeats
    homoglyph folding entirely — the outer message is plain ASCII, so nothing
    folds, and the Cyrillic arrives afterwards. See :data:`CHARACTER_STAGES`.

    One pass, not a loop to a fixed point: the character stages do not create
    new encoded content, so a third pass can never find anything a second did
    not, and an unbounded loop over attacker-supplied text is a worse idea than
    the problem it would solve.
    """
    applied: list[str] = []
    skipped: list[str] = []
    current = text
    grew = False
    for stage in STAGES:
        if stage.name in disabled:
            skipped.append(stage.name)
            continue
        updated = stage.apply(current)
        if stage.name in EXPANDING_STAGES and updated != current:
            grew = True
        current = updated
        applied.append(stage.name)

    if grew:
        for name in CHARACTER_STAGES:
            if name in disabled:
                continue
            current = BY_NAME[name].apply(current)
            applied.append(f"{name}:2")

    return Normalized(original=text, text=current, applied=tuple(applied), skipped=tuple(skipped))


def stages_for_fold(held_out: str | None) -> frozenset[str]:
    """Which stages must be switched off when *held_out* is the unseen family."""
    if held_out is None:
        return frozenset()
    return frozenset(stage.name for stage in STAGES if held_out in stage.motivated_by)
