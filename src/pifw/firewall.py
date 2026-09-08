"""The integration point: wrap a model call, decide, and record what got through.

A detector that scores a corpus is a detector. What makes this a firewall is
that it sits on the request path and that **it keeps measuring after it is
deployed**.

That second part is the design's whole reason for existing. The bypass rate in
the README was measured against a synthetic corpus of twelve techniques. Real
traffic contains techniques nobody has enumerated, and the only honest claim
about them is that the number does not cover them. So every decision is written
to an append-only record, and ``pifw audit`` reads it back: what share of traffic
is being flagged, how the scores of *allowed* traffic are distributed, and
whether either has moved. A firewall whose flag rate silently fell to zero last
Tuesday is indistinguishable from one that is working, unless somebody is
looking.

**The record does not contain the prompts.** A log of every message a user sent
an assistant is a data-protection problem that arrives with the mitigation, so
the default stores a salted digest, the length, the score, the decision and the
rule names. Keeping the text is available, is opt-in, and says so.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pifw.detect.ensemble import Decision, Detector, Verdict
from pifw.errors import ConfigError

#: Environment variable holding the salt for prompt digests. Set it to a stable
#: secret and digests correlate across restarts; leave it unset and each process
#: gets a fresh random salt, so a record cannot be linked to anything — not even
#: to yesterday's record of the same message.
SALT_ENV = "PIFW_RECORD_SALT"

#: Stop appending past this. A record file that grows without bound on the
#: request path is an outage waiting for a busy afternoon.
MAX_RECORD_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Outcome[T]:
    """What the firewall did, and what came back if it let the call happen."""

    verdict: Verdict
    called: bool
    response: T | None = None
    #: Set when the call was refused, so a caller has something to return.
    refusal: str | None = None

    @property
    def decision(self) -> Decision:
        """allow, flag or block."""
        return self.verdict.decision


class Recorder:
    """Append-only JSONL of decisions, without the prompts.

    Deliberately not structured logging into whatever the host application uses.
    An audit record that shares a sink with debug output gets sampled, truncated
    and rotated according to a policy chosen for debug output.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        keep_text: bool = False,
        salt: str | None = None,
        max_bytes: int = MAX_RECORD_BYTES,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.keep_text = keep_text
        self.max_bytes = max_bytes
        self._salt = salt if salt is not None else os.environ.get(SALT_ENV) or secrets.token_hex(16)
        self._stable_salt = salt is not None or SALT_ENV in os.environ

    @property
    def salt_is_stable(self) -> bool:
        """Will digests written now match digests written by the next process?

        Surfaced rather than hidden: an operator correlating two days of records
        needs to know whether a digest is a pseudonym or a per-process nonce,
        and finding that out by noticing nothing ever matches is expensive.
        """
        return self._stable_salt

    def fingerprint(self, text: str) -> str:
        """A salted digest of the prompt.

        A pseudonym, not an anonymisation. The space of short prompts is small
        enough to enumerate, so with the salt in hand a determined reader can
        confirm a guess. It is here to link repeat offenders across records, and
        it is documented as being no stronger than that.
        """
        digest = hashlib.sha256(f"{self._salt}\x00{text}".encode()).hexdigest()
        return f"sha256:{digest[:32]}"

    def record(self, verdict: Verdict, *, called: bool) -> None:
        """Append one decision. Never raises on the request path.

        A firewall that throws because its audit disk filled up has converted a
        logging failure into an outage. Recording is best-effort by design, and
        ``pifw audit`` reports gaps in the record rather than assuming there are
        none.
        """
        row: dict[str, Any] = {
            "at": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "fingerprint": self.fingerprint(verdict.text),
            "length": len(verdict.text),
            "score": round(verdict.score, 6),
            "decision": verdict.decision,
            "called": called,
            "layers": {name: round(value, 6) for name, value in verdict.layers.items()},
            "reasons": list(verdict.reasons),
        }
        if self.keep_text:
            row["text"] = verdict.text
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                return
            with self.path.open("a", encoding="utf-8", newline="\n") as sink:
                sink.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        except OSError:
            return

    def rows(self) -> list[dict[str, Any]]:
        """Read the record back, skipping lines a partial write left behind."""
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


@dataclass(frozen=True, slots=True)
class Audit:
    """What the record says about traffic since it was opened."""

    total: int
    by_decision: dict[str, int]
    allowed_score_quantiles: dict[str, float]
    flag_rate: float

    def to_dict(self) -> dict[str, Any]:
        """As JSON."""
        return {
            "total": self.total,
            "by_decision": self.by_decision,
            "allowed_score_quantiles": self.allowed_score_quantiles,
            "flag_rate": self.flag_rate,
        }


def audit(rows: list[dict[str, Any]]) -> Audit:
    """Summarise a record.

    The quantiles of *allowed* traffic are the interesting part. A firewall
    working normally allows a mass of traffic scoring near zero; a distribution
    that has grown a shoulder just under the threshold is either drift or
    somebody probing for where the threshold is, and both are worth a look
    before the flag rate itself moves.
    """
    by_decision: dict[str, int] = {}
    allowed: list[float] = []
    for row in rows:
        decision = str(row.get("decision", "unknown"))
        by_decision[decision] = by_decision.get(decision, 0) + 1
        if decision == "allow":
            try:
                allowed.append(float(row["score"]))
            except (KeyError, TypeError, ValueError):
                continue
    allowed.sort()
    quantiles: dict[str, float] = {}
    for label, fraction in (("p50", 0.5), ("p90", 0.9), ("p99", 0.99), ("max", 1.0)):
        if allowed:
            index = min(len(allowed) - 1, int(fraction * (len(allowed) - 1) + 0.5))
            quantiles[label] = allowed[index]
        else:
            quantiles[label] = 0.0
    total = len(rows)
    flagged = total - by_decision.get("allow", 0)
    return Audit(
        total=total,
        by_decision=dict(sorted(by_decision.items())),
        allowed_score_quantiles=quantiles,
        flag_rate=flagged / total if total else 0.0,
    )


class Firewall:
    """A detector, a recorder, and a policy for what to do with a verdict."""

    def __init__(
        self,
        detector: Detector,
        *,
        recorder: Recorder | None = None,
        refusal: str = (
            "This request was held for review because it looks like an attempt to "
            "change the assistant's instructions."
        ),
    ) -> None:
        if detector.mode == "enforce" and recorder is None:
            raise ConfigError(
                "enforce mode without a recorder",
                remedy=(
                    "Blocking traffic without recording what was blocked leaves nobody "
                    "able to tell a working firewall from a broken one. Pass a Recorder."
                ),
            )
        self.detector = detector
        self.recorder = recorder
        self.refusal = refusal

    def guard(self, text: str) -> Verdict:
        """Score a message and record the decision, without calling anything."""
        verdict = self.detector.inspect(text)
        if self.recorder is not None:
            self.recorder.record(verdict, called=verdict.decision != "block")
        return verdict

    def run[T](self, text: str, call: Callable[[str], T]) -> Outcome[T]:
        """Guard a message, then make the call unless the verdict was ``block``.

        ``flag`` still calls. That is the point of monitor mode: the message is
        recorded and surfaced, and the assistant answers, because a firewall
        whose measured bypass rate is not zero should not be the sole thing
        standing between a user and their own request.
        """
        verdict = self.detector.inspect(text)
        blocked = verdict.decision == "block"
        if self.recorder is not None:
            self.recorder.record(verdict, called=not blocked)
        if blocked:
            return Outcome(verdict=verdict, called=False, refusal=self.refusal)
        return Outcome(verdict=verdict, called=True, response=call(text))

    def wrap[T](self, call: Callable[[str], T]) -> Callable[[str], Outcome[T]]:
        """Turn a model call into a guarded one."""

        def guarded(text: str) -> Outcome[T]:
            return self.run(text, call)

        return guarded

    def audit(self) -> Audit:
        """Summarise this firewall's own record."""
        if self.recorder is None:
            raise ConfigError(
                "this firewall has no recorder",
                remedy="Construct it with Recorder(path) to make its traffic auditable.",
            )
        return audit(self.recorder.rows())
