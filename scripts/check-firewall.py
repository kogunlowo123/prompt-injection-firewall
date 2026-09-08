#!/usr/bin/env python
"""Assert the firewall's gates fire, by running the real command line against them.

A gate that has only ever been observed passing is indistinguishable from `true`
in a shell script. The test suite has its own negative controls; this runs the
**shipped binary** against the **shipped corpora**, which is the configuration a
reader will actually reproduce, and asserts five things:

1. the shipped evaluation passes its committed baseline — the control, without
   which every failure below could be a fact about the tool rather than the gate;
2. a baseline recording a family this run does not measure exits **2**, not
   merely non-zero: 3 would mean the tool broke rather than the gate firing;
3. a baseline recording an impossibly good bypass rate exits 2;
4. asked to gate with no baseline at all, it **refuses** rather than inventing a
   threshold to pass;
5. a model that has not converged produces **no bypass rate at all**, because a
   number measured from an undertrained model describes the optimiser.

Run through ``python tasks.py check-firewall``. CI runs it on every push.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
CORPUS = EXAMPLES / "corpus.jsonl.gz"
HOLDOUT = EXAMPLES / "holdout.jsonl.gz"
BASELINE = EXAMPLES / "baseline.json"

EXIT_OK = 0
EXIT_GATE_FAILED = 2

#: Two folds rather than twelve. This script checks that the gate *fires*, and
#: the folds it fires on do not change the answer; the full twelve-fold
#: measurement is `python tasks.py evaluate`, which CI also runs.
FOLDS = ("direct_override", "indirect")


def pifw(*argv: str) -> tuple[int, str, str]:
    """Run the command line and return (exit code, stdout, stderr)."""
    result = subprocess.run(  # noqa: S603 - a fixed argument vector
        [sys.executable, "-m", "pifw", *argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
        cwd=ROOT,
        encoding="utf-8",
    )
    return result.returncode, result.stdout, result.stderr


def evaluate(*extra: str) -> tuple[int, str, str]:
    return pifw(
        "evaluate",
        "--corpus",
        str(CORPUS),
        "--eval-corpus",
        str(HOLDOUT),
        "--families",
        *FOLDS,
        "--quiet",
        *extra,
    )


def write_baseline(path: Path, changes: dict[str, Any]) -> Path:
    """Copy the committed baseline with some fields replaced."""
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    data.update(changes)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main() -> int:  # noqa: PLR0912 - five sequential checks, not nested logic
    failures = 0

    for path in (CORPUS, HOLDOUT, BASELINE):
        if not path.exists():
            print(f"FAIL  {path} is missing", file=sys.stderr)
            print("      Run 'python tasks.py corpus' and 'python tasks.py baseline'.")
            return 1

    # `var/` is gitignored, so on a fresh clone it does not exist and
    # TemporaryDirectory(dir=...) raises FileNotFoundError. Created here rather
    # than assumed: this script's whole job is to run on a checkout nobody has
    # run anything else in yet.
    scratch_root = ROOT / "var"
    scratch_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=scratch_root) as scratch:
        work = Path(scratch)

        # 1. The control. Two folds against a baseline recorded from twelve, so
        #    only the families in FOLDS are compared; the rest are removed from
        #    the copy rather than left to trip the "did not measure" check.
        recorded = json.loads(BASELINE.read_text(encoding="utf-8"))
        subset = write_baseline(
            work / "subset.json",
            {
                "family_bypass": {
                    name: value
                    for name, value in recorded["family_bypass"].items()
                    if name in FOLDS
                },
                # The pooled and control figures in the committed baseline are
                # over twelve folds, so they do not describe this two-fold run.
                # Relaxed here on purpose: this check is about the gate firing,
                # and `tasks.py evaluate` gates the real pooled figure.
                "pooled_bypass": 1.0,
                "control_bypass": 1.0,
            },
        )
        code, stdout, stderr = evaluate("--baseline", str(subset))
        if code == EXIT_OK and "no regression" in stdout:
            print("ok    the shipped firewall passes its committed baseline")
        else:
            print(
                f"FAIL  the shipped firewall did not pass: exit {code}\n{stderr}",
                file=sys.stderr,
            )
            failures += 1

        # 2. A family in the baseline that this run does not measure.
        missing = write_baseline(
            work / "missing.json",
            {
                "family_bypass": {
                    **dict.fromkeys(FOLDS, 1.0),
                    "a_family_nobody_ran": 0.0,
                },
                "pooled_bypass": 1.0,
                "control_bypass": 1.0,
            },
        )
        code, _, stderr = evaluate("--baseline", str(missing))
        if code == EXIT_GATE_FAILED and "did not measure" in stderr:
            print("ok    a fold that stopped running fails the gate, exit 2")
        else:
            print(f"FAIL  missing fold: exit {code}, expected {EXIT_GATE_FAILED}", file=sys.stderr)
            failures += 1

        # 3. A baseline nothing could meet.
        impossible = write_baseline(
            work / "impossible.json",
            {
                "family_bypass": dict.fromkeys(FOLDS, -1.0),
                "pooled_bypass": -1.0,
                "control_bypass": 1.0,
            },
        )
        code, _, stderr = evaluate("--baseline", str(impossible))
        if code == EXIT_GATE_FAILED and "regressed" in stderr:
            print("ok    a regression against the baseline fails the gate, exit 2")
        else:
            print(f"FAIL  regression: exit {code}, expected {EXIT_GATE_FAILED}", file=sys.stderr)
            failures += 1

        # 4. No baseline, no verdict.
        code, _, stderr = evaluate()
        if code != EXIT_OK and "does not invent a threshold" in stderr:
            print("ok    without a baseline it refuses rather than inventing one")
        else:
            print(f"FAIL  uncalibrated run: exit {code}", file=sys.stderr)
            failures += 1

        # 5. An undertrained model produces no number at all.
        code, stdout, stderr = evaluate("--max-iterations", "3", "--no-gate")
        if code == EXIT_GATE_FAILED and "gradient tolerance" in stderr and "bypass" not in stdout:
            print("ok    an unconverged model reports no bypass rate at all")
        else:
            print(
                f"FAIL  unconverged run: exit {code}, and it printed a rate anyway",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"\n{failures} check(s) failed", file=sys.stderr)
        return 1
    print(
        "\nthe gate passes the shipped configuration, fails a regression, fails a "
        "fold that stopped running, refuses without a baseline, and refuses to "
        "report a number from an undertrained model"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
