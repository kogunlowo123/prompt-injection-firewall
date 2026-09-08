"""The task table. Run through ``python tasks.py <name>``.

Stdlib only, because a task runner that needs its own dependency installed
before it can install dependencies is a bootstrap problem nobody asked for.

``uv run`` picks the group each task actually needs rather than installing
everything: the documentation build gets a renderer and not pytest, and the
example commands get the project alone.
"""

from __future__ import annotations

from collections.abc import Sequence

IMAGE = "prompt-injection-firewall"

EXAMPLES = "examples"
CORPUS = f"{EXAMPLES}/corpus.jsonl.gz"
HOLDOUT = f"{EXAMPLES}/holdout.jsonl.gz"
MODEL = f"{EXAMPLES}/model.json"
BASELINE = f"{EXAMPLES}/baseline.json"


def _run(*args: str) -> list[str]:
    return ["uv", "run", *args]


def _pifw(*args: str) -> list[str]:
    return _run("python", "-m", "pifw", *args)


_EVALUATE = (
    "evaluate",
    "--corpus",
    CORPUS,
    "--eval-corpus",
    HOLDOUT,
    "--baseline",
    BASELINE,
)


TASKS: dict[str, tuple[str, list[Sequence[str]]]] = {
    "setup": (
        "Install the project and its development tooling.",
        [["uv", "sync", "--locked", "--group", "dev", "--group", "docs"]],
    ),
    "fmt": ("Format.", [_run("ruff", "format", ".")]),
    "lint": (
        "Lint and check formatting.",
        [_run("ruff", "check", "."), _run("ruff", "format", "--check", ".")],
    ),
    "typecheck": ("Type check under mypy --strict.", [_run("mypy")]),
    "test": (
        "Run the whole test suite with the coverage gate.",
        [_run("pytest", "--cov", "--cov-report=term-missing", "--cov-fail-under=90")],
    ),
    "test-unit": ("Unit tests only.", [_run("pytest", "-m", "unit")]),
    "test-integration": ("Integration tests only.", [_run("pytest", "-m", "integration")]),
    "test-security": (
        "Adversarial tests only. A failure here is a security regression.",
        [_run("pytest", "-m", "security")],
    ),
    "test-e2e": (
        "End-to-end tests only: the CLI as a real process.",
        [_run("pytest", "-m", "e2e")],
    ),
    "test-meta": (
        "The gates' own negative controls: break one thing, assert it goes red.",
        [_run("pytest", "-m", "meta")],
    ),
    # -- the shipped corpora, rebuilt from nothing -------------------------
    "corpus": (
        "Regenerate the shipped corpora. The holdout excludes the training set.",
        [
            _pifw("synth", "--plan", "main", "--out", CORPUS),
            _pifw(
                "synth",
                "--plan",
                "holdout",
                "--out",
                HOLDOUT,
                "--disjoint-from",
                CORPUS,
            ),
        ],
    ),
    "corpus-check": (
        "Do the committed corpora still match their plans? The CI check.",
        [
            _pifw("check", "--plan", "main", "--corpus", CORPUS),
            _pifw("check", "--plan", "holdout", "--corpus", HOLDOUT, "--disjoint-from", CORPUS),
        ],
    ),
    "train": (
        "Train the learned layer on the shipped corpus.",
        [_pifw("train", "--corpus", CORPUS, "--out", MODEL)],
    ),
    "evaluate": (
        "The leave-one-family-out evaluation, gated against the committed baseline.",
        [
            _pifw(
                *_EVALUATE,
                "--json-out",
                "reports/evaluation.json",
                "--junit-out",
                "reports/evaluation.xml",
                "--markdown-out",
                "reports/evaluation.md",
            )
        ],
    ),
    "baseline": (
        "Re-record the committed baseline. Commit the result on its own.",
        [_pifw(*_EVALUATE, "--update-baseline")],
    ),
    "calibrate": (
        "Print the threshold each layer needs to meet the false-positive budget.",
        [_pifw("calibrate", "--corpus", HOLDOUT)],
    ),
    "rules": (
        "List the detection stack and which family motivated each part of it.",
        [_pifw("rules")],
    ),
    "check-firewall": (
        "Assert the gates fire: the shipped binary against the shipped corpora.",
        [_run("python", "scripts/check-firewall.py")],
    ),
    "doctor": (
        "Check that this installation works end to end.",
        [_pifw("doctor")],
    ),
    "examples": (
        "Run every example. They are documentation that executes.",
        [
            _run("python", "examples/quickstart.py"),
            _run("python", "examples/false_positive_demo.py"),
            _run("python", "examples/unseen_technique_demo.py"),
        ],
    ),
    "site": (
        "Build the documentation site into _site.",
        [_run("--only-group", "docs", "python", "scripts/build_site.py", "--output", "_site")],
    ),
    "security": (
        "Local security scans.",
        [
            _run("bandit", "-c", "pyproject.toml", "-r", "src", "-f", "screen"),
            [
                "uv",
                "export",
                "--locked",
                "--no-emit-project",
                "--no-hashes",
                "--output-file",
                "requirements.audit.txt",
            ],
            [
                "uv",
                "tool",
                "run",
                "pip-audit",
                "--strict",
                "--no-deps",
                "--requirement",
                "requirements.audit.txt",
            ],
        ],
    ),
    "docker-build": (
        "Build the container image.",
        [["docker", "build", "-t", f"{IMAGE}:local", "."]],
    ),
    "smoke": (
        "Build the image and run the smoke test against it.",
        [
            ["docker", "build", "-t", f"{IMAGE}:local", "."],
            ["bash", "scripts/smoke-test.sh", f"{IMAGE}:local"],
        ],
    ),
}

#: The order CI runs things in, cheapest gate first. Formatting and typing fail
#: in seconds; the evaluation takes minutes. A developer who broke an import
#: should learn that before the suite has finished collecting.
ALL = (
    "lint",
    "typecheck",
    "test",
    "corpus-check",
    "evaluate",
    "check-firewall",
    "examples",
    "site",
)

# Expanded here rather than special-cased in the runner: tasks.py runs whatever
# command list it finds, and a task carrying an empty one would print nothing
# and exit 0. Nothing about that looks wrong on a terminal, which is what makes
# it worth catching.
TASKS["all"] = (
    "Everything CI runs, in the order CI runs it.",
    [step for name in ALL for step in TASKS[name][1]],
)
