# Continuous integration

Six workflows. The organising rule is that **every gate can fail for a reason
somebody can act on**, and that no job prints a success it did not earn.

## What runs on every pull request

`.github/workflows/ci.yml`, six jobs, ordered cheapest first. A developer who
broke an import should learn that in seconds rather than after the twelve-fold
evaluation has finished.

| Job | What it proves | Typical time |
| --- | --- | --- |
| `quality` | ruff lint, ruff format, `mypy --strict`, and the docs site builds | ~1 min |
| `test` | Five matrix legs, one per pytest marker: `unit`, `integration`, `security`, `e2e`, `meta` | ~2 min |
| `coverage` | The whole suite again, with `--cov-fail-under=90` | ~2 min |
| `gates` | `doctor`, the corpus digest check, the twelve-fold evaluation against the committed baseline, and the gate's own negative controls | ~15 min |
| `examples` | All three example scripts run to completion | ~5 min |
| `build` | The wheel builds, installs into a clean environment, and its console script works | ~1 min |

### Why the test matrix is separate from the coverage job

The matrix legs run bare, with no coverage flag. A leg that inherited
`--cov-fail-under` would fail on every layer except the full run — the unit
tests alone do not cover the CLI — and it would fail for a reason that has
nothing to do with the layer it is reporting on. Splitting them means a red
`security` leg means a security regression, and a red `coverage` job means
coverage.

### Why `build` installs the wheel

Building is not the same as being installable. A source checkout has the package
directory on the path anyway, so a missing `packages` entry or a broken console
script entry point is invisible locally and fails on the first user. The job
installs the built wheel into a fresh virtual environment and runs `pifw
--version` and `pifw rules` from it.

### What the `gates` job actually gates

Four failure modes, all of which exit non-zero:

1. **A corpus that no longer matches its plan.** `pifw check` re-derives it from
   the plan and compares SHA-256 digests. The holdout check also re-asserts
   disjointness from the training corpus, because a holdout that quietly
   overlaps its training set reports optimism as detection.
2. **A regression against the committed baseline.** Per family, pooled, and in
   the random-split control, with a tolerance. Also a family in the baseline
   that this run did not measure, and a family measured that the baseline does
   not carry — a gate that silently ignores a missing family is a gate that
   stops noticing a deleted one.
3. **Exceeding the false-positive budget.**
4. **A fold whose model did not converge.** The evaluation refuses to report a
   bypass rate rather than publishing one — see
   [ADR-009](../ARCHITECTURE.md#adr-009--training-runs-to-convergence-or-reports-no-number).
   An undertrained model produces a number that looks exactly like a
   measurement, which is what makes it worth refusing.

`scripts/check-firewall.py` then asserts the gate itself is alive: it constructs
baselines that *should* fail, runs the real binary against them, and checks the
exit code is 2 rather than 0. A gate nobody has watched go red is a gate nobody
knows the exit code of. It is the difference between CI that verifies and CI
that prints.

Exit codes are part of the interface, so the meta tests pin them:

| Code | Meaning |
| --- | --- |
| 0 | The gate held |
| 1 | Usage error — bad arguments, missing file |
| 2 | A gate failed, or the run refused to report a number |
| 3 | Could not run at all |

`argparse` exits 2 on a usage error by default, which would be indistinguishable
from a failed gate. `_Parser` in `src/pifw/cli.py` subclasses `error()` to exit 1
instead, and an end-to-end test asserts it.

## Security

`.github/workflows/security.yml`, on every pull request and on a weekly
schedule. The schedule matters: a dependency that was clean on the day it was
merged is not clean forever, and nothing about the repository changes on the day
an advisory is published.

| Check | What it looks for |
| --- | --- |
| `bandit` | Static analysis over `src/`. Findings are fixed or annotated with a justification, never suppressed wholesale |
| `pip-audit` | Every package in `uv.lock`, audited as resolved with `--no-deps`. HIGH or CRITICAL fails the build |
| `gitleaks` | Secrets, over the **full history** rather than the diff |
| CodeQL | The `python` query pack, on push and weekly |

`pip-audit` runs against the exported lockfile rather than re-resolving, because
`uv.lock` is what actually ships and a re-resolution audits a set nobody will
install. Exceptions are time-boxed and justified in
[`security/audit-exceptions.md`](../security/audit-exceptions.md); an identifier
in `security/audit-ignores.txt` without a dated entry there is a review failure.

Gitleaks scanning full history is deliberate. A secret committed and then
removed in the next commit is still in the history, still fetched by every
clone, and a diff-only scan reports it clean.

## Container

`.github/workflows/docker.yml` builds the image and runs `scripts/smoke-test.sh`
against it. The smoke test exercises the container the way an operator would —
`doctor`, a scan on stdin, the rules table — and asserts it runs as a non-root
user with no writable filesystem outside `var/`.

An image that builds is not an image that works. The most common failure this
catches is an editable install leaking into the runtime stage, where the `.pth`
file points at a build directory that no longer exists and the container dies
with an `ImportError` at start.

## Documentation

`.github/workflows/pages.yml` builds `docs/` into a static site and publishes it
on pushes to `main`. The builder fails on a broken internal link, so a renamed
page fails the pull request instead of shipping a 404.

## Dependencies

`.github/dependabot.yml` watches `uv.lock` and the Actions used by these
workflows, weekly, grouped so that a routine bump is one pull request rather
than nine.

Actions are pinned by major version and Python by exact minor. The project pins
`>=3.12,<3.13`, so testing on anything else would be testing a configuration
nobody can install.

## Running the same thing locally

```bash
python tasks.py all
```

runs the CI sequence in the CI order: lint, typecheck, the suite with the
coverage gate, the corpus check, the evaluation, the gate's own negative
controls, every example, and the docs build. `python tasks.py --list` prints the
whole table.

`tasks.py` is the source of truth and the `Makefile` delegates to it, so the two
cannot drift.

## See also

- [CONTRIBUTING.md](../CONTRIBUTING.md) — the local workflow
- [docs/reproducibility.md](reproducibility.md) — which artefacts are gated how
- [SECURITY.md](../SECURITY.md) — reporting a vulnerability
