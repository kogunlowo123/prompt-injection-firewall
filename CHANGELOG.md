# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this repository's deliverable is a **measurement**, one extra rule
applies: any release that changes a published number says which number, what it
was, what it became, and why. A changelog entry that reports an improvement
without naming its cost is the failure mode this project exists to argue
against.

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-09-08

First release.

### Added

- **A prompt-injection firewall that publishes its own bypass rate.**
  Normalisation, 21 bounded rules, 7 structural signals and a learned layer over
  BLAKE2b-hashed n-grams, behind a `Firewall` with `monitor` and `enforce`
  modes.
- **Leave-one-family-out evaluation.** Every rule, normalisation stage and
  structural signal declares the attack families that motivated it; the harness
  reads that field and disables a held-out family's countermeasures along with
  the family itself. The result is the detector somebody would have built if the
  technique had never occurred to them, measured against it.
- **A generated corpus.** 12 attack families and 8 benign kinds, four of the
  benign kinds written as hard negatives. Both corpora are byte-reproducible
  from a seeded plan and gated by SHA-256 digest; the holdout is disjoint from
  the training set **by construction** rather than by filtering afterwards.
- **Wilson score intervals on every rate.** Zero out of 140 is reported as zero
  with a 95% upper bound of 2.67%, not as "0%".
- **A baseline regression gate.** `examples/baseline.json` records what was
  measured; `pifw evaluate` fails on a per-family regression, a pooled
  regression, a control regression, a family that stopped being measured, a
  family the baseline has never heard of, or a run over its false-positive
  budget.
- **Negative controls for the gates themselves.** `scripts/check-firewall.py`
  runs the shipped binary against baselines constructed to fail and asserts the
  exit code is 2. A gate only ever observed passing is indistinguishable from
  `true` in a shell script.
- **An audit record** that stores a salted digest, the score, the per-layer
  scores and the named evidence — but not the prompt, unless explicitly asked.
  Recording never raises on the request path.
- CLI: `synth`, `check`, `train`, `scan`, `evaluate`, `calibrate`, `audit`,
  `rules`, `doctor`. Exit codes are part of the interface: 0 held, 1 usage,
  2 gate failed, 3 could not run.
- Five test layers — unit, integration, security, e2e and meta — with a 90%
  coverage gate.
- A container image that runs as a non-root user and can re-derive its own
  corpora, a documentation site, and CI covering lint, types, tests, coverage,
  the evaluation, the examples, the wheel, secrets, dependencies and CodeQL.

### Measured, and worth reading before the code

Three results changed what this project ships. Each was a number that looked
exactly like a measurement until it was checked.

- **Training to a fixed step count reported 40.47%; training to convergence
  reported 20.89%.** A fixed 400 steps of plain gradient descent had not
  converged. Replaced with heavy-ball descent to a gradient tolerance, and the
  harness now **refuses to report any bypass rate** for a fold whose model hit
  the iteration ceiling.
- **The three-layer noisy-OR ensemble measures ten times worse than one of its
  own inputs.** At a shared 1% false-positive budget the rules bypass at 93.75%,
  the structural signals at 83.69%, the learned layer at **2.08%** — and all
  three combined at 20.89%. The rule and structural layers fire on
  documentation, code and imperative English, so mixing them in pushes the
  threshold from 0.11 to 0.79, above attacks the learned layer had ranked
  correctly. Re-measuring at a matched *realised* false-positive rate leaves
  every fold unchanged, so this is not an operating-point artefact.

  **The decision score is therefore the learned layer alone.** The rule and
  structural layers stay as evidence: computed, named in every verdict, written
  to the audit record. **The cost:** the realised false-positive rate rose from
  1.25% to 1.84%. Both halves are published.
- **Holding out the vocabulary as well as the technique does not move the
  result.** The families share slot vocabularies by design, which leaves a
  held-out family's lexicon in training through the other eleven.
  `scripts/lexicon-holdout.py` measures that directly: with disjoint lexicons,
  `hypothetical` and `indirect` stay at 0.00% and `homoglyph` moves to 5.00% —
  three samples, on an interval straddling zero. What still cannot be held out
  is the **grammar** that generates both halves, which is the ceiling on any
  synthetic evaluation and the reason the audit record exists.

### Security

- Two real bypasses were found by `tests/security/test_adversarial.py`, which
  composes obfuscations rather than testing them one at a time. Every individual
  stage passed its own unit test throughout:
  - character normalisation ran **before** decoding, so one line of base64
    around a homoglyph payload defeated confusable folding entirely. The
    character stages now run a second time after any expanding stage.
  - zero-width characters are `isprintable() == False`, so sprinkling them
    inside a payload before encoding pushed the decoder's printability ratio
    under threshold and it discarded the blob as binary. Unicode `Cf` characters
    now count as printable for that test.
- No credentials anywhere: the package authenticates to nothing, downloads
  nothing and calls no model API. A test asserts the generated corpora contain
  no credential-shaped string and that `Settings` has no key-like field.
- Every regex is bounded, with no nested quantifiers, and a test asserts it over
  the whole table — this code runs on attacker-supplied text in front of the
  thing it protects.
- `Firewall` refuses to construct in enforce mode without a recorder. Blocking
  traffic while keeping no evidence of having done so leaves nobody able to tell
  a working firewall from a broken one.

[Unreleased]: https://github.com/kogunlowo123/prompt-injection-firewall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kogunlowo123/prompt-injection-firewall/releases/tag/v0.1.0
