# prompt-injection-firewall

**A prompt-injection firewall that publishes its own bypass rate.**

[![CI](https://github.com/kogunlowo123/prompt-injection-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/kogunlowo123/prompt-injection-firewall/actions/workflows/ci.yml)
[![Security](https://github.com/kogunlowo123/prompt-injection-firewall/actions/workflows/security.yml/badge.svg)](https://github.com/kogunlowo123/prompt-injection-firewall/actions/workflows/security.yml)
[![Docs](https://github.com/kogunlowo123/prompt-injection-firewall/actions/workflows/pages.yml/badge.svg)](https://kogunlowo123.github.io/prompt-injection-firewall/)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Prompt injection has no known reliable defence. This does not claim one.

It detects a measurable share of injection attempts, measures that share
**against techniques it was not built for**, publishes the false-positive cost
in the same table, and keeps measuring after deployment by recording what it let
through.

---

## The headline

Calibrated at a **1% false-positive budget** on benign traffic. 3,120 training
attacks across 12 technique families, 1,680 held-out attacks from a corpus
generated with the training corpus excluded.

| Measurement | Bypass rate | 95% interval |
| --- | --- | --- |
| **Unseen technique** — leave-one-family-out | **2.08%** | 1.50% – 2.88% |
| Seen technique — random split | 0.00% | 0.00% – 2.67% |

**Read the per-family table below, not that pooled figure.** 2.08% is eleven
zeros and one 25%; its mean describes no fold that was actually run.

The two arms share a *budget*, not a threshold. Each is calibrated to cost 1% of
the same benign calibration set; see [ADR-003](ARCHITECTURE.md#adr-003--both-arms-share-a-budget-not-a-threshold).

### Per family, with that family's own countermeasures held out

| Family | Bypass | 95% interval | AUC | What the fold removed |
| --- | --- | --- | --- | --- |
| `encoding_wrapper` | **25.00%** | 18.56% – 32.78% | 0.970 | 2 rules, the decode stage |
| `authority_claim` | 0.00% | 0.00% – 2.67% | 1.000 | 2 rules |
| `delimiter_escape` | 0.00% | 0.00% – 2.67% | 1.000 | 3 rules |
| `direct_override` | 0.00% | 0.00% – 2.67% | 1.000 | 3 rules |
| `exfiltration` | 0.00% | 0.00% – 2.67% | 1.000 | 3 rules, 1 signal |
| `homoglyph` | 0.00% | 0.00% – 2.67% | 1.000 | NFKC, zero-width, confusable folding |
| `hypothetical` | 0.00% | 0.00% – 2.67% | 1.000 | 1 rule |
| `indirect` | 0.00% | 0.00% – 2.67% | 1.000 | 1 rule |
| `payload_splitting` | 0.00% | 0.00% – 2.67% | 1.000 | 1 rule, the reassembly stage |
| `refusal_suppression` | 0.00% | 0.00% – 2.67% | 1.000 | 1 rule |
| `role_assumption` | 0.00% | 0.00% – 2.67% | 1.000 | 2 rules |
| `translation_pivot` | 0.00% | 0.00% – 2.67% | 1.000 | 2 rules |

Eleven zeros is not eleven perfect scores. A fold holds 140 attacks, so zero out
of 140 is zero **with a 95% upper bound of 2.67%** — that bound is the ceiling
this corpus can demonstrate, and it is what the pooled interval is made of.

One family survives, and the pattern is the finding:

> **What generalises across techniques is the payload. What does not is the
> transport.** `direct_override` is one of the *easiest* folds at 0.00%, even
> with every override rule switched off, because eleven other families embed the
> same instruction and the learned layer has seen thousands of examples of it.
> `encoding_wrapper` survives because it hides the payload inside base64 and its
> own fold disables the decoder — the words that would have been recognised are
> not in the message at all. A new technique reusing a familiar payload will
> probably be caught. A new **transport** will not.

Read the AUC column next to the bypass column. `encoding_wrapper` ranks at 0.970
— it orders attacks above benign traffic almost perfectly — and still misses a
quarter of them, because ranking well says nothing about where the threshold had
to go to stay inside the budget. **AUC is not an operating point.**

### Every false positive is the security team's own documentation

At the same 1% budget, measured per kind of benign traffic:

| Kind of benign traffic | n | Flagged | Hard negative? |
| --- | --- | --- | --- |
| `security_docs` — threat models quoting real payloads | 72 | **23.61%** | yes |
| `encoding_question` — "what does this base64 decode to?" | 72 | 1.39% | yes |
| `credential_hygiene` | 54 | 0.00% | |
| `imperative` — "ignore the whitespace and diff these" | 126 | 0.00% | yes |
| `markup` — code, XML and logs containing `</system>` | 108 | 0.00% | yes |
| `multilingual` | 54 | 0.00% | |
| `ordinary` | 306 | 0.00% | |
| `role_request` — "act as a Python tutor" | 108 | 0.00% | yes |
| **Overall** | **900** | **2.00%** | |

Not a diffuse two percent spread thinly. **Seventeen of the eighteen false
positives are text *about* prompt injection** — lexically identical to the
attack corpus, because it is generated by the same grammar, and distinguished
only by the sentence around it.

A guardrail whose only false positives land on the security team's own runbook
is a guardrail the security team switches off, and that is invisible in an
aggregate number. `python examples/false_positive_demo.py`.

---

## Quickstart

```bash
uv sync --group dev
python tasks.py doctor          # does this installation work?
python examples/quickstart.py   # the firewall in forty lines
```

```python
from pifw import Detector, Firewall, Recorder
from pifw.model.logistic import Model

firewall = Firewall(
    Detector(model=Model.load("examples/model.json")),
    recorder=Recorder("var/decisions.jsonl"),
)

outcome = firewall.run(user_message, call_your_model)
if outcome.decision != "allow":
    escalate(outcome.verdict.explain())  # "flag at 0.986 (indirect.addressed_to_model, ...)"
```

Default mode is **monitor**: a flagged message is recorded and surfaced, and the
model is still called. A firewall with a 20% bypass rate that blocks by default
teaches its operator to stop checking. `enforce` mode exists and refuses to be
constructed without a recorder — blocking traffic while keeping no evidence of
doing so leaves nobody able to tell a working firewall from a broken one.

---

## How it works

Three layers over a normalised message. **One of them decides; the other two
explain.** That split was measured, not assumed, and it is the most interesting
result in the repository — see [the layer table](#which-layer-is-actually-doing-the-work).

**Normalisation** — NFKC, zero-width stripping, script-confusable folding,
whitespace, base64/hex/ROT13/reversal decoding, fragment reassembly, casefold,
then the character stages **again**. That last step is not tidiness: decoding
appends text the character stages have never seen, so without it a homoglyph
payload wrapped in one line of base64 defeats homoglyph folding entirely.

> **NFKC is not a confusable defence.** It folds compatibility variants, so it
> undoes the fullwidth block — but Cyrillic `е` and Latin `e` are different
> letters in different scripts and NFKC leaves them alone by design. Folding
> them needs an explicit table.

**Rules** — 21 bounded regexes, each with a weight and a recorded provenance.
Auditable and cheap; a verdict naming `exfil.reveal_prompt` tells an on-call
engineer more than a score of 0.83 does. They are **evidence, not score**, for
the reason directly below.

**Structural signals** — seven measurements of *shape* rather than of words:
script mixing inside a word, zero-width density, how much text normalisation had
to decode. Two of the seven are family-agnostic and survive every fold.

**A learned layer** — logistic regression over BLAKE2b-hashed n-grams, in NumPy,
trained to a gradient tolerance in about ten seconds. Convex, so no seed, no
initialisation, no shuffle order. No network call, no model download, no
credentials: a firewall that needs an outbound request has added an availability
dependency to the request path it was meant to protect.

Every rule, stage and signal declares which attack families motivated it, and
the evaluation reads that field — see below.

### Which layer is actually doing the work

Each layer scored on its own, calibrated to the same 1% budget on the same
benign traffic, across the same twelve folds:

| Arm | Unseen bypass | Realised FPR | 1% threshold lands at |
| --- | --- | --- | --- |
| `rules` — 21 regexes | 93.75% | 0.68% | 0.500 – 0.843 |
| `signals` — 7 structural measurements | 83.69% | 1.16% | 0.150 – 0.300 |
| **`model`** — logistic regression | **2.08%** | 1.84% | 0.109 – 0.118 |
| `combined` — noisy-OR of all three | 20.89% | 1.25% | 0.603 – 0.797 |

**The obvious ensemble is ten times worse than one of its own inputs.** The rule
and structural layers fire on documentation, code and imperative English, so
mixing them in raises the benign score tail and pushes the 1% threshold from
0.11 to 0.79 — above attacks the learned layer had already ranked correctly.
Eleven of twelve folds go from 0% to non-zero purely by adding them. Re-running
the model at the ensemble's *realised* false-positive rate changes nothing, so
this is not the model buying its result with a looser operating point.

So the shipped score is the learned layer alone, and the regex layer everyone
ships — including the version of this project that existed a week ago —
contributes no detection lift at a usable operating point. It stays for what it
is genuinely good at: naming which pattern fired, in the verdict and in the
audit record.

The cost is published too. Dropping two layers from the score raised the
realised false-positive rate from 1.25% to 1.84%. That is the trade.
[ADR-016](ARCHITECTURE.md#adr-016--the-decision-score-is-one-layer-because-the-measurement-said-so),
[docs/detection.md](docs/detection.md).

---

## Why the evaluation is built this way

A detector is built by people who have a list of attacks. They write rules
against that list, add normalisation against the tricks on that list, train a
classifier on that list, split it at random, and publish. Every attack in the
resulting test set is a rewording of something the detector was built against.

This holds out an entire **technique**, and — the part that is usually skipped —
holds out the countermeasures that technique motivated. In the `homoglyph` fold
the confusable-folding stage is switched off along with the family. What is left
is the detector somebody would have built if the technique had never occurred to
them, evaluated against it.

The predictable consequence is that the obfuscation families score badly. That
result is on the front page rather than buried, because it is the honest form of
the only reliable finding in this field: **you do not defend against a technique
you have not seen.**

```bash
python examples/unseen_technique_demo.py   # the argument, in about a minute
```

---

## What it does not do

* It does not stop prompt injection. Nothing does.
* It inspects **input**. Model output, and downstream effects, are out of scope.
* It scores each message alone. A payload assembled across five turns has no
  single turn that looks like anything.
* It sees text. Images, audio and files are not inspected.
* It measures *detection*, not exploitation. A detected injection the model
  would have ignored and an undetected one the model obeys score identically.
* Its number covers twelve families. Real traffic contains techniques nobody has
  enumerated, and the leave-one-family-out result is the best available evidence
  about those: for the families whose disguise nothing else teaches, close to
  everything gets through.

This is a defence-in-depth layer, not a boundary. Anything downstream that would
be catastrophic if an injection succeeded needs its own control. See
[THREAT-MODEL.md](THREAT-MODEL.md).

---

## The corpus

Twelve attack families and eight kinds of benign traffic, all generated from
seeded grammars — reproducible, license-clean, and useless as a ready-made
attack library while remaining a fair test of whether a detector generalises.
Not scraped jailbreaks. No credential-shaped string appears anywhere in it, and
a test asserts that.

The holdout corpus is generated **with the training corpus excluded**, so
disjointness is a property of how it was built. That matters more than it
sounds: before it was done this way, 568 of 3,480 holdout samples also appeared
in training, and the overlap was badly skewed — `credential_hygiene` lost 65% of
its samples while every attack family lost under 20%. Dropping the overlap
afterwards left the benign side quietly easier than designed.

```bash
python tasks.py corpus         # regenerate both
python tasks.py corpus-check   # do the committed ones still match their plans?
```

---

## The gates

`python tasks.py all` runs what CI runs, cheapest first. Three of them are
unusual enough to describe:

**Training must converge, or no number is reported.** An early version of this
project trained for a fixed 400 steps and reported a headline bypass rate of
40.47% where the same code trained to convergence reported 20.89%. Both outputs
looked exactly like a measurement. The harness now refuses — no bypass rate at
all — for a fold whose model hit the iteration ceiling.

**The gate is a baseline comparison, not an absolute budget.** Per-family rates
run from 0% to 25%; any ceiling admitting `encoding_wrapper` is far too high to
notice a good family getting worse. `examples/baseline.json` records what was
measured; CI fails on a regression past five points. A family in the run that
the baseline has never heard of is a **failure**, not a pass.

**The gates have their own negative controls.** `scripts/check-firewall.py` runs
the shipped binary against the shipped corpora and asserts that the gate fires
on an injected regression, fires on a fold that stopped running, refuses without
a baseline, and refuses to report a number from an undertrained model. A gate
only ever observed passing is indistinguishable from `true` in a shell script.

---

## Documentation

| | |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The shape of it, and fifteen decisions with their reasons |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What it detects, and attacks on the firewall itself |
| [docs/attacks.md](docs/attacks.md) | The twelve families, and why each is a technique |
| [docs/detection.md](docs/detection.md) | The three layers, measured separately |
| [docs/evaluation.md](docs/evaluation.md) | Leave-one-family-out, in full |
| [docs/false-positives.md](docs/false-positives.md) | The benign corpus, and why it is adversarial |
| [docs/policy.md](docs/policy.md) | Monitor, enforce, and the audit record |
| [docs/reproducibility.md](docs/reproducibility.md) | Digest gates, tolerance gates, and why they differ |
| [docs/ci.md](docs/ci.md) | Every job, and what makes it fail |

---

## Development

```bash
python tasks.py               # list the tasks
python tasks.py all           # everything CI runs
python tasks.py test-security # adversarial cases only
python tasks.py test-meta     # the gates' own negative controls
python tasks.py smoke         # build the container and exercise it
```

256 tests across five layers, 92% coverage. Python 3.12, uv, ruff, mypy
`--strict`, bandit, pip-audit, CodeQL, gitleaks.

Exit codes are the interface: **0** held, **1** usage error, **2** a gate
failed, **3** could not run. The distinction between 2 and 3 is the one that
matters in CI — "not evaluated" is not "passed", and a pipeline that treats any
non-zero code alike will retry a broken run until it flakes green.

## License

MIT. See [LICENSE](LICENSE).
