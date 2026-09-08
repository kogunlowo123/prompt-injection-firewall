# Architecture

## The shape of the thing

```
                    ┌──────────────────────────────────────────┐
   untrusted text → │  normalise                               │
                    │    nfkc → zero-width → confusables →     │
                    │    whitespace → decode → reassemble →    │
                    │    casefold → (character stages again)   │
                    └──────────────────┬───────────────────────┘
                                       │ normalised text
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
     ┌────────────────┐      ┌──────────────────┐     ┌──────────────────┐
     │ rules          │      │ structural       │     │ learned          │
     │ 21 regexes,    │      │ signals          │     │ logistic         │
     │ each with a    │      │ 7 measurements   │     │ regression over  │
     │ weight and a   │      │ of shape rather  │     │ hashed n-grams   │
     │ provenance     │      │ than of words    │     │                  │
     └───────┬────────┘      └────────┬─────────┘     └────────┬─────────┘
             │                        │                        │
             │  evidence: named in    │  evidence, and the     │  THE SCORE
             │  the verdict and the   │  model-less fallback   │
             │  audit record          │                        │
             └────────────────────────┴───────────┬────────────┘
                                                  ▼
                                    ┌───────────────────────────┐
                                    │ decision score in [0, 1]  │
                                    │ = the learned layer, when │
                                    │   a model is loaded       │
                                    │ (the noisy-OR of all      │
                                    │  three is still computed  │
                                    │  and recorded: ADR-016)   │
                                    └─────────────┬─────────────┘
                                                  ▼
                      ┌───────────────────────────────┐
                      │ threshold, calibrated on      │
                      │ benign traffic at a 1% budget │
                      └───────────────┬───────────────┘
                                      ▼
                          allow  /  flag  /  block
                                      │
                                      ▼
                            append-only audit record
                            (salted digest, not text)
```

Everything to the left of the ensemble is measurable in isolation, and the
evaluation measures each layer separately for exactly that reason.

## Decisions

Written as ADRs because the interesting part of this repository is *why*, and a
reader who disagrees with a decision should be able to find the argument rather
than reverse-engineer it.

### ADR-001 — The deliverable is a bypass rate, not a defence

Prompt injection has no known reliable defence. A repository claiming one would
be wrong, and worse than nothing, because it would give its user confidence they
have not earned.

So the headline number is the share of attacks that **got through**, not the
share caught. It is the same arithmetic pointed the other way, and the direction
changes what a reader does with it: "96% recall" invites a nod, "4% of attacks
reach the model" invites the question of whether 4% is survivable for this
application. The second question is the one worth asking.

**Consequence:** every claim in the README is a measurement with a confidence
interval, and the uncomfortable number is on the first screen.

### ADR-002 — Evaluation holds out techniques, not wordings

The conventional methodology builds a detector from a list of attacks, splits
that list at random, and reports the result. Every attack in the resulting test
set is a rewording of something the detector was built against, so the number
describes recognition of the familiar. It says nothing about a technique that
was not on the list, and a technique that was not on the list is the only kind
that matters.

Leave-one-family-out holds out a whole *technique*, and — the part that is
usually skipped — holds out the countermeasures that technique motivated. The
rules written against `delimiter_escape` are switched off in the
`delimiter_escape` fold, along with the normalisation stages and structural
signals that exist because of it. Every rule, stage and signal in this codebase
declares a `motivated_by` set, and that field is read by the harness rather than
being documentation.

**Consequence:** measured here, the gap between the two methodologies is
**+20.9 points of bypass rate**. See [docs/evaluation.md](docs/evaluation.md).

### ADR-003 — Both arms share a budget, not a threshold

Thresholds are calibrated on benign traffic at a fixed false-positive budget,
and the bypass rate is read off afterwards. The reverse order — pick a threshold
that makes the bypass rate look good, report the resulting false-positive rate
in a footnote — is how two detectors become incomparable.

Each fold's detector and the control's detector are *different detectors*, so
each gets the threshold that costs **it** 1% of the same benign calibration set.
Holding the numeric threshold fixed across them would mean the two arms were
paying different false-positive prices, which is the thing calibration exists to
prevent. The report prints every threshold so the difference is visible rather
than asserted.

### ADR-004 — Calibrate on one half of benign traffic, measure on the other

Calibrating a threshold and then measuring the false-positive rate on the same
samples reports the target budget back at you no matter what the detector does.
The benign holdout is split by alternating index — not by a shuffle, because
benign samples come out of the generator grouped by kind and alternating splits
every kind evenly without needing a seed, and a split that needs no seed cannot
be accidentally reseeded into a different answer.

Measured, the realised false-positive rate comes out at **1.84%** against a 1.0%
budget. That gap is the honest cost of calibrating on a different sample, and it
widened when the decision score changed: the rejected three-layer combination
realised 1.25% on the same halves. The learned layer's benign scores are steep
near its operating point, so a small error in the threshold becomes a large one
in the rate. See [ADR-016](#adr-016--the-decision-score-is-one-layer-because-the-measurement-said-so).

### ADR-005 — The benign corpus is adversarial on purpose

A false-positive rate measured against "what is the capital of France" is a
formality. Four of the eight benign kinds are hard negatives, and the hardest is
`security_docs`: text *about* prompt injection, quoting real payloads generated
by the same grammar. Lexically it is the attack corpus; the only difference is
the sentence around it.

**Consequence, and the second published finding:** at a 1% budget, **every
single false positive is `security_docs`** — 25% of that kind, and 0.00% of
every other kind. A guardrail whose only false positives are on the security
team's own documentation is a guardrail the security team will switch off. That
is invisible in an aggregate number and is why the report breaks it out by kind.

### ADR-006 — Noisy-OR, not a sum

Three rules firing on the same clause is one observation, not three. A sum lets
overlapping patterns reach a confident total from a single piece of evidence;
noisy-OR treats each layer as independent evidence, is order-free, and cannot
exceed one. Layer reliabilities are constants set once and never fitted per
fold, because tuning them per fold would be fitting to the held-out family
through the back door.

Superseded in part by [ADR-016](#adr-016--the-decision-score-is-one-layer-because-the-measurement-said-so):
noisy-OR is still how rule hits combine within a layer, and how the model-less
fallback combines the two non-learned layers, but it is no longer how the
decision score is formed. The three-layer combination measured worse than one of
its own inputs.

### ADR-007 — Monitor by default; enforce is a decision somebody makes

A firewall with a measured bypass rate above zero — which is every firewall in
this field — that blocks by default teaches its operator to stop checking. The
default decision for a high score is `flag`, which records and surfaces the
message and still calls the model.

`enforce` mode exists, and constructing a firewall in enforce mode **without a
recorder raises**. Blocking traffic while keeping no evidence of having done so
leaves nobody able to distinguish a working firewall from a broken one.

### ADR-008 — The record holds a digest, not the prompt

A log of every message users sent an assistant is a data-protection problem that
arrives bundled with the mitigation. The audit record stores a salted SHA-256
prefix, the length, the score, the decision and the rule names. Keeping the text
is available and opt-in.

The salt comes from `PIFW_RECORD_SALT` or is generated per process. `Recorder`
exposes `salt_is_stable`, and `pifw audit` says when digests will not correlate
across runs — finding that out by noticing nothing ever matches is expensive.
The digest is a **pseudonym, not an anonymisation**: the space of short prompts
is small enough to enumerate, and the docstring says so.

### ADR-009 — Training runs to convergence, or reports no number

The first version trained for a fixed 400 steps of plain gradient descent and
produced a headline bypass rate of **40.47%**. The same code trained to
convergence gives **20.89%**. Both outputs looked exactly like a measurement.

Training now runs heavy-ball descent to a gradient tolerance and carries a
`converged` flag, and the evaluation **refuses** — no bypass rate at all — for a
fold whose model hit the iteration ceiling. A number measured from an
undertrained model is a statement about the optimiser, and it is
indistinguishable from a statement about the firewall.

### ADR-010 — The holdout is disjoint by construction, not by hope

Two seeded walks over the same grammar are not disjoint. Measured before this
was fixed: **568 of 3,480** holdout samples also appeared in training, and the
overlap was badly skewed — `credential_hygiene` lost 65% of its samples and
`markup` 47%, while every attack family lost under 20%. Dropping the overlap
afterwards left the *benign* side quietly easier than it was designed to be, and
every false-positive rate measured on it correspondingly quietly better.

The holdout is now generated with the training corpus excluded, so disjointness
is a property of how it was built. `--drop-shared` remains for corpora somebody
else supplies, and reports the count rather than absorbing it.

### ADR-011 — Character normalisation runs twice

Found by the security test layer, and live until two obfuscations were combined
in one input. Decoding *appends* text the character stages have never seen,
because it did not exist when they ran — so a homoglyph payload wrapped in
base64 arrived as plain ASCII, nothing folded, and the Cyrillic turned up
afterwards. One line of base64 defeated the entire homoglyph defence while every
individual stage passed its own unit test.

The same test found a second bypass in the same input: zero-width characters are
`isprintable() == False`, so sprinkling them *inside* the payload before
encoding pushed the decoder's printability ratio under threshold and it
discarded the blob. Format characters now count as printable for that test.

Both are the argument for a security layer that composes techniques rather than
testing them one at a time.

### ADR-012 — The gate is a baseline comparison, not an absolute budget

Per-family bypass rates here run from 0.00% on eleven families to 25.00% on
`encoding_wrapper` — and under the combination this project rejected they ran to
100.00%. Any ceiling high enough to admit the worst family is far too high to
notice a good one getting worse, and `max_family_bypass = 1.0` is a gate that
passes whatever happens.

`examples/baseline.json` records what this firewall measured. CI re-measures and
fails on a regression beyond a five-point tolerance. Three properties that are
easy to leave out:

* a family in the run that the baseline has never heard of is a **failure**, not
  a pass — a new technique arriving with no recorded expectation must not
  default to "fine";
* a family in the baseline that the run did not measure is a failure too, since
  a fold that stops running is indistinguishable from one that passed;
* the random-split control is gated, because the headline is a *difference*
  between arms and a degraded control shrinks the gap while looking like an
  improvement.

Baselines are re-recorded by a person running `--update-baseline` and committing
the diff. A gate that re-records itself ratchets its own standard downwards one
run at a time.

### ADR-013 — No network, no model download, no credentials

The detection path makes no outbound request. A firewall that needs one has
added an availability dependency to the request path it was meant to protect,
and a latency budget to a decision that has to happen before every call.

The consequence is a weaker detector than a large model would give, and that is
stated rather than hidden. It also means this package authenticates to nothing,
which is why there is no API key in `.env.example` and nothing to leak.

### ADR-014 — Digest gates for integers, tolerance gates for floats

Carried forward from the previous project in this series, where it was measured
rather than assumed: trained float weights differ across platforms by up to
2.4e-14 relative, because BLAS accumulation order is a property of the build.

Corpora are integers and strings, so they are gated by **digest** equality. The
model is floats, so it is gated on **metrics within a tolerance**, and its
`config_digest` covers the featuriser configuration rather than the weights. The
featuriser hash is BLAKE2b rather than Python's `hash`, which is salted per
process: a model trained in one interpreter and loaded in another would index
different buckets, score worse, and raise nothing.

### ADR-015 — Both CLI test layers, always

`tests/integration/test_cli_in_process.py` runs commands in-process, where a
traceback is readable. `tests/e2e/test_cli.py` runs the same commands as real
processes, where the exit code is the whole interface.

Both are needed. `argparse` exits **2** on a usage error, and 2 is this
project's "a gate failed" code — so a pipeline reading exit codes would have
treated a misspelled flag as an attack getting through. Nothing in-process could
see it.

### ADR-016 — The decision score is one layer, because the measurement said so

The obvious design combines all three layers. This project shipped that first.
Measured across twelve leave-one-family-out folds at a shared 1% false-positive
budget, it is roughly ten times worse than one of its own inputs:

| Arm | Unseen bypass | Realised FPR | Threshold range |
| --- | --- | --- | --- |
| `rules` | 93.75% | 0.68% | 0.500 – 0.843 |
| `signals` | 83.69% | 1.16% | 0.150 – 0.300 |
| **`model`** | **2.08%** | 1.84% | 0.109 – 0.118 |
| `combined` | 20.89% | 1.25% | 0.603 – 0.797 |

The mechanism is in the threshold column. The rule and structural layers fire on
documentation, code and imperative English, so mixing them in raises the benign
score tail; a 1% budget on the combination lands at 0.79 where the model's own
lands at 0.11, and attacks the learned layer ranked correctly fall below the
higher line. Eleven of twelve folds go from 0% bypass to non-zero purely by
adding the other two layers.

Re-measuring the model at the combination's *realised* false-positive rate
leaves every fold unchanged, so this is not the model buying its result with a
looser operating point.

**Decision.** The decision score is the learned layer alone when a model is
loaded, and the noisy-OR of the two non-learned layers when one is not. The rule
and structural layers remain as **evidence**: computed on every message, named
in every verdict, written to the audit record. A verdict naming
`exfil.reveal_prompt` tells an on-call engineer something a probability of 0.94
does not — that value is real, it is simply not detection lift.

**What was rejected, and why.** Shrinking the reliability constants until the
ensemble stopped hurting would fit constants to held-out families, which is the
exact failure this evaluation exists to detect; the constants stand as first
written so the `combined` column keeps measuring the rejected design rather than
a tuned version of it. An exceedance (Fisher) combination was tried and lost on
three of four folds. No combination rule recovers information its inputs do not
carry.

**The cost.** The realised false-positive rate rose from 1.25% to 1.84% pooled.
Cutting unseen-technique bypass by a factor of ten roughly doubled what benign
users pay, and both halves of that are published.

**Consequence for operators.** The score is a logistic probability with a model
and a noisy-OR of rule weights without one, so a 1% budget lands near 0.11 in
the first case and near 0.84 in the second. A threshold carried across that
boundary is not a threshold. `pifw calibrate` prints both.

### ADR-017 — The corpus cannot hold out its own generator, and says so

Leave-one-family-out holds out the technique. It does not hold out the
vocabulary: the twelve families share slot vocabularies by design, so they
differ by technique rather than by wording, which leaves a held-out family's
lexicon in the training set through the other eleven.

That is a specific way for the headline to be wrong, so it was measured.
`scripts/lexicon-holdout.py` runs two arms at identical scale — one sharing the
slot vocabularies, one drawing training attacks from half of every slot and
evaluation attacks from the other half. The result is negative: `hypothetical`
and `indirect` stay at 0.00%, and `homoglyph` moves to 5.00%, three samples on
an interval that straddles zero. The learned layer is generalising across the
technique rather than memorising the frame.

What remains is not fixable. Both arms share the grammar that assembles those
slots, and no synthetic corpus can hold out its own generator. This bounds what
any number on this page can mean, and it is the reason the audit record exists:
the rest of the measurement happens in production, on traffic nobody generated.

The probe is deliberately **not** wired into CI. What it measures is a property
of the corpus design, which changes on the day somebody edits
`src/pifw/corpus/attacks.py` and on no other day; running it on every pull
request would spend six model trainings to re-confirm a constant.

## Layout

| Path | What lives there |
| --- | --- |
| `src/pifw/corpus/` | The attack grammar, the benign grammar, and the assembler |
| `src/pifw/detect/` | Normalisation, rules, structural signals, the ensemble |
| `src/pifw/model/` | Hashed features and the logistic regression over them |
| `src/pifw/evaluate/` | Metrics with intervals, the LOFO harness, the baseline gate |
| `src/pifw/firewall.py` | The integration point and the audit record |
| `scripts/check-firewall.py` | The gates' own negative controls, against the shipped binary |
| `tests/{unit,integration,security,e2e,meta}/` | Five layers, each catching what the others cannot |
