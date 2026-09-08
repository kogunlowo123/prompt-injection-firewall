# The detection stack

Three layers over a normalised message. **Only one of them decides.** Each is
measured separately every run, and the measurement is what chose which — see
[the ensemble](#the-ensemble-and-why-there-is-not-one) at the bottom, which is
the most useful thing on this page.

## Normalisation

Seven stages, then the character stages **again**.

| Stage | What it does | Motivated by |
| --- | --- | --- |
| `nfkc` | Unicode compatibility normalisation; undoes fullwidth forms | `homoglyph` |
| `zero_width` | Removes characters that render as nothing | `homoglyph` |
| `confusables` | Folds script-confusable letters onto Latin | `homoglyph` |
| `whitespace` | Line endings and runs of spaces | — |
| `decode` | Appends base64, hex, ROT13 and reversed content | `encoding_wrapper` |
| `reassemble` | Appends the concatenation of quoted assignments | `payload_splitting` |
| `casefold` | Lowercases, once, at the end | — |

The two stages with no `motivated_by` are generic hygiene and survive every
leave-one-family-out fold. The other five are switched off when their family is
held out — see [docs/evaluation.md](evaluation.md).

### NFKC is not a confusable defence

This is the point most pipelines get wrong. Unicode normalisation folds
*compatibility* variants, so it does undo the fullwidth block:

```python
apply_nfkc("ｉｇｎｏｒｅ") == "ignore"  # True
```

But Cyrillic `е` (U+0435) and Latin `e` (U+0065) are different letters in
different scripts, not compatibility variants, and NFKC leaves them alone by
design:

```python
apply_nfkc("ignorе") == "ignorе"  # True — unchanged
fold_confusables("ignorе") == "ignore"  # True — needs the explicit table
```

`tests/unit/test_normalize.py` asserts both, so if a future Unicode release
changes it the test says so rather than the stage quietly becoming redundant.

The folding table is deliberately small and one-directional. A full Unicode
confusables table folds far more aggressively, and folding aggressively on the
*benign* side is how a firewall starts flagging Cyrillic text for being Cyrillic.

### Decoding appends rather than substitutes

A message whose base64 blob decodes to an override is suspicious **because** it
wrapped it. Replacing the blob with its contents throws that signal away, so the
decoded text is appended and `structure.expansion` measures how much was added.

ROT13 and reversal are detected without needing the attacker to leave a hint:
the transformation is applied and accepted only if it raises the density of
English function words by at least 15 points. That is a cheap, language-blind
test for "did that turn noise into English".

### The character stages run twice, and that is a bug fix

Decoding appends text the character stages have never seen, because it did not
exist when they ran. A homoglyph payload wrapped in base64 arrives as plain
ASCII; nothing folds; the Cyrillic turns up afterwards. **One line of base64
defeated the entire homoglyph defence**, and every individual stage passed its
own unit test throughout.

The same input exposed a second bypass: zero-width characters are
`isprintable() == False`, so sprinkling them inside the payload *before*
encoding pushed the decoder's printability ratio under threshold and it
discarded the blob as binary. Unicode format characters now count as printable
for that test.

Both were found by `tests/security/test_adversarial.py`, which composes
obfuscations rather than testing them one at a time. It is the argument for
having that layer at all.

One extra pass, not a loop to a fixed point: the character stages do not create
new encoded content, so a third pass can never find anything a second did not,
and an unbounded loop over attacker-supplied text is a worse idea than the
problem it solves.

## Rules

21 regexes. Each has a weight in [0, 1], a one-line summary, and a
`motivated_by` set naming the families that would have caused someone to write
it. `pifw rules` prints the table.

**Regular expressions are a floor, not a defence.** Measured against a technique
they were not written for, they are not even that: **93.75% bypass**. They are
kept because they are cheap, auditable, and they explain themselves — a verdict
naming `exfil.reveal_prompt` tells an on-call engineer more than a score of
0.083. That value is real. It is not detection lift, and this project stopped
spending detection accuracy to pretend otherwise.

Every pattern is bounded. Nothing nests a quantifier inside a quantifier, every
wildcard run carries an explicit upper bound, and a test asserts the first
property over the whole table — this code runs on attacker-supplied text in
front of the thing it protects, and a regex that backtracks exponentially is a
denial-of-service primitive that arrived through the front door.

A rule fires **at most once** per message. A message saying "ignore previous
instructions" four times is not four times more likely to be an attack, and
counting occurrences is how a scorer ends up ranking verbosity.

## Structural signals

Seven measurements of *shape* rather than of words. Shape survives paraphrase in
a way a literal does not — in principle. Measured, it survives about as badly as
the literals do: **83.69% bypass** against an unseen technique.

| Signal | Weight | Motivated by |
| --- | --- | --- |
| `structure.zero_width` | 0.55 | `homoglyph` |
| `structure.script_mixing` | 0.55 | `homoglyph` |
| `structure.expansion` | 0.45 | `encoding_wrapper`, `payload_splitting` |
| `structure.encoded_blob` | 0.30 | `encoding_wrapper` |
| `structure.context_reference` | 0.30 | `exfiltration` |
| `structure.directive` | 0.30 | — |
| `structure.imperative` | 0.25 | — |

Each returns a **value** in [0, 1], not a boolean. "9% imperative" and "80%
imperative" are different observations, and thresholding each signal separately
would throw that away before anything else sees it.

`structure.script_mixing` counts scripts mixed *inside* a word, not between
words. A Russian sentence quoting an English product name mixes scripts and is
entirely ordinary; one word made of both is not.

The two signals with no `motivated_by` describe what every injection has in
common — it is a command addressed to the assistant — and are the only part of
the non-learned stack that keeps working when a fold removes its own
countermeasures. That is not a large amount of signal, and the table below says
so rather than implying otherwise.

## The learned layer

L2-regularised logistic regression over BLAKE2b-hashed word and character
n-grams, in NumPy. Convex, so training has one answer: weights start at zero,
there is no seed, no initialisation and no shuffle order. Deliberately the
simplest thing that could work, for three reasons that point the same way — it
is reproducible, it is inspectable, and it is **weak in a known way**. A larger
model would move the numbers and obscure the finding.

It is also, measurably, the only layer that detects anything it was not shown.

Training runs heavy-ball descent to a gradient tolerance, not to an iteration
count, and reports whether it converged. See
[ADR-009](../ARCHITECTURE.md#adr-009--training-runs-to-convergence-or-reports-no-number).

The hash is BLAKE2b rather than Python's `hash`, which is salted per process: a
model trained in one interpreter and loaded in another would index different
buckets, score worse, and raise nothing.

## The ensemble, and why there is not one

The obvious design — the one this project shipped first, and the one most
guardrails ship — combines all three layers with a noisy-OR:

```
combined = 1 - (1 - rules·0.90)(1 - signals·0.65)(1 - model·0.95)
```

Every arm below is calibrated to the same 1% false-positive budget on the same
benign calibration half, measured on the same held-out half, across the same
twelve folds. The only thing that differs is which score the threshold is put
on.

| Arm | Unseen bypass | Seen (control) | Realised FPR | Threshold range |
| --- | --- | --- | --- | --- |
| `rules` | 93.75% | 75.71% | 0.68% | 0.500 – 0.843 |
| `signals` | 83.69% | 72.86% | 1.16% | 0.150 – 0.300 |
| **`model`** | **2.08%** | **0.00%** | 1.84% | 0.109 – 0.118 |
| `combined` | 20.89% | 0.00% | 1.25% | 0.603 – 0.797 |

**The combination is ten times worse than one of its own inputs.** Not a little
worse — eleven of the twelve folds go from 0% bypass to non-zero purely by
mixing the other two layers in.

The mechanism is visible in the threshold column. The rule and structural layers
fire on benign traffic — documentation, code, imperative English — so adding
them raises the benign score tail, and a 1% budget on the combined score lands
at **0.79** where the model's own lands at **0.11**. Attacks the learned layer
had ranked correctly sit under the higher line. The rules do not so much miss
those attacks as *raise the price of admission* for everything.

### It is not the operating point

The model realises 1.84% against a 1% budget where the combination realises
1.25%, so the obvious objection is that the model simply bought its result by
flagging more. Re-measuring the model at the combination's *realised* rate, fold
by fold, answers it:

| Fold | `combined` | `model` at 1% budget | `model` at `combined`'s realised FPR |
| --- | --- | --- | --- |
| `encoding_wrapper` | 100.00% | 25.00% | 25.00% |
| `homoglyph` | 87.14% | 0.00% | 0.00% |
| `hypothetical` | 46.43% | 0.00% | 0.00% |
| `indirect` | 10.71% | 0.00% | 0.00% |
| the other eight | 0.00% – 5.00% | 0.00% | 0.00% |
| **pooled** | **20.89%** | **2.08%** | **2.08%** |

Every fold is unchanged. The operating point explains none of the gap.

### What was done about it

The decision score is the learned layer alone. The rule and structural layers
are still computed, still named in every verdict, and still written to the audit
record — as **evidence, not as score**.

Two things were deliberately *not* done:

**The reliabilities were not retuned.** Shrinking `RULE_RELIABILITY` and
`SIGNAL_RELIABILITY` towards zero until the ensemble stops hurting would fit
constants to held-out families, which is the exact failure the evaluation exists
to detect. The constants stand as first written, so the `combined` column keeps
measuring the design that was rejected rather than a version quietly tuned to
look better. It is still computed on every message and recorded next to the
shipped score, because a claim of this kind should stay falsifiable by whoever
deploys it rather than resting on a table in a README.

**A better combination function was not hunted for.** An exceedance (Fisher)
combination was tried and lost on three of four folds — 20.00% against 0.00% on
`indirect`, 7.86% against 0.00% on `hypothetical`. No combination rule recovers
information that is not in its inputs, and at a 1% budget the rule and
structural layers do not have much.

**The cost is real and is reported.** The realised false-positive rate went from
1.25% to 1.84% pooled, and from 1.22% to 2.00% in the control fold. Dropping two
layers from the score cut unseen-technique bypass by a factor of ten and roughly
doubled what benign users pay. Both halves of that are in
[docs/false-positives.md](false-positives.md).

### Without a model

`pifw scan` runs with no learned layer unless given one, and the package ships
no weights. In that configuration the score falls back to the noisy-OR of the
two non-learned layers — which is the 93.75%/83.69% row above. It is a real
configuration and a **much weaker** one, and it is why `PIFW_MODEL_PATH` is the
first thing [docs/policy.md](policy.md) tells an operator to set.

## See also

- [docs/evaluation.md](evaluation.md) — what these layers are measured against
- [docs/false-positives.md](false-positives.md) — what the switch cost
- [docs/attacks.md](attacks.md) — what each rule was written for
- [ADR-016](../ARCHITECTURE.md#adr-016--the-decision-score-is-one-layer-because-the-measurement-said-so)
- `pifw rules` — the table, from the command line
