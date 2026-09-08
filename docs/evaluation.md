# Evaluation

The argument this repository exists to make, in full.

## The problem with the usual number

A detector is built by people who have a list of attacks. They write rules
against that list, add normalisation stages against the tricks on that list, and
train a classifier on that list. Then they split the list at random, measure,
and publish a bypass rate.

Every attack in that test set is an attack of a kind the detector was built
against. The number describes how well the detector recognises rewordings of
things it already knows. Real traffic contains techniques that were not on the
list, and the published number says nothing at all about those.

## What this does instead

**Leave one family out.** Hold out an entire technique, and hold out the
countermeasures that technique motivated along with it.

Every rule, normalisation stage and structural signal in this codebase declares
a `motivated_by` set — the attack families that would have caused somebody to
write it. The harness reads that field. In the `homoglyph` fold, the
confusable-folding stage is switched off; in the `delimiter_escape` fold, the
three delimiter rules go. What is left is the detector somebody would have built
if that technique had never occurred to them, evaluated against it.

Leaving the countermeasure enabled while holding the family out would measure a
firewall built by someone who had already seen the technique, then report the
number as if they had not.

## The procedure, exactly

For each family *F*:

1. Train the learned layer on the training corpus **minus every attack from
   *F***, with the normalisation stages *F* motivated switched off. Assert the
   resulting model does not list *F* in `trained_families`, and assert it
   converged.
2. Build a detector with *F*'s rules, stages and signals disabled.
3. Split the held-out corpus's benign samples in half by alternating index:
   a **calibration** half and a **measurement** half.
4. Calibrate the threshold on the calibration half at a 1% false-positive
   budget.
5. Measure the bypass rate on the held-out corpus's *F* attacks, and the
   false-positive rate on the measurement half.

The random-split **control** runs the same procedure with nothing held out: all
twelve families in training, every countermeasure enabled, and an evaluation set
strided across all families so it is the same size as one fold. The attacks are
still unseen *text* — they come from the disjoint corpus — so this is not a
contaminated measurement. It is an honest random split, which is the point.

## Results

3,120 training attacks, 1,680 held-out attacks, 1% budget.

| Measurement | Bypass rate | 95% interval |
| --- | --- | --- |
| **Unseen technique** | **2.08%** | 1.50% – 2.88% |
| Seen technique (control) | 0.00% | 0.00% – 2.67% |

**Read the per-family table, not the pooled figure.** 2.08% is eleven zeros and
one 25%; its mean describes no fold. Reporting the average of a distribution
that lumpy is the same error this project calls out on the false-positive side.

| Family | Bypass | 95% interval | FPR | AUC |
| --- | --- | --- | --- | --- |
| `encoding_wrapper` | **25.00%** | 18.56% – 32.78% | 1.67% | 0.970 |
| `authority_claim` | 0.00% | 0.00% – 2.67% | 1.67% | 1.000 |
| `delimiter_escape` | 0.00% | 0.00% – 2.67% | 2.11% | 1.000 |
| `direct_override` | 0.00% | 0.00% – 2.67% | 1.89% | 1.000 |
| `exfiltration` | 0.00% | 0.00% – 2.67% | 1.89% | 1.000 |
| `homoglyph` | 0.00% | 0.00% – 2.67% | 1.67% | 1.000 |
| `hypothetical` | 0.00% | 0.00% – 2.67% | 1.78% | 1.000 |
| `indirect` | 0.00% | 0.00% – 2.67% | 2.22% | 1.000 |
| `payload_splitting` | 0.00% | 0.00% – 2.67% | 1.78% | 1.000 |
| `refusal_suppression` | 0.00% | 0.00% – 2.67% | 1.78% | 1.000 |
| `role_assumption` | 0.00% | 0.00% – 2.67% | 2.00% | 1.000 |
| `translation_pivot` | 0.00% | 0.00% – 2.67% | 1.67% | 1.000 |

These are the numbers for the **shipped** score, which is the learned layer
alone. The layered noisy-OR this project measured and rejected bypasses at
20.89% on the same folds; the comparison, and why the obvious design lost, is in
[docs/detection.md](detection.md#the-ensemble-and-why-there-is-not-one).

## Reading the results

### Eleven zeros is a claim about the corpus, not about the world

Zero out of 140 is not "0%". It is zero with a 95% upper bound of **2.67%**, and
eleven folds all sitting at that bound is what the pooled interval of 1.50% –
2.88% is made of. The corpus cannot demonstrate anything better than about 2.7%
per fold at this size; a table of bare zeros would hide that ceiling entirely.

### The payload generalises; the transport does not

`direct_override` is one of the easy folds, at 0.00%, with all three override
rules switched off. The obvious prediction is the opposite —
`override.verb_scope` is the rule that catches everything once normalisation has
undone a disguise, so removing it ought to be catastrophic.

It is not, because eleven other families embed the same core instruction. The
learned layer sees thousands of examples of that phrasing from families that
*were* in training, and catches the plain one without any rule at all.

The one family that survives is the one whose **transport** nothing else in the
corpus teaches. `encoding_wrapper` hides its payload inside base64, and with
`decode` switched off in its own fold there is nothing left for the learned
layer to read — the words it would have recognised are not in the message. That
is why it is also the fold where the rejected ensemble scored 100%: the failure
is upstream of scoring.

A more useful statement than "unseen techniques are hard": a new technique that
reuses a familiar payload will probably be caught, and a new technique that
introduces a novel **transport** will not. Transport is where to spend the next
engineering hour.

### AUC is not an operating point

`encoding_wrapper` has an AUC of 0.970 and a bypass rate of 25%. Those are not
in tension. AUC says the scores *order* attacks above benign traffic. The bypass
rate says where the threshold had to go to keep the false-positive budget.

A detector can rank well and still miss a quarter of a technique at a usable
budget. Reporting AUC alone is how that gets hidden — and under the rejected
ensemble this same fold ranked at 0.876 and bypassed at **100%**, which is the
extreme version of the same point.

### Budgets, not thresholds

Each fold's detector and the control's are *different detectors*, so each gets
the threshold that costs **it** 1% of the same benign calibration set. Holding
the numeric threshold fixed instead would mean the two arms were paying
different false-positive prices, and comparing bypass rates at different prices
is what calibration exists to prevent. Every threshold is in the report so the
difference is visible rather than asserted.

The realised false-positive rate is 1.84% pooled against a 1.0% budget, because
the threshold is calibrated on one half of the benign holdout and measured on
the other. Calibrating and measuring on the same samples would report the budget
back at you regardless of what the detector did. The gap is wider than it was
under the rejected ensemble, and that is a cost of the change rather than noise
— see [docs/false-positives.md](false-positives.md).

## Does this hold out the technique, or only the technique?

The strongest objection to the table above is structural. The twelve families
deliberately share slot vocabularies so that they differ by *technique* rather
than by wording — which means a fold removes the family but leaves its lexicon
in the training set, spread across eleven other families. A bag of hashed
n-grams could then recognise a held-out family from the frame around its
payload, report 0%, and have generalised to nothing.

`scripts/lexicon-holdout.py` measures it. Two arms at identical scale: one with
the same slot vocabularies on both sides, one with training attacks drawn from
half of every slot and evaluation attacks from the other half. Benign generation
is untouched in both, so the calibration threshold moves for only one reason.

| Fold | Shared lexicon | Disjoint lexicon | Delta |
| --- | --- | --- | --- |
| `homoglyph` | 0.00% | 5.00% *(3/60, 1.71% – 13.70%)* | +5.00% |
| `hypothetical` | 0.00% | 0.00% | — |
| `indirect` | 0.00% | 0.00% | — |

**The result is negative, and that is the useful outcome.** Holding out the
vocabulary as well as the technique moves one fold by three samples, on an
interval that straddles zero. The learned layer is generalising across the
technique rather than memorising the frame.

Two things make that reading legitimate. Collision rates stayed at 4.6% and 5.2%
after halving all six slots, so the grammar did not exhaust and start repeating
itself. And the shared arm — run at 120/60 per family rather than the shipped
260/140 — reproduced 0.00% on all three folds, so the delta is a property of the
lexicon rather than of the smaller corpus.

### What is still not held out, and cannot be

Both arms share the **grammar** that assembles those slots. LOFO holds out the
technique; `lexicon-holdout.py` holds out the vocabulary; nothing holds out the
generator, because the generator is what makes it a corpus.

This is the ceiling on every synthetic evaluation, including this one. A real
attacker is not drawing from these templates, and no amount of care inside the
corpus can measure the distance between the templates and them. It is the reason
this project ships an audit record and tells operators to keep watching the
quantiles of allowed traffic: the number on this page describes a corpus, and
production is where the rest of the measurement happens. See
[docs/policy.md](policy.md).

## What the harness refuses to do

A refusal produces **no metric at all**. "Not evaluated" is not "passed", and a
report that omits the number is honest in a way that a report with a flattering
number is not.

| Situation | Response |
| --- | --- |
| Training and evaluation corpora share text | Refuse, unless `--drop-shared` is passed — which then reports the count |
| A fold's model did not converge | Refuse, naming the iteration count and how to fix it |
| A fold's model was trained on its own held-out family | Refuse (a harness bug, checked rather than assumed) |
| A family requested that the training corpus lacks | Refuse |
| Gating asked for with no baseline | Refuse rather than inventing a threshold to pass |

The convergence refusal exists because of a measured mistake. An early version
trained for a fixed 400 steps of plain gradient descent and reported **40.47%**
where the same code trained to convergence reported 20.89%. Both outputs looked
exactly like a measurement, and nothing distinguished them.

## The gate

`examples/baseline.json` records what was measured. CI re-measures and fails on
a regression past five points — wide enough to absorb the sampling noise on a
140-attack fold, narrow enough that a real regression cannot hide inside it. See
[ADR-012](../ARCHITECTURE.md#adr-012--the-gate-is-a-baseline-comparison-not-an-absolute-budget).

`scripts/check-firewall.py` is the gate's own negative control: it runs the
shipped binary against the shipped corpora and asserts the gate fires on an
injected regression, fires on a fold that stopped running, fires on a family the
baseline does not carry, and fires on a run that exceeded its false-positive
budget.

## Running it

```bash
python tasks.py evaluate                    # the full twelve folds, gated
python tasks.py baseline                    # re-record; commit the diff alone
python examples/unseen_technique_demo.py    # three folds, about a minute
python scripts/lexicon-holdout.py           # the limitation probe above
```

## See also

- [docs/detection.md](detection.md) — what is being evaluated, and why one layer
- [docs/false-positives.md](false-positives.md) — the cost side of the trade
- [docs/reproducibility.md](reproducibility.md) — why the model is gated on metrics
