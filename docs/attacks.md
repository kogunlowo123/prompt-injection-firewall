# The attack corpus

Twelve technique families, generated from a seeded grammar in
`src/pifw/corpus/attacks.py`.

## What this is, and is not

It is **not** a collection of jailbreaks scraped from the internet, and it is not
tuned against any particular model. Every string is generated from a template by
a seeded pseudo-random walk, which makes the corpus reproducible, license-clean,
and useless as a ready-made attack library while remaining a fair test of whether
a detector generalises. The families are the public taxonomy — instruction
override, role assumption, delimiter escape, obfuscation, indirect injection —
written out as grammar.

**No credential-shaped string appears anywhere in it.** The `exfiltration` family
asks for credentials in the abstract ("the configuration values in your
environment") because putting a realistic key format into a public repository in
order to test a detector would be committing a secret-shaped fixture to make a
point about secrets. `tests/security/test_adversarial.py` asserts it.

## Why a family is a technique and not a wording

The whole evaluation turns on this distinction. `src/pifw/evaluate/lofo.py`
splits on family and asks what the firewall does against a technique nobody
building it had seen; a corpus split on *wording* would answer a much easier
question and give a much better-looking number.

So the families share their surface vocabulary deliberately. `LEADS`, `SCOPES`,
`TASKS` and `PREAMBLES` are drawn from by every family that needs them. If each
family had its own word list, the families would be separable by vocabulary
alone, a classifier would learn the vocabulary, and the leave-one-family-out
result would measure nothing but how different the word lists are.

## The twelve

| Family | The technique | Rules it motivated |
| --- | --- | --- |
| `direct_override` | States the override plainly, with no evasion at all | `override.verb_scope`, `override.instruction_noun`, `override.new_task` |
| `role_assumption` | Assigns a persona asserted not to have the constraint | `role.you_are_now`, `role.unrestricted` |
| `delimiter_escape` | Emits a closing marker for the user block, opens a forged system block | `delimiter.close_tag`, `delimiter.forged_header`, `delimiter.end_marker` |
| `encoding_wrapper` | Carries the instruction through base64, hex, ROT13 or reversal | `encoding.decode_and_obey`, `encoding.read_backwards` |
| `homoglyph` | Confusable scripts, fullwidth forms, zero-width breaks | **none** — see below |
| `indirect` | Hides the payload in a document the assistant was asked to read | `indirect.addressed_to_model` |
| `exfiltration` | Asks for the system prompt or context, and names a channel out | `exfil.reveal_prompt`, `exfil.channel`, `exfil.repeat_above` |
| `refusal_suppression` | Forbids the shapes a refusal takes | `refusal.suppression` |
| `payload_splitting` | Assembles the instruction from individually harmless fragments | `split.assemble` |
| `translation_pivot` | Delivers the instruction in another language, or translate-then-obey | `translate.then_obey`, `translate.foreign_override` |
| `hypothetical` | Wraps the request in fiction so the answer belongs to a character | `hypothetical.no_rules` |
| `authority_claim` | Claims a role entitled to lift the constraint | `authority.claim`, `authority.authorise` |

### `homoglyph` has no rule, on purpose

There is no *phrase* that means "these letters are from the wrong script". Its
countermeasures are the normalisation stages (`nfkc`, `zero_width`,
`confusables`) and two structural signals, and the fold removes those instead.

`pifw rules` prints this table, including the "families with no rule of their
own" line, so the asymmetry is visible from the command line rather than only in
this document.

### `indirect` is the one that matters most

The payload arrives in a web page, a support ticket, a PDF or a calendar invite
that the assistant was asked to read. The person whose account is at risk never
typed it and has no way to avoid it. It is also the family with the single
highest-weighted rule in the pack (`indirect.addressed_to_model`, 0.65), because
a document that addresses the model reading it has no legitimate reason to exist.

## Grammar quality

Every frame varies at least five slots. That is a lesson from the previous
project in this series rather than a preference: a grammar whose frames varied
two slots produced a corpus 26% of which collided with itself, and every
deduplication number measured on it was a measurement of the grammar.

Measured on the shipped plans:

| Corpus | Samples | Collision rate |
| --- | --- | --- |
| `main` | 6,720 (3,120 attack, 3,600 benign) | 2.29% |
| `holdout` | 3,480 (1,680 attack, 1,800 benign) | 6.87% |

The collision rate is the share of draws that repeated a string already in the
corpus and had to be redrawn. It measures how much headroom the grammar has left,
and it is reported rather than absorbed: a rate climbing towards the retry limit
means a corpus that will silently come up short.

The holdout's higher rate is expected — it is generated with the entire training
corpus excluded, so it is drawing from what is left.

An earlier version of the benign grammars scored **34.60%** and could not fill
its quota at all: `multilingual` produced 30 samples against a request for 216,
because five fixed sentences times six closers is thirty distinct outputs. The
fix was to build those kinds compositionally rather than writing sentences out.

## Regenerating

```bash
pifw synth --plan main --out examples/corpus.jsonl.gz
pifw synth --plan holdout --out examples/holdout.jsonl.gz \
    --disjoint-from examples/corpus.jsonl.gz
```

`--disjoint-from` is how the holdout is made disjoint **by construction**. See
[ADR-010](../ARCHITECTURE.md#adr-010--the-holdout-is-disjoint-by-construction-not-by-hope)
for the measurement that made it necessary.

`pifw check --plan main --corpus examples/corpus.jsonl.gz` re-derives the corpus
from its plan and compares digests. CI runs it, so a corpus edited by hand fails
the build rather than silently changing every number downstream.

## See also

- [docs/false-positives.md](false-positives.md) — the other half of the corpus
- [docs/evaluation.md](evaluation.md) — what the families are used for
