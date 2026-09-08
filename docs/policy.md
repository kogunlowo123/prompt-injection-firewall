# Policy: monitor, enforce, and the audit record

## Monitor is the default, and that is a design decision

A flagged message is recorded and surfaced, and **the model is still called**.

The measured bypass rate against unseen techniques is 2.08%, and that number is
the argument *for* monitor mode rather than against it.

Three reasons, in increasing order of importance.

**The pooled figure is eleven zeros and one 25%.** `encoding_wrapper` — a
payload hidden inside base64, with the decoder switched off — bypasses a quarter
of the time. An operator who reads 2.08% and blocks by default has deployed
something that misses one technique in four attempts and looks flawless on the
other eleven. The failure is concentrated, which makes it easy to miss and
expensive when it lands.

**2.08% describes a corpus, not an attacker.** Leave-one-family-out holds out
the technique and `scripts/lexicon-holdout.py` holds out the vocabulary, but
both arms share the grammar that generates them, and nothing can hold that out —
see [docs/evaluation.md](evaluation.md#what-is-still-not-held-out-and-cannot-be).
A real attacker is not drawing from these templates. The honest reading of a
good synthetic number is that it has ruled some failures out, not that it has
bounded the rate.

**A firewall that blocks teaches its operator to stop checking.** The operator
sees blocks, concludes the thing works, and stops treating downstream tool
access as if injection were possible. Monitor mode keeps the failure visible: a
flag rate is a number somebody looks at, and a block is a number nobody looks at
because the problem appears solved.

The corollary is that the audit record below is not optional decoration. It is
where the part of the measurement this repository cannot do gets done.

## Enforce is available and takes a decision

```bash
export PIFW_MODE=enforce
export PIFW_BLOCK_THRESHOLD=0.95
export PIFW_RECORD_PATH=/var/lib/pifw/decisions.jsonl
```

Two properties are enforced in code rather than recommended:

**A mode cannot be overridden by a threshold.** In monitor mode `decide()` never
returns `block`, whatever the score and whatever `block_threshold` says. A mode a
threshold can override is not a mode.

**Enforce without a recorder raises at construction.** Blocking traffic while
keeping no evidence of having done so leaves nobody able to distinguish a working
firewall from a broken one. `Firewall.__init__` refuses, and `Settings.build()`
refuses, and both name the fix.

Choose the block threshold from the calibration table, not by intuition. The
default of 0.9 is a placeholder, and a threshold carried over from a different
configuration is not a threshold: the score is a logistic probability when a
model is loaded and a noisy-OR of rule weights when one is not, and a 1% budget
lands near **0.11** on the first and near **0.84** on the second.

```bash
pifw calibrate --corpus examples/holdout.jsonl.gz --target-fpr 0.001
```

## Three decisions, and what each is for

| Decision | Meaning | What to do with it |
| --- | --- | --- |
| `allow` | Below the flag threshold | Nothing. The call proceeds. |
| `flag` | At or above the flag threshold | Call proceeds; the message is recorded with its evidence. Route to review, or downgrade the tools available for that turn. |
| `block` | Enforce mode only, at or above the block threshold | Return the refusal string. The model is never called. |

`flag` is where the useful behaviour lives. It is a good place to hang a
narrower tool policy for that turn — no writes, no outbound requests — which is
a proportionate response to a 0.6 score in a way that a refusal is not.

## The audit record

The measurement in the README covers twelve technique families on a synthetic
corpus. Real traffic contains techniques nobody has enumerated, and the number
does not cover them. So the firewall keeps measuring:

```bash
pifw audit --record /var/lib/pifw/decisions.jsonl
```

```
1284 decision(s), flag rate 1.87%
  allow      1260
  flag         24

scores of traffic that was allowed through:
  p50  0.031
  p90  0.118
  p99  0.402
  max  0.497
```

The **quantiles of allowed traffic** are the interesting part. A firewall working
normally allows a mass of traffic scoring near zero. A distribution that has
grown a shoulder just under the threshold is either drift or somebody probing for
where the threshold is, and both are worth a look *before* the flag rate itself
moves. A firewall whose flag rate silently fell to zero last Tuesday is
indistinguishable from one that is working, unless somebody is looking.

### The record does not contain the prompts

A log of every message users sent an assistant is a data-protection problem that
arrives bundled with the mitigation. Each row holds:

```json
{
  "at": "2026-09-08T14:02:11.884+00:00",
  "fingerprint": "sha256:1f6b0d3c...",
  "length": 142,
  "score": 0.986,
  "decision": "flag",
  "called": true,
  "layers": {"rules": 0.79, "signals": 0.31, "model": 0.986,
             "combined": 0.998, "decision": 0.986},
  "reasons": ["indirect.addressed_to_model", "exfil.reveal_prompt"]
}
```

`keep_text=True` stores the message as well. It is opt-in, it is off by default,
and it says so.

### The fingerprint is a pseudonym, not an anonymisation

The space of short prompts is small enough to enumerate, so with the salt in hand
a determined reader can confirm a guess. It exists to link repeat offenders
across records, and the docstring says it is no stronger than that.

Set `PIFW_RECORD_SALT` to a stable secret and fingerprints correlate across
process restarts. Leave it unset and each process generates a fresh random salt,
so a record cannot be linked to anything — not even to yesterday's record of the
same message. `Recorder.salt_is_stable` reports which, and `pifw audit` prints a
note when it is not, because finding that out by noticing nothing ever matches is
expensive.

### Recording never raises on the request path

A firewall that throws because its audit disk filled up has converted a logging
failure into an outage. `Recorder.record` swallows `OSError` and stops writing
past `MAX_RECORD_BYTES`. Recording is best-effort by design, and `pifw audit`
reports what is in the record rather than assuming there are no gaps.

## Configuration

Every variable, all optional, all safe to run with:

| Variable | Default | Notes |
| --- | --- | --- |
| `PIFW_MODE` | `monitor` | `monitor` or `enforce` |
| `PIFW_FLAG_THRESHOLD` | `0.5` | Calibrate it; do not guess it |
| `PIFW_BLOCK_THRESHOLD` | `0.9` | Must be ≥ the flag threshold |
| `PIFW_MODEL_PATH` | unset | **Set this.** Without it the learned layer is off and the score falls back to the layers that bypass at 93.75% |
| `PIFW_RECORD_PATH` | unset | Required when `PIFW_MODE=enforce` |
| `PIFW_RECORD_TEXT` | `false` | Stores the prompts. Opt-in |
| `PIFW_RECORD_SALT` | unset | Stable fingerprints across restarts |

No credentials. This package authenticates to nothing and calls nothing.

## See also

- [THREAT-MODEL.md](../THREAT-MODEL.md) — what a `flag` does and does not tell you
- [docs/false-positives.md](false-positives.md) — who gets flagged wrongly
