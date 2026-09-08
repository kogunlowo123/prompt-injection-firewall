# Threat model

Two threat models, and conflating them is the most common mistake in this
category of tool. **What this software is meant to detect** is not the same
question as **what an attacker can do to this software**, and a project that
answers only the first has shipped a new attack surface as a mitigation.

---

## Part 1: what this is meant to detect

### The asset

An LLM application's *instruction integrity*: the property that the assistant
follows the instructions its operator gave it, and treats everything arriving
from a user, a document, a web page or a tool result as data.

### The adversary

Anyone who can put text in front of the model. That is a much wider set than
"the user":

| Path | Who controls it | Covered by the `indirect` family |
| --- | --- | --- |
| The user's own message | The user | — |
| A retrieved document | Whoever wrote the document | yes |
| A web page the assistant reads | Whoever runs the site | yes |
| A support ticket, an email, a calendar invite | Whoever sent it | yes |
| A tool result | Whatever the tool talked to | yes |

The `indirect` case is the one that matters most in practice and the one users
have no defence against: the person whose account is at risk never typed it.

### What it detects, and how well

Twelve technique families, listed in [docs/attacks.md](docs/attacks.md). The
measured bypass rate against a technique the firewall was **not** built for is
in the README, per family, with confidence intervals.

Read it before deploying. Eleven of the twelve are caught with a 95% upper
bound of 2.67% when held out; `encoding_wrapper` is not, at 25.00% — a payload
hidden inside base64, measured with the decoder switched off. **What survives is
a novel transport, not a novel wording**, and that is where an attacker who has
read this file will go first.

### What it does not detect

Stated plainly, because a threat model that lists only successes is marketing:

* **Techniques not in the taxonomy.** The measured number is over twelve
  families. Real traffic contains techniques nobody has enumerated. The bypass
  rate does not cover them, and the leave-one-family-out result is the best
  available evidence about what happens when they arrive: for the three families
  whose disguise nothing else teaches, close to everything gets through.
* **Attacks in the model's *output*.** This inspects input. An assistant that
  has already been compromised, or that emits a payload of its own into a
  downstream system, is out of scope.
* **Semantic attacks with no lexical or structural signature.** A message that
  is a perfectly ordinary request whose *consequences* are harmful is not
  something a text classifier can see.
* **Multi-turn attacks.** Each message is scored on its own. A payload assembled
  across five turns has no single turn that looks like anything.
* **Attacks in modalities other than text.** Images, audio and files are not
  inspected.
* **Anything about whether the model complies.** A detected injection that the
  model would have ignored anyway and an undetected one that the model obeys
  score identically here. This measures detection, not exploitation.

### The security claim, in one sentence

*Some* injection attempts are detectable from the text, this measures what share
of them it catches against techniques it was not built for, and it publishes the
false-positive cost in the same table. It is a **defence in depth layer**, not a
boundary. Anything downstream that would be catastrophic if an injection
succeeded needs its own control — least privilege on tools, confirmation on
irreversible actions, and an assistant that cannot reach data its user cannot.

---

## Part 2: attacks on the firewall itself

This code runs on attacker-supplied text, in front of the thing it protects. It
is itself a target.

### Denial of service through the detection path

| Vector | Control | Tested |
| --- | --- | --- |
| Catastrophic regex backtracking | Every pattern bounded; no quantifier nested in a quantifier; asserted by a lint-style test over the rule table | `tests/unit/test_patterns.py`, `tests/security` |
| Decompression bomb in a corpus | Bound on the **decompressed** stream, not the file size or the gzip trailer — both are the writer's choice | `tests/integration/test_corpus_io.py` |
| Decode amplification (short base64 carrying a long payload) | `MAX_DECODE_BYTES` budget across all rounds; `MAX_DECODE_ROUNDS = 2` | `tests/security` |
| Very long input | `MAX_TEXT_CHARS` on corpus samples; featurisation is linear and asserted to be | `tests/security` |
| Pathological unicode | Hostile inputs run through the whole stack under a time budget | `tests/security` |

### Evasion of the detector

This is the *point* of the repository rather than a footnote, and the measured
answers are in the README. Two evasions were found during development by the
security layer, both live until two techniques were combined in one input:

* **Character normalisation ran before decoding.** A homoglyph payload wrapped
  in base64 arrives as plain ASCII; nothing folds; the Cyrillic appears after
  the folding stages have run. One line of base64 defeated the entire homoglyph
  defence. Fixed by running the character stages again after any expanding
  stage (ADR-011).
* **Zero-width characters inside an encoded payload.** They are
  `isprintable() == False`, so they pushed the decoder's printability ratio
  under threshold and the blob was discarded as binary. Fixed by counting
  Unicode format characters as printable for that test.

Both are why the security layer composes obfuscations rather than testing them
individually. Every stage passed its own unit test throughout.

### Attacks on the audit record

| Vector | Control |
| --- | --- |
| The record becomes a database of user prompts | Salted digest by default; keeping text is opt-in and documented |
| The record is used to re-identify a user across sessions | Salt is per process unless `PIFW_RECORD_SALT` is set; `salt_is_stable` and `pifw audit` say which |
| The digest is treated as anonymisation | Documented as a **pseudonym**: short prompts are enumerable, and with the salt a guess can be confirmed |
| Unbounded growth fills the disk | `MAX_RECORD_BYTES`; writes stop rather than failing |
| A logging failure becomes an outage | `Recorder.record` never raises on the request path |
| Log injection through crafted prompt text | Records are JSON with the text excluded; nothing is interpolated into a log line |

### Attacks through the corpus and model files

| Vector | Control |
| --- | --- |
| A tampered model file scores differently and raises nothing | `config_digest` checked on load; a mismatched featuriser is refused |
| A model from an older layout is silently reinterpreted | `FORMAT_VERSION` checked on load |
| A hand-edited corpus | Digest compared against the plan by `pifw check`; the CI job runs it |
| Malicious JSON in a corpus | Parsed by pydantic with `extra="forbid"`; the failing line number is reported |

### What this project handles that is *not* a secret

Nothing. It authenticates to nothing, calls nothing, and reads no credentials.
`PIFW_RECORD_SALT` is the only secret-adjacent variable and it is optional. A
test asserts that `Settings` grows no field named like a key or a token, and
`.gitleaks.toml` allowlists only content digests.

The attack corpus deliberately contains **no credential-shaped string**. The
`exfiltration` family asks for credentials in the abstract; putting a realistic
key format into a public repository in order to test a detector would be
committing a secret-shaped fixture to make a point about secrets. A test asserts
the grammar emits nothing matching the common key formats.

---

## Reporting

See [SECURITY.md](SECURITY.md). A finding that this firewall can be bypassed by
a technique in the taxonomy is a **bug**. A finding that it can be bypassed by a
technique outside the taxonomy is a **contribution** — that is the documented
state of the art, and the useful response is a new family in the grammar and a
re-recorded baseline showing what it costs.
