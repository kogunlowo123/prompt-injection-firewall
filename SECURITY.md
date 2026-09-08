# Security policy

## Reporting a vulnerability

Report privately through GitHub's [Security
Advisories](https://github.com/kogunlowo123/prompt-injection-firewall/security/advisories/new)
form. Please do not open a public issue for anything that would give someone
else a working bypass before there is a fix.

Include what you did, what happened, and what you expected. A message that
bypasses the firewall is most useful with the exact input bytes — obfuscation
survives round-tripping through a chat window badly, so a base64 or hex dump of
the payload is worth more than a screenshot.

Expect an acknowledgement within 5 working days and an assessment within 15.
This is a portfolio project maintained by one person, so those are honest
targets rather than a commercial SLA.

## What counts as a vulnerability here

This project is a detector. Being evaded is its normal condition, and the
README publishes the rate at which it happens. So the bar for "vulnerability"
is not "I got a payload past it" — that is expected, measured, and documented.

**In scope:**

* **A bypass that defeats an entire class**, not one sample. If it works
  against every family in the corpus, or defeats a normalisation stage outright
  (something that survives `decode` plus the second character pass, say), that
  is a finding and it wants a rule, a stage or a corpus family.
* **Denial of service through the detector.** This code runs on
  attacker-supplied text in front of the thing it protects. An input that makes
  a regex backtrack exponentially, or that drives memory or time superlinearly,
  is a real vulnerability — the firewall becomes the outage. `MAX_GAP` bounds
  every pattern and a test asserts no nested quantifiers, but the assertion is
  structural and a counterexample would be valuable.
* **Anything that makes the audit record lie.** A message that gets recorded
  with the wrong decision, a fingerprint that collides by construction, or a
  path that lets an attacker suppress their own record.
* **Enforce mode failing open silently.** `Firewall` refuses to construct in
  enforce mode without a recorder; a route around that check is in scope.
* **A crash on the request path.** `Recorder.record` swallows `OSError` by
  design, but an unhandled exception anywhere in `inspect` turns a detection
  problem into an availability problem.
* **Anything secret-shaped in the repository or its history.** See below.

**Out of scope:**

* A single clever prompt that scores below the threshold. Please open a normal
  issue — those are welcome, and they are how the corpus grows — but it is not
  a security report.
* The measured false-positive rate on `security_docs`. It is 25%, it is in the
  README, and it is a documented property rather than a defect.
* The fingerprint being reversible for short prompts. Documented in
  `docs/policy.md`: it is a pseudonym for linking repeat offenders, not an
  anonymisation, and it says so in its own docstring.
* Findings that require an attacker who already controls the host, the
  configuration, or the trained model file.

## The security model in one paragraph

This package **detects and reports; it does not sanitise.** It never modifies a
message and passes it on, because a "cleaned" prompt is a prompt an operator
stops being careful with. Normalisation exists only to score against, and the
original text is what reaches the model. The default mode is monitor, so the
default behaviour is to record and continue — see `docs/policy.md` for why a
detector with a double-digit bypass rate against unseen techniques should not
block by default, and `THREAT-MODEL.md` for the attacks against the firewall
itself.

## Secrets

There are none, and that is enforced rather than asserted:

* the package authenticates to nothing, downloads nothing, and calls no model
  API, so there is no credential for it to hold;
* `.env.example` contains no value that is secret, and the one variable worth
  protecting (`PIFW_RECORD_SALT`) is documented as such and left unset;
* `tests/security/test_adversarial.py` scans the generated corpora for
  credential-shaped strings and asserts `Settings` has no field that looks like
  a key, because the corpus is the one place in this repository where writing
  something that resembles a leaked token would look natural;
* CI runs gitleaks over the full history, not just the diff.

If you believe a secret is present, treat it as in scope and report it
privately.

## Supported versions

The most recent release is supported. This project uses semantic versioning;
before 1.0.0, expect the detection surface to change between minor versions.

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## Dependencies

CI fails the build on any HIGH or CRITICAL advisory against the locked
dependency set. Exceptions are time-boxed, justified in writing, and reviewed —
see [`security/audit-exceptions.md`](security/audit-exceptions.md). The table
there is currently empty, which is the intended steady state. Suppressing a
finding without an entry there is a review failure: an unexplained suppression
and an unnoticed vulnerability look identical from outside.
