# Examples

Three scripts and three data files. The scripts are documentation that
executes: `python tasks.py examples` runs all of them, and CI runs that, so a
change that breaks an example breaks the build rather than rotting quietly in a
README.

Each one prints its numbers rather than asserting them, because the point of
each is a figure a reader should be able to disbelieve and re-derive.

## The scripts

### `quickstart.py`

Five messages through the firewall — one ordinary, one blatant injection, one
benign imperative, one security document quoting a real payload, and one
indirect injection of the kind that arrives inside a fetched web page. Prints
each verdict with its evidence.

Read this one first. It shows the shape of a `Verdict` and it shows, on the
third and fourth messages, why the false-positive side of this problem is hard:
the benign imperative and the security document are lexically almost
indistinguishable from the attacks around them.

Runs without a trained model, so it exercises the **fallback** scoring path —
the non-learned layers alone. That is the weak configuration, and the numbers in
`docs/detection.md` say by how much.

### `unseen_technique_demo.py`

The repository's argument, in about forty lines. Holds out one attack family,
disables the countermeasures that family motivated, trains on what is left, and
reports the bypass rate against the technique the detector has never seen.

This is the leave-one-family-out evaluation in miniature. The full version is
`pifw evaluate`, which does it twelve times and takes minutes; this does it
once, so the mechanism is legible without reading `src/pifw/evaluate/lofo.py`.

### `false_positive_demo.py`

The cost side. Calibrates a threshold on one half of the held-out benign corpus,
measures on the other, and reports the flag rate **per kind** with Wilson
intervals, naming which kinds were built to be hard.

The overall figure is small and the figure for `security_docs` is not. An
overall rate that is concentrated on one kind of traffic is not described by the
overall rate, which is the entire reason this script prints a table instead of a
number.

## The data files

| File | What it is |
| --- | --- |
| `corpus.jsonl.gz` | The training corpus: 12 attack families and 8 benign kinds, from plan `main` |
| `holdout.jsonl.gz` | The evaluation corpus, from plan `holdout`, generated **disjoint** from the training set |
| `baseline.json` | The recorded per-family bypass rates that `pifw evaluate` gates against |

Both corpora are generated, not collected, and both are checked rather than
trusted:

```bash
python tasks.py corpus-check
```

re-derives each from its plan and compares SHA-256 digests. A corpus edited by
hand fails the build. The holdout is disjoint **by construction** —
`generate(plan, exclude=...)` — rather than filtered afterwards, because
filtering afterwards removes samples unevenly and skews the very kinds that are
hardest.

Neither corpus contains a credential, a real person, or text from anywhere. A
test asserts the first of those, since the attack corpus is the one place in
this repository where writing something that looks like a leaked API key would
seem natural.

## Regenerating everything

```bash
python tasks.py corpus      # rebuild both corpora from their plans
python tasks.py train       # train the learned layer -> examples/model.json
python tasks.py baseline    # re-record baseline.json
```

`baseline.json` is a **measurement**, so re-record it deliberately and commit it
on its own. A baseline updated in the same commit as a detection change cannot
be used to tell whether the change helped: the gate compares against a number
that moved with it.
