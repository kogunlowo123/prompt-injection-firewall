"""Rendering an evaluation: JSON for machines, Markdown for people, JUnit for CI.

Three formats from one object, and the same numbers in all three. Reports that
are assembled separately drift, and the version a reviewer reads stops being the
version the build gated on.

JUnit is here because it is the one format every CI system renders inline. A
failing fold shows up in the pull request as a named failing test —
``lofo.homoglyph`` — rather than as a line in a log somebody has to open.
"""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree  # noqa: ICN001  # nosec B405

from pifw.evaluate.lofo import LAYERS, Evaluation


def to_json(evaluation: Evaluation, *, indent: int = 2) -> str:
    """The whole evaluation as JSON."""
    return json.dumps(evaluation.to_dict(), indent=indent, sort_keys=True) + "\n"


def _threshold_range(evaluation: Evaluation) -> str:
    """The span of per-fold thresholds, so the reader can see they are not one number."""
    thresholds = [fold.threshold for fold in evaluation.folds]
    if not thresholds:
        return "n/a"
    low, high = min(thresholds), max(thresholds)
    return f"{low:.3f}" if low == high else f"{low:.3f} – {high:.3f}"


def to_markdown(evaluation: Evaluation) -> str:
    """The evaluation as a Markdown document.

    Ordered so the uncomfortable number is first. A report that opens with an
    AUC of 0.99 and puts the per-family bypass rates on page three is a report
    written to be skimmed favourably.
    """
    pooled = evaluation.pooled_bypass
    control = evaluation.control.bypass
    worst = evaluation.worst_fold
    lines = [
        "# Bypass rate",
        "",
        f"Calibrated at a {evaluation.target_fpr:.1%} false-positive budget on benign traffic.",
        "",
        "| Measurement | Bypass rate | 95% interval | Threshold |",
        "| --- | --- | --- | --- |",
        (
            f"| **Unseen technique** (leave-one-family-out) | **{pooled.point:.2%}** "
            f"| {pooled.low:.2%} – {pooled.high:.2%} "
            f"| {_threshold_range(evaluation)} |"
        ),
        (
            f"| Seen technique (random split) | {control.point:.2%} "
            f"| {control.low:.2%} – {control.high:.2%} "
            f"| {evaluation.control.threshold:.3f} |"
        ),
        "",
        (
            f"The gap is **{evaluation.optimism_gap:+.1%}**. That is the amount by which a "
            "random split overstates this firewall against a technique it was not built for."
        ),
        "",
        (
            "The two arms share a **budget**, not a threshold. Each fold's detector and the "
            "control's are different detectors, so each gets the threshold that costs it "
            f"{evaluation.target_fpr:.0%} of the same benign calibration set. Comparing bypass "
            "rates at different false-positive prices is exactly what the calibration step "
            "exists to prevent, so the thresholds are shown rather than assumed equal."
        ),
        "",
        (
            f"Worst family: **{worst.family}** at {worst.bypass.point:.2%} "
            f"({worst.bypass.low:.2%} – {worst.bypass.high:.2%})."
        ),
        "",
        "## Per family, with its own countermeasures held out",
        "",
        "| Family | Bypass | 95% interval | FPR | AUC | Threshold | Rules off | Stages off |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        f"| `{fold.family}` | {fold.bypass.point:.2%} "
        f"| {fold.bypass.low:.2%} – {fold.bypass.high:.2%} "
        f"| {fold.confusion.false_positive_rate.point:.2%} "
        f"| {fold.auc:.3f} "
        f"| {fold.threshold:.3f} "
        f"| {len(fold.disabled_rules)} | {len(fold.disabled_stages)} |"
        for fold in sorted(evaluation.folds, key=lambda item: item.bypass.point, reverse=True)
    )

    lines += [
        "",
        "## Per layer",
        "",
        (
            "Each layer scored on its own, at its own threshold calibrated to the same "
            "false-positive budget. Pooled over every fold."
        ),
        "",
        "| Layer | Bypass (unseen) | Bypass (seen) |",
        "| --- | --- | --- |",
    ]
    for layer in LAYERS:
        missed = sum(
            round(fold.layer_bypass[layer].point * fold.layer_bypass[layer].total)
            for fold in evaluation.folds
        )
        total = sum(fold.layer_bypass[layer].total for fold in evaluation.folds)
        pooled_layer = missed / total if total else 0.0
        lines.append(
            f"| `{layer}` | {pooled_layer:.2%} "
            f"| {evaluation.control.layer_bypass[layer].point:.2%} |"
        )

    lines += [
        "",
        "## False positives, by kind of benign traffic",
        "",
        "Measured with every countermeasure enabled, which is the deployed configuration.",
        "",
        "| Kind | Flagged |",
        "| --- | --- |",
    ]
    for kind, interval in evaluation.benign_flag_rate_by_kind.items():
        lines.append(f"| `{kind}` | {interval.point:.2%} |")

    lines += [
        "",
        (
            f"Trained on {evaluation.train_size} samples, evaluated on {evaluation.eval_size} "
            "from a corpus generated with a different seed."
        ),
        "",
    ]
    return "\n".join(lines)


def to_junit(evaluation: Evaluation, *, max_family_bypass: float) -> str:
    """One test case per fold, failing when a family is over its budget.

    The per-family budget rather than the pooled one, because JUnit's unit is a
    named case and "the pool" is not a family anybody can go and look at.
    """
    failures = 0
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": "pifw.lofo",
            "tests": str(len(evaluation.folds)),
        },
    )
    for fold in evaluation.folds:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {"classname": "lofo", "name": fold.family},
        )
        if fold.bypass.point > max_family_bypass:
            failures += 1
            failure = ElementTree.SubElement(
                case,
                "failure",
                {
                    "type": "BypassRateExceeded",
                    "message": (
                        f"{fold.bypass.point:.2%} of held-out {fold.family} attacks got "
                        f"through, over the {max_family_bypass:.2%} budget"
                    ),
                },
            )
            failure.text = (
                f"threshold {fold.threshold:.4f}; "
                f"{fold.confusion.false_negative} of {fold.confusion.attacks} missed; "
                f"rules disabled: {', '.join(fold.disabled_rules) or 'none'}"
            )
        else:
            ElementTree.SubElement(
                case,
                "system-out",
            ).text = f"bypass {fold.bypass.point:.2%} of {fold.confusion.attacks} attacks"
    suite.set("failures", str(failures))
    return ElementTree.tostring(suite, encoding="unicode") + "\n"


def write_reports(
    evaluation: Evaluation,
    *,
    json_out: Path | None = None,
    markdown_out: Path | None = None,
    junit_out: Path | None = None,
    max_family_bypass: float,
) -> list[Path]:
    """Write whichever reports were asked for, returning the paths written."""
    written: list[Path] = []
    for path, body in (
        (json_out, to_json(evaluation)),
        (markdown_out, to_markdown(evaluation)),
        (
            junit_out,
            to_junit(evaluation, max_family_bypass=max_family_bypass) if junit_out else "",
        ),
    ):
        if path is None:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8", newline="\n")
        written.append(path)
    return written
