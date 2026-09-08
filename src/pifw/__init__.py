"""A prompt-injection firewall that publishes its own bypass rate.

The short version of what is here and why.

Prompt injection has no known reliable defence. Anything that claims one is
either wrong or is measuring itself against the attacks it was built from. This
package therefore does not claim to stop prompt injection. It detects a
measurable share of it, measures that share **against techniques it was not
built from**, publishes both that number and its cost in false positives, and
keeps measuring after deployment by recording what it let through.

The entry points a caller wants:

``pifw.Firewall``
    The integration point. Wraps a call to a model, returns a decision, and
    records what was allowed.
``pifw.Detector``
    The scoring stack on its own, if you want the verdict without the wrapper.
``pifw.evaluate.lofo.run``
    The evaluation. Everything on the front page of the README comes out of it.
"""

from __future__ import annotations

from pifw.detect.ensemble import Decision, Detector, Thresholds, Verdict
from pifw.errors import (
    EXIT_CANNOT_RUN,
    EXIT_GATE_FAILED,
    EXIT_OK,
    EXIT_USAGE,
    ConfigError,
    CorpusError,
    FirewallError,
    GateError,
    ModelError,
    RefusalError,
)
from pifw.firewall import Firewall, Outcome, Recorder
from pifw.sample import Corpus, Sample

__version__ = "0.1.0"

__all__ = [
    "EXIT_CANNOT_RUN",
    "EXIT_GATE_FAILED",
    "EXIT_OK",
    "EXIT_USAGE",
    "ConfigError",
    "Corpus",
    "CorpusError",
    "Decision",
    "Detector",
    "Firewall",
    "FirewallError",
    "GateError",
    "ModelError",
    "Outcome",
    "Recorder",
    "RefusalError",
    "Sample",
    "Thresholds",
    "Verdict",
    "__version__",
]
