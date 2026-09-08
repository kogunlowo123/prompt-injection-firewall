"""The exceptions this package raises, and the exit codes they map to.

Exit codes are an interface. A caller in a shell script cannot catch a Python
exception, so the difference between "the firewall held" and "the firewall could
not run" has to survive the process boundary:

===== =============================================================
  0   held: every gate passed
  1   the command line was used incorrectly
  2   a gate failed: something the firewall is supposed to catch got through,
      or the false-positive rate exceeded its budget
  3   the run could not produce a verdict at all
===== =============================================================

The distinction between 2 and 3 is the one that matters in CI. Exit 2 means the
measurement happened and the answer was bad. Exit 3 means there is no answer,
which is *not* the same as a pass — and a pipeline that treats any non-zero code
alike will retry a broken run until it flakes green.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_GATE_FAILED = 2
EXIT_CANNOT_RUN = 3


class FirewallError(Exception):
    """Base class for everything this package raises deliberately.

    Carries a ``remedy``: the sentence a person needs in order to do something
    about the failure. An error message that says what went wrong and not what
    to do about it makes the reader search the source.
    """

    exit_code = EXIT_CANNOT_RUN

    def __init__(self, message: str, *, remedy: str = "") -> None:
        super().__init__(message)
        self.remedy = remedy


class CorpusError(FirewallError):
    """A corpus could not be read, or is not what it claims to be."""


class ConfigError(FirewallError):
    """A configuration value is missing or contradictory."""


class ModelError(FirewallError):
    """A detector could not be loaded, or was loaded against a mismatched featuriser."""


class GateError(FirewallError):
    """A measurement was made and it failed its budget.

    Distinct from every other error in this module: the pipeline worked. This is
    the firewall reporting that it does not meet the standard it was asked to
    meet, which is the outcome the whole repository exists to make visible.
    """

    exit_code = EXIT_GATE_FAILED


class RefusalError(FirewallError):
    """The tool declined to report a number it could not stand behind.

    Raised when a bypass rate is requested for an evaluation whose attack
    families overlap the ones the detector was tuned on. Reporting a recall
    figure measured that way is not a weak result, it is a wrong one, and the
    right behaviour is to produce no figure rather than a flattering one.
    """

    exit_code = EXIT_GATE_FAILED
