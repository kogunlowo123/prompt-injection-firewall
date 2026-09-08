"""Deployment configuration, from the environment, validated once at startup.

Everything here has a default that is safe to run with. The two that matter:
``PIFW_MODE`` defaults to ``monitor``, and ``PIFW_RECORD_PATH`` defaults to
unset, which means no record is kept — so the *only* configuration that both
blocks traffic and keeps no evidence of doing so is rejected in
:class:`pifw.Firewall`, not merely discouraged here.

No secrets are read. This package authenticates to nothing and calls nothing,
which is why there is no API key in this file and no ``.env`` entry for one.
``PIFW_RECORD_SALT`` is the closest thing, and it is optional: without it the
audit record still works, it just cannot be correlated across process restarts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from pifw.detect.ensemble import DEFAULT_BLOCK, DEFAULT_FLAG, Detector, Thresholds
from pifw.errors import ConfigError
from pifw.firewall import Firewall, Recorder
from pifw.model.logistic import Model


class Settings(BaseSettings):
    """Everything the deployed firewall reads from its environment."""

    model_config = SettingsConfigDict(
        env_prefix="PIFW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    mode: Literal["monitor", "enforce"] = "monitor"
    flag_threshold: float = Field(default=DEFAULT_FLAG, ge=0.0, le=1.0)
    block_threshold: float = Field(default=DEFAULT_BLOCK, ge=0.0, le=1.0)
    model_path: Path | None = None
    record_path: Path | None = None
    #: Off by default, and it stays off unless somebody types the word. The
    #: prompts belong to the people who wrote them.
    record_text: bool = False

    @model_validator(mode="after")
    def _thresholds_are_ordered(self) -> Settings:
        if self.block_threshold < self.flag_threshold:
            raise ValueError("PIFW_BLOCK_THRESHOLD cannot be below PIFW_FLAG_THRESHOLD")
        return self

    def build(self) -> Firewall:
        """Construct the firewall this configuration describes."""
        model = Model.load(self.model_path) if self.model_path is not None else None
        detector = Detector(
            model=model,
            thresholds=Thresholds(flag=self.flag_threshold, block=self.block_threshold),
            mode=self.mode,
        )
        recorder = (
            Recorder(self.record_path, keep_text=self.record_text)
            if self.record_path is not None
            else None
        )
        if self.mode == "enforce" and recorder is None:
            raise ConfigError(
                "PIFW_MODE=enforce with no PIFW_RECORD_PATH",
                remedy="Set PIFW_RECORD_PATH so blocked traffic leaves a record.",
            )
        return Firewall(detector, recorder=recorder)
