"""Detector settings, validated at import of the application.

Mirrors the gateway's rule: a configuration error names the variable and the
requirement, never the value. Settings carry credentials once a provider is
wired in at C13, and an error quoting the offending value writes a secret to
the logs.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectorMode(StrEnum):
    """Which detector implementation to run.

    ``fake`` is the default so a clean checkout, the test suite and ordinary
    pull-request CI all work with no API key and no provider spend. ``live``
    arrives at C13.
    """

    FAKE = "fake"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AVOIDPP_DETECTOR_",
        extra="forbid",
        frozen=True,
    )

    mode: DetectorMode = DetectorMode.FAKE
    host: str = "127.0.0.1"
    port: int = Field(default=9000, gt=0, lt=65536)

    # Identity recorded in every assessment and every evaluation report, so a
    # result can be attributed to what produced it.
    detector_version: str = Field(default="fake-0", min_length=1)
    prompt_version: str = Field(default="none", min_length=1)

    # Set to force initialisation to fail, so readiness can be exercised
    # without a real dependency to break. Tests rely on this; C13 replaces it
    # with the provider client's own startup check.
    fail_initialisation: bool = False
