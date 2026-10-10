"""Detector settings, validated at import of the application.

Mirrors the gateway's rule: a configuration error names the variable and the
requirement, never the value. Settings carry credentials once a provider is
wired in at C13, and an error quoting the offending value writes a secret to
the logs.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectorMode(StrEnum):
    """Which detector implementation to run.

    ``fake`` is the default so a clean checkout, the test suite and ordinary
    pull-request CI all work with no API key and no provider spend. ``live``
    must be chosen deliberately, because it costs money on every scan.
    """

    FAKE = "fake"
    LIVE = "live"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AVOIDPP_DETECTOR_",
        extra="ignore",
        frozen=True,
        # The repository-root .env holds the provider key. populate_by_name
        # lets api_key be read from LLM_API_KEY rather than the prefixed name.
        env_file=(Path(__file__).resolve().parents[3] / ".env", ".env"),
        env_file_encoding="utf-8",
        populate_by_name=True,
    )

    mode: DetectorMode = DetectorMode.FAKE
    host: str = "127.0.0.1"
    port: int = Field(default=9000, gt=0, lt=65536)

    # Identity recorded in every assessment and every evaluation report, so a
    # result can be attributed to what produced it.
    detector_version: str = Field(default="fake-0", min_length=1)
    prompt_version: str = Field(default="none", min_length=1)

    # Provider credential. Read from LLM_API_KEY, which is what the key is
    # called in the repository-root .env. Never logged, never echoed in an
    # error: config errors name the variable, not the value.
    api_key: str | None = Field(default=None, alias="LLM_API_KEY")

    # Model identifier, configurable so a cheaper or newer model can be
    # evaluated without a code change. The response records which one ran.
    model: str = Field(default="claude-opus-5", min_length=1)

    # Per-request ceiling. The gateway's deadline still wins when it is lower.
    request_timeout_seconds: float = Field(default=15.0, gt=0, le=120)

    # Log level for this service's own logger. uvicorn's access log is
    # separate and left alone.
    log_level: str = Field(default="INFO", pattern=r"^(?i:debug|info|warning|error)$")

    # Concurrency bound, defence in depth behind the gateway's own.
    #
    # Set above the gateway's default of 4 on purpose: in normal operation the
    # gateway sheds first and this never fires, so a rejection here means
    # something is calling the detector directly or a second gateway replica
    # exists. That is worth surfacing rather than absorbing silently.
    max_active: int = Field(default=8, ge=1, le=256)
    max_waiting: int = Field(default=16, ge=0, le=1024)

    # Set to force initialisation to fail, so readiness can be exercised
    # without a real dependency to break.
    fail_initialisation: bool = False
