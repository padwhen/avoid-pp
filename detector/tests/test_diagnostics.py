"""C18: versioned inference diagnostics.

Diagnostics exist so a recorded number can be attributed and costed. They must
never become a channel for anything the caller should not see.
"""

from __future__ import annotations

import json

from translation_guard import prompts
from translation_guard.detectors.claude import ClaudeDetector
from translation_guard.schemas import Diagnostics, Versions

SECRET = "sk-ant-SUPERSECRET-must-never-appear"


def detector() -> ClaudeDetector:
    return ClaudeDetector(
        api_key=SECRET, model="claude-opus-5", identity="claude:claude-opus-5"
    )


# C18-AC1: a result must identify model, prompt and inference settings.
def test_the_detector_exposes_what_a_report_needs():
    d = detector()
    assert d.identity == "claude:claude-opus-5"
    assert d.prompt_version == prompts.DEFAULT_VERSION
    assert len(d.prompt_fingerprint) == 64
    assert d.max_tokens > 0


def test_the_fingerprint_matches_the_registry():
    assert (
        detector().prompt_fingerprint
        == prompts.get(prompts.DEFAULT_VERSION).fingerprint()
    )


def test_versions_carries_the_fingerprint():
    prompt = prompts.get(prompts.DEFAULT_VERSION)
    versions = Versions(
        detector="claude:claude-opus-5",
        prompt=prompt.version,
        prompt_fingerprint=prompt.fingerprint(),
    )
    assert versions.prompt_fingerprint == prompt.fingerprint()


# C18-AC3: unknown usage is absent, never zero.
def test_unknown_usage_is_absent_not_zero():
    """Reporting an unknown token count as 0 would quietly understate cost in
    every report that aggregates it."""
    diagnostics = Diagnostics(model="claude-opus-5", latency_ms=1234, attempts=1)
    assert diagnostics.input_tokens is None
    assert diagnostics.output_tokens is None

    dumped = diagnostics.model_dump(exclude_none=True)
    assert "input_tokens" not in dumped
    assert "output_tokens" not in dumped
    assert dumped["latency_ms"] == 1234


def test_zero_usage_is_still_representable():
    """Absent and zero must stay distinguishable - a genuinely free call is
    not the same as an unmeasured one."""
    diagnostics = Diagnostics(input_tokens=0, output_tokens=0)
    dumped = diagnostics.model_dump(exclude_none=True)
    assert dumped["input_tokens"] == 0


def test_no_confidence_field_exists():
    """An LLM-invented probability is not calibrated and must not be rendered
    as though it were."""
    assert "confidence" not in Diagnostics.model_fields
    assert "score" not in Diagnostics.model_fields
    assert "probability" not in Diagnostics.model_fields


# C18-AC2: only intended stable fields leave the service.
def test_diagnostics_cannot_carry_unexpected_fields():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Diagnostics(api_key=SECRET)  # type: ignore[call-arg]


def test_no_credential_or_prompt_text_reaches_a_serialised_result():
    """The credential is held by the detector and the prompt is large; neither
    belongs in a response a caller reads."""
    d = detector()
    diagnostics = Diagnostics(
        model=d._model,
        latency_ms=100,
        attempts=1,
        max_tokens=d.max_tokens,
    )
    versions = Versions(
        detector=d.identity,
        prompt=d.prompt_version,
        prompt_fingerprint=d.prompt_fingerprint,
    )

    serialised = json.dumps(
        {
            "versions": versions.model_dump(exclude_none=True),
            "diagnostics": diagnostics.model_dump(exclude_none=True),
        }
    )

    assert SECRET not in serialised
    assert "sk-ant" not in serialised
    # The fingerprint identifies the prompt without reproducing it.
    assert prompts.get(prompts.DEFAULT_VERSION).system[:40] not in serialised
    assert len(serialised) < 500


def test_the_fingerprint_identifies_without_disclosing():
    prompt = prompts.get(prompts.DEFAULT_VERSION)
    fingerprint = prompt.fingerprint()
    assert prompt.system not in fingerprint
    assert len(fingerprint) == 64
    # Same bytes, same hash: a report can be checked against the repository.
    assert prompts.get(prompts.DEFAULT_VERSION).fingerprint() == fingerprint
