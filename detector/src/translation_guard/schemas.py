"""Pydantic models for the private assessment API.

These mirror ``contracts/schemas/assessment-request.schema.json`` and
``assessment-response.schema.json``. The JSON Schema remains normative; these
are its runtime enforcement inside the detector.

Every model forbids unknown fields. That is not tidiness — it is the only
reason a caller cannot smuggle a field the detector was never designed to read
and have it silently become trusted input. A model that quietly drops unknown
keys and one that quietly accepts them are both failures; rejecting is the
behaviour the contract promises.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

# Matches contracts/schemas/common.schema.json. Kept in sync by
# tests/test_contract_parity.py rather than by hand.
MAX_TEXT_CHARS = 32768
MAX_QUOTE_CHARS = 512
MAX_REQUEST_ID_CHARS = 64
MAX_CONTENT_ID_CHARS = 128

STRICT = ConfigDict(extra="forbid", strict=True, frozen=True)

# Strict mode requires an *instance* of an enum, but JSON only carries strings,
# so enum fields opt out of strictness individually. Everything else stays
# strict: an int must not silently become a string, and unknown fields are
# still refused. Only the enum's own membership check is relaxed, and an
# unknown value is still rejected.
LooseEnum = Field(strict=False)

ContentID = Annotated[
    str,
    Field(
        min_length=1, max_length=MAX_CONTENT_ID_CHARS, pattern=r"^[A-Za-z0-9._:\-]+$"
    ),
]
RequestID = Annotated[str, Field(min_length=1, max_length=MAX_REQUEST_ID_CHARS)]
LanguageHint = Annotated[str, Field(pattern=r"^[a-z]{2,3}$")]


class TaskID(StrEnum):
    """Server-resolved task configuration. A caller names a task; it never
    supplies the instructions, the target language or the policy."""

    TRANSLATE_FI_EN_V1 = "translate_fi_en_v1"


class SourceType(StrEnum):
    """What the passage is. Never widens trust: every source type is untrusted."""

    TRANSLATION_INPUT = "translation_input"


class Label(StrEnum):
    """The detector's assessment. Not a decision — policy is applied in Go."""

    NO_INJECTION_DETECTED = "no_injection_detected"
    SUSPICIOUS = "suspicious"
    UNCERTAIN = "uncertain"


class Category(StrEnum):
    TASK_REDIRECTION = "task_redirection"
    DETECTOR_TARGETING = "detector_targeting"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    OUTPUT_FORMAT_HIJACK = "output_format_hijack"


class Content(BaseModel):
    """One bounded passage, untrusted for its entire length."""

    model_config = STRICT

    id: ContentID
    source_type: Annotated[SourceType, LooseEnum]
    text: Annotated[str, Field(min_length=1, max_length=MAX_TEXT_CHARS)]
    language_hint: LanguageHint | None = None


class AssessmentRequest(BaseModel):
    """Gateway to detector. Carries the original passage, unmodified.

    There is deliberately no policy or mode field: the detector assesses, it
    does not decide.
    """

    model_config = STRICT

    request_id: RequestID
    task_id: Annotated[TaskID, LooseEnum]
    content: Content
    deadline_ms: Annotated[int, Field(gt=0)] | None = None


class EvidenceItem(BaseModel):
    """An exact, bounded quotation from the original passage.

    The quote is verified against the referenced content before it leaves the
    detector; a model that invents a citation must not be able to publish it.
    """

    model_config = STRICT

    content_id: ContentID
    quote: Annotated[str, Field(min_length=1, max_length=MAX_QUOTE_CHARS)]
    category: Annotated[Category, LooseEnum] | None = None


class Assessment(BaseModel):
    model_config = STRICT

    label: Annotated[Label, LooseEnum]
    categories: Annotated[list[Annotated[Category, LooseEnum]], Field(max_length=8)]
    evidence: Annotated[list[EvidenceItem], Field(max_length=8)]


class Coverage(BaseModel):
    """Byte accounting. ``scanned`` equals ``original`` or the scan was not
    complete, whatever the model reported."""

    model_config = STRICT

    original_utf8_bytes: Annotated[int, Field(ge=0)]
    scanned_utf8_bytes: Annotated[int, Field(ge=0)]
    truncated: bool


class Versions(BaseModel):
    model_config = STRICT

    detector: Annotated[str, Field(min_length=1)]
    prompt: Annotated[str, Field(min_length=1)]


class Diagnostics(BaseModel):
    """Non-authoritative. Unknown provider usage is absent, never zero —
    reporting an unknown token count as 0 would quietly understate cost."""

    model_config = STRICT

    model: Annotated[str, Field(min_length=1)] | None = None
    latency_ms: Annotated[int, Field(ge=0)] | None = None
    input_tokens: Annotated[int, Field(ge=0)] | None = None
    output_tokens: Annotated[int, Field(ge=0)] | None = None


class AssessmentResponse(BaseModel):
    """Detector to gateway. An assessment and its evidence, with no decision.

    There is deliberately no confidence number: an LLM-invented probability is
    not calibrated and must not be rendered as though it were.
    """

    model_config = STRICT

    request_id: RequestID
    assessment: Assessment
    coverage: Coverage
    versions: Versions
    diagnostics: Diagnostics | None = None


class ErrorBody(BaseModel):
    model_config = STRICT

    code: str
    message: Annotated[str, Field(min_length=1, max_length=512)]


class ErrorResponse(BaseModel):
    """Every non-200 outcome.

    ``extra="forbid"`` is load-bearing: an error can never carry an assessment,
    so no failure path can present itself as a clean scan.
    """

    model_config = STRICT

    request_id: RequestID
    error: ErrorBody
