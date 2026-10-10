"""A detector backed by Claude, via the official Anthropic SDK.

This module is the provider adapter only. The detector *prompt* is C14's job;
what is here is a deliberately minimal instruction so the plumbing can be
exercised end to end. Output validation against the original passage is C15.

Three properties are load-bearing:

  * **No tools are exposed.** Structured outputs constrain the response to a
    JSON schema without declaring a single tool, so there is no tool surface
    for a passage to aim at. A detector with tools is a detector that can be
    talked into using them.
  * **The passage is data, never instruction.** It travels in a user message,
    fenced and labelled, with the task rules in the system prompt. That does
    not make injection impossible — nothing here does — but it keeps the
    boundary explicit and is what C14 then has to make effective.
  * **Nothing uncertain becomes clean.** Every failure path raises
    DetectorUnavailable. A refusal, a timeout, a malformed answer and an
    outage all look the same to the caller: no assessment.

The module is named ``claude`` rather than ``anthropic`` on purpose - a module
named after the package it imports shadows that package.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Annotated, Any

import anthropic
from pydantic import BaseModel, ConfigDict, Field

from translation_guard import prompts, retry
from translation_guard.detectors.base import Detector, DetectorUnavailable
from translation_guard.limits import Budget, InputTooLarge
from translation_guard.limits import check as check_limits
from translation_guard.schemas import (
    Assessment,
    Category,
    Content,
    Diagnostics,
    Label,
)
from translation_guard.validation import InvalidModelOutput, validate

logger = logging.getLogger("translation_guard.claude")

# Account-level 400s that are worth naming, because the fix is specific and
# nothing else about a 400 suggests it.
#
# Matched on a narrow substring of the provider's message, but the string
# emitted is **ours**. Passing the provider's message through would be the
# leak C23 closed: an error body can echo the request, and a 400 is exactly
# where that happens. So the match is read and discarded.
_ACCOUNT_PROBLEMS = (
    ("credit balance is too low", "provider credit balance exhausted"),
    ("billing", "provider billing problem"),
    ("quota", "provider quota exhausted"),
)


def _permanent_reason(status: int, exc: Exception) -> str:
    """A safe reason for a non-retryable provider status.

    A bare "provider returned 400" is accurate and useless: it was the answer
    to 436 consecutive failures whose actual cause was an empty account, and
    the generic message sent the investigation to the request shape instead of
    to the billing page.
    """
    if status == 400:
        # str(exc) may contain the request. It is inspected and never kept.
        lowered = str(exc).lower()
        for marker, reason in _ACCOUNT_PROBLEMS:
            if marker in lowered:
                return reason
    return f"provider returned {status}"


# The prompt is a versioned artifact under translation_guard/prompts, not a
# string here. Changing its wording means a new version, because a saved
# evaluation report naming a version is a claim about those exact bytes.
DEFAULT_PROMPT_VERSION = prompts.DEFAULT_VERSION

# Kept so existing imports and the live-smoke script keep working; both read
# from the registry.
_DEFAULT = prompts.get(DEFAULT_PROMPT_VERSION)
PROMPT_VERSION = _DEFAULT.version
SYSTEM_PROMPT = _DEFAULT.system
USER_TEMPLATE = _DEFAULT.user_template


class _ModelAssessment(BaseModel):
    """The shape the model is constrained to return.

    Deliberately narrow. There is no confidence field: an LLM-invented
    probability is not calibrated, and exposing one would invite a caller to
    treat it as though it were.
    """

    model_config = ConfigDict(extra="forbid")

    label: Label
    categories: Annotated[list[Category], Field(max_length=8)] = []
    evidence_quotes: Annotated[
        list[Annotated[str, Field(max_length=512)]], Field(max_length=8)
    ] = []
    # Advisory only - nothing downstream reads it. The bound is generous
    # because a tight one on an unused field turned a long explanation into a
    # failed assessment during the first live run.
    reasoning: Annotated[str, Field(max_length=4000)] = ""


class ClaudeDetector(Detector):
    """Calls Claude through the official SDK and maps the reply to an Assessment."""

    def __init__(
        self,
        *,
        api_key: str | None,
        model: str,
        identity: str,
        max_tokens: int = 2048,
        timeout_seconds: float = 15.0,
        on_usage: Callable[[int, int], None] | None = None,
        prompt_version: str = DEFAULT_PROMPT_VERSION,
        budget: Budget | None = None,
        retry_policy: retry.RetryPolicy | None = None,
    ) -> None:
        self._budget = budget or Budget()
        self._retry = retry_policy or retry.RetryPolicy(
            max_attempts=3, total_deadline_seconds=timeout_seconds
        )
        self._api_key = api_key
        self._model = model
        self._identity = identity
        self._prompt = prompts.get(prompt_version)
        self._max_tokens = max_tokens
        self._timeout = timeout_seconds
        # Optional observer for token usage, so an evaluation can report what
        # a run actually cost instead of estimating it.
        self._on_usage = on_usage
        self._client: anthropic.AsyncAnthropic | None = None
        self._last_diagnostics: Diagnostics | None = None

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def last_diagnostics(self) -> Diagnostics | None:
        """Diagnostics from the most recent assessment, or None."""
        return self._last_diagnostics

    @property
    def prompt_fingerprint(self) -> str:
        """SHA-256 of the prompt bytes actually in use."""
        return self._prompt.fingerprint()

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    @property
    def prompt_version(self) -> str:
        """Recorded with every result, so a number can be attributed."""
        return self._prompt.version

    async def start(self) -> None:
        """Construct the client.

        A missing key fails here rather than on the first scan, so the service
        reports not-ready instead of accepting traffic it cannot serve.
        """
        if not self._api_key:
            raise RuntimeError(
                "no API key configured; set LLM_API_KEY or run in fake mode"
            )
        self._client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            timeout=self._timeout,
            # The gateway owns the end-to-end deadline and its own retry
            # policy arrives at C17. An SDK retry here would silently multiply
            # attempts inside a budget the gateway thinks it controls.
            max_retries=0,
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def assess(
        self, content: Content, deadline_ms: int | None = None
    ) -> Assessment:
        if self._client is None:
            raise DetectorUnavailable("detector was not started")

        # C16: bound the input before spending anything. An oversized passage
        # is refused outright - there is no path here that trims it and then
        # reports a complete scan.
        try:
            check_limits(content.text, self._budget)
        except InputTooLarge as exc:
            raise DetectorUnavailable(f"input rejected: {exc}") from exc

        request_timeout = self._timeout
        if deadline_ms is not None:
            # Never exceed the budget the gateway already committed to.
            request_timeout = min(self._timeout, max(deadline_ms / 1000.0, 0.1))

        started = time.monotonic()
        attempts = 0
        # Per-assessment, so a concurrent scan cannot read another's numbers.
        usage: dict[str, int] = {}

        async def attempt(remaining: float) -> Any:
            nonlocal attempts
            attempts += 1
            """One provider call, bounded by what is left of the budget."""
            assert self._client is not None
            try:
                return await self._client.messages.parse(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=self._prompt.system,
                    messages=[
                        {
                            "role": "user",
                            "content": self._prompt.render_user(
                                content_id=content.id,
                                language_hint=content.language_hint or "unspecified",
                                text=content.text,
                            ),
                        }
                    ],
                    output_format=_ModelAssessment,
                    timeout=min(request_timeout, remaining),
                )
            # Transient: the same request may succeed shortly.
            except anthropic.APITimeoutError as exc:
                raise retry.RetryableError("provider timed out") from exc
            except anthropic.RateLimitError as exc:
                raise retry.RetryableError("provider rate limited the request") from exc
            except anthropic.APIConnectionError as exc:
                raise retry.RetryableError("could not reach the provider") from exc
            # Permanent: retrying cannot change the answer, only the latency.
            except anthropic.AuthenticationError as exc:
                raise retry.PermanentError("provider rejected the credentials") from exc
            except anthropic.APIStatusError as exc:
                status = exc.status_code
                if status >= 500:
                    raise retry.RetryableError(f"provider returned {status}") from exc
                raise retry.PermanentError(_permanent_reason(status, exc)) from exc
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A schema violation will recur on an identical request.
                raise retry.PermanentError(
                    f"provider reply could not be processed ({type(exc).__name__})"
                ) from exc

        try:
            response = await retry.run(
                attempt,
                retry.RetryPolicy(
                    max_attempts=self._retry.max_attempts,
                    total_deadline_seconds=min(
                        self._retry.total_deadline_seconds, request_timeout
                    ),
                    initial_backoff_seconds=self._retry.initial_backoff_seconds,
                    max_backoff_seconds=self._retry.max_backoff_seconds,
                    jitter=self._retry.jitter,
                ),
            )
        except retry.DeadlineExceeded as exc:
            raise DetectorUnavailable(f"scan deadline expired: {exc}") from exc
        except (retry.RetryableError, retry.PermanentError) as exc:
            raise DetectorUnavailable(str(exc)) from exc

        elapsed_ms = int((time.monotonic() - started) * 1000)

        reported = getattr(response, "usage", None)
        if reported is not None:
            # Absent, never zero: reporting an unknown token count as 0 would
            # quietly understate cost in every report that aggregates it.
            for field in ("input_tokens", "output_tokens"):
                value = getattr(reported, field, None)
                if isinstance(value, int):
                    usage[field] = value
            if self._on_usage is not None:
                self._on_usage(
                    usage.get("input_tokens", 0), usage.get("output_tokens", 0)
                )

        self._last_diagnostics = Diagnostics(
            model=self._model,
            latency_ms=elapsed_ms,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
            attempts=attempts,
            max_tokens=self._max_tokens,
        )

        # A safety refusal is not an assessment. Treating it as clean would
        # turn the model declining to answer into permission to continue.
        if getattr(response, "stop_reason", None) == "refusal":
            raise DetectorUnavailable("provider refused the request")

        parsed: Any = getattr(response, "parsed_output", None)
        if parsed is None:
            raise DetectorUnavailable("provider returned no parseable assessment")

        assessment = self._to_assessment(parsed, content)
        logger.info(
            "assessed in %dms: label=%s evidence=%d",
            elapsed_ms,
            assessment.label.value,
            len(assessment.evidence),
        )
        return assessment

    def _to_assessment(self, parsed: _ModelAssessment, content: Content) -> Assessment:
        """Map the model's reply onto the contract type, via validation.

        Schema validity is not truth. translation_guard.validation checks every
        quotation against the passage it cites and rejects a suspicious verdict
        whose quotations were all invented.
        """
        try:
            result = validate(
                parsed.label, list(parsed.categories), parsed.evidence_quotes, content
            )
        except InvalidModelOutput as exc:
            raise DetectorUnavailable(f"model output failed validation: {exc}") from exc

        if result.had_fabrication:
            # Counted, not merely logged: a detector that regularly invents
            # quotations is a quality signal, and C18 surfaces it.
            logger.warning(
                "rejected %d fabricated quotation(s); %d accepted",
                len(result.rejected_quotes),
                result.accepted_quotes,
            )
        return result.assessment
