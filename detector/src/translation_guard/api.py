"""The private detector service.

Exposes ``POST /internal/v1/assessments`` plus liveness and readiness. Private
by construction: it is never published to the host in the Compose topology at
C12, and the gateway reaches it over the internal network.

Two behaviours here exist to stop a failure from reading as a clean result:

  * a detector that cannot start leaves the service **live but not ready**, so
    an orchestrator routes traffic away instead of killing a process that
    would only fail the same way after restart;
  * an operational failure returns 503 with an error envelope that cannot
    carry an assessment, rather than an assessment that happens to look fine.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from translation_guard.config import DetectorMode, Settings
from translation_guard.detectors import (
    ClaudeDetector,
    Detector,
    DetectorUnavailable,
    FakeDetector,
)
from translation_guard.detectors.claude import PROMPT_VERSION as CLAUDE_PROMPT_VERSION
from translation_guard.schemas import (
    AssessmentRequest,
    AssessmentResponse,
    Coverage,
    ErrorBody,
    ErrorResponse,
    Versions,
)

logger = logging.getLogger("translation_guard")


@dataclass
class State:
    """Runtime state. ``ready`` flips only after initialisation succeeds."""

    settings: Settings
    detector: Detector | None = None
    ready: bool = False
    init_error: str | None = field(default=None)


def build_detector(settings: Settings) -> Detector:
    """Select the detector implementation.

    Fake is the default. Live is opt-in because every scan costs money, and
    a missing key fails at startup so the service reports not-ready rather
    than accepting traffic it cannot serve.
    """
    if settings.mode is DetectorMode.LIVE:
        return ClaudeDetector(
            api_key=settings.api_key,
            model=settings.model,
            identity=f"claude:{settings.model}",
            timeout_seconds=settings.request_timeout_seconds,
        )
    return FakeDetector(
        identity=settings.detector_version,
        fail_start=settings.fail_initialisation,
    )


def error_response(
    request_id: str, code: str, message: str, http_status: int
) -> JSONResponse:
    """Build an error envelope.

    ErrorResponse forbids extra fields, so no error can carry an assessment.
    """
    body = ErrorResponse(
        request_id=request_id or "unknown",
        error=ErrorBody(code=code, message=message),
    )
    return JSONResponse(status_code=http_status, content=body.model_dump(mode="json"))


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings()
    state = State(settings=resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        detector = build_detector(resolved)
        try:
            await detector.start()
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            # C08-AC3: the process stays up so readiness can report the
            # failure. Exiting here would turn a recoverable dependency
            # problem into a crash loop that reports nothing.
            state.init_error = type(exc).__name__
            logger.error("detector initialisation failed: %s", type(exc).__name__)
        else:
            state.detector = detector
            state.ready = True
            logger.info("detector ready: %s", detector.identity)
        try:
            yield
        finally:
            state.ready = False
            if state.detector is not None:
                await state.detector.stop()

    app = FastAPI(
        title="avoid-pp detector",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime = state

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Reject malformed input with 422 and no assessment.

        The detail is deliberately not echoed: it embeds the offending input,
        which is attacker-controlled and may be a passage.
        """
        request_id = _request_id_of(exc)
        return error_response(
            request_id,
            "schema_invalid",
            "Request does not match the assessment schema.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness. Answers whenever the process runs, with no external call."""
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        """Readiness. 503 until the detector has started successfully."""
        if not state.ready:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "not_ready",
                    "reason": state.init_error or "starting",
                },
            )
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ready"})

    @app.post(
        "/internal/v1/assessments",
        response_model=AssessmentResponse,
        response_model_exclude_none=True,
    )
    async def assess(payload: AssessmentRequest) -> Any:
        if not state.ready or state.detector is None:
            return error_response(
                payload.request_id,
                "detector_unavailable",
                "Detector is not available.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        try:
            assessment = await state.detector.assess(
                payload.content, payload.deadline_ms
            )
        except DetectorUnavailable:
            return error_response(
                payload.request_id,
                "detector_unavailable",
                "Detector is not available.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception:  # noqa: BLE001 - never surfaces as a clean assessment
            logger.exception("assessment failed")
            return error_response(
                payload.request_id,
                "internal_error",
                "Assessment failed.",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Coverage is computed from the bytes actually received, never from
        # what the detector claims. The whole passage reached the detector, so
        # scanned equals original and truncated is false.
        encoded = len(payload.content.text.encode("utf-8"))
        return AssessmentResponse(
            request_id=payload.request_id,
            assessment=assessment,
            coverage=Coverage(
                original_utf8_bytes=encoded,
                scanned_utf8_bytes=encoded,
                truncated=False,
            ),
            versions=Versions(
                detector=state.detector.identity,
                prompt=(
                    CLAUDE_PROMPT_VERSION
                    if resolved.mode is DetectorMode.LIVE
                    else resolved.prompt_version
                ),
            ),
        )

    return app


def _request_id_of(exc: RequestValidationError) -> str:
    """Recover request_id from a rejected body, for correlation only."""
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        candidate = body.get("request_id")
        if isinstance(candidate, str) and 0 < len(candidate) <= 64:
            return candidate
    return "unknown"


app = create_app()
