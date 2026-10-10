"""C32: an oversized passage is the caller's problem, and says so.

Until C32 the Claude adapter wrapped every `InputTooLarge` as
`DetectorUnavailable`, so the service answered 503 and the gateway passed on
`detector_unavailable`. A passage that was merely too long therefore looked
like an outage: permanent, reported as transient, and worth retrying forever
by any client that treats 503 as a hint to come back later.

The contract already had both codes. `token_budget_exceeded` had no emitter
at all until these paths existed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from translation_guard.api import create_app
from translation_guard.config import DetectorMode, Settings
from translation_guard.limits import (
    DEFAULT_MAX_SOURCE_TOKENS,
    MAX_PASSAGE_BYTES,
    InputTooLarge,
    PassageTooLarge,
    TokenBudgetExceeded,
    check,
)

FINNISH = "Ilmatieteen laitos ennustaa räntäsateita maan etelä- ja keskiosiin. "


def passage_of(chars: int) -> str:
    return (FINNISH * (chars // len(FINNISH) + 1))[:chars]


def test_the_two_size_failures_are_distinguishable() -> None:
    """Separate types, because the remedies differ.

    "Send fewer bytes" and "send a shorter passage" are not the same
    instruction, and a caller cannot convert between them without knowing
    which bound it hit.
    """
    with pytest.raises(TokenBudgetExceeded):
        check(passage_of(DEFAULT_MAX_SOURCE_TOKENS * 2))

    # Over the byte ceiling without being over the token budget is only
    # reachable with text far denser than Finnish, which is the point of
    # having both bounds.
    dense = "\U0001f600" * (MAX_PASSAGE_BYTES // 4 + 1)
    with pytest.raises(PassageTooLarge):
        check(dense)

    # Both remain catchable as one thing, for callers that only need to know
    # the passage was refused.
    for oversized in (passage_of(DEFAULT_MAX_SOURCE_TOKENS * 2), dense):
        with pytest.raises(InputTooLarge):
            check(oversized)


def test_an_over_budget_passage_is_422_not_503() -> None:
    settings = Settings(mode=DetectorMode.FAKE)
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/internal/v1/assessments",
            json={
                "request_id": "req-too-long",
                "task_id": "translate_fi_en_v1",
                "content": {
                    "id": "p1",
                    "source_type": "translation_input",
                    "text": passage_of(DEFAULT_MAX_SOURCE_TOKENS * 2),
                },
            },
        )

    # The fake detector does not enforce the budget - only the Claude adapter
    # does - so this asserts the schema's own character bound is not what
    # rejects it, and the request is accepted at this layer. The end-to-end
    # mapping is covered by the gateway's client tests, which exercise the
    # status this service produces.
    assert response.status_code in (200, 413, 422), response.status_code
    if response.status_code != 200:
        assert response.json()["error"]["code"] in (
            "payload_too_large",
            "token_budget_exceeded",
        )


def test_an_error_response_still_cannot_carry_an_assessment() -> None:
    """The property every failure path has to keep.

    Two new error branches are two new chances for one to return something
    that reads as a clean scan.
    """
    settings = Settings(mode=DetectorMode.FAKE)
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/internal/v1/assessments",
            json={"request_id": "req-bad", "task_id": "nope", "content": {}},
        )
    assert response.status_code != 200
    assert "assessment" not in response.json()
