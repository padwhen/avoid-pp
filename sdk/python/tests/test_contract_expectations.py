"""The Python half of the cross-language contract test.

Every assertion here comes from sdk/contract-expectations.json, which the Go
suite reads too. Two test suites that merely agree are two opinions; one table
and two implementations of it is a contract test.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import httpx
import pytest
from avoidpp import (
    Action,
    ErrorCode,
    Label,
    ResponseUnusable,
    ScanClient,
    ServiceFailed,
    Verdict,
)
from expectations import FIXTURES, TABLE, Case, load

CASES = load()


def client_for(case: Case) -> ScanClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            case.status,
            content=case.raw_body.encode("utf-8"),
            headers={"Content-Type": "application/json", **case.headers},
        )

    return ScanClient(
        base_url="https://gateway.test",
        api_key="k" * 32,
        timeout_seconds=5.0,
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_case(case: Case) -> None:
    async with client_for(case) as client:
        expect = case.expect
        outcome = expect["outcome"]

        if outcome == "verdict":
            verdict = await client.scan(case.request_text, content_id="case-1")
            assert verdict.action is Action(expect["action"])
            assert verdict.label is Label(expect["label"])
            assert verdict.reason_code == expect["reason_code"]
            assert verdict.unrecognised_action == expect.get("unrecognised_action")
            # The verdict is about the passage that was sent, and says so.
            assert verdict.covers(case.request_text)
            assert not verdict.covers(case.request_text + " ")
            if "no_field_named" in expect:
                assert expect["no_field_named"] not in {f.name for f in fields(Verdict)}
            return

        if outcome == "error":
            with pytest.raises(ServiceFailed) as raised:
                await client.scan(case.request_text, content_id="case-1")
            assert raised.value.code is ErrorCode(expect["code"])
            assert raised.value.status == case.status
            assert raised.value.retryable is expect["retries"]
            if "retry_after_seconds" in expect:
                assert raised.value.retry_after_seconds == expect["retry_after_seconds"]
            if "no_field_named" in expect:
                assert not hasattr(raised.value, expect["no_field_named"])
            return

        if outcome == "rejected":
            with pytest.raises(ResponseUnusable) as rejected:
                await client.scan(case.request_text, content_id="case-1")
            assert rejected.value.reason == expect["reason"]
            # A rejection is never retried: the same request would get the
            # same contradictory answer.
            assert rejected.value.retryable is False
            return

        raise AssertionError(f"unknown expected outcome {outcome!r}")


def test_every_contract_fixture_has_an_expectation() -> None:
    """No fixture may be silently absent from the table.

    Without this, adding a fixture to contracts/fixtures/ would leave both
    clients untested against it, and the omission would look exactly like
    coverage.
    """
    listed = {case.fixture for case in CASES if case.fixture}
    on_disk = {
        f"{kind}/{path.name}"
        for kind in ("valid", "invalid")
        for path in (FIXTURES / kind).glob("*.json")
        if path.name.startswith(("scan-response.", "error."))
    }
    assert on_disk - listed == set(), "fixtures with no client expectation"
    assert listed - on_disk == set(), "expectations naming a fixture that is gone"


def test_no_allow_outside_the_declared_allow_cases() -> None:
    """The table itself may not grow a permissive expectation by accident.

    A guard's test table is a thing people edit under time pressure. This
    asserts that the only cases expecting an allow are ones whose label is the
    clean one, so a future edit that turns a hostile case into an allow fails
    here rather than passing quietly.
    """
    for case in CASES:
        if case.expect.get("action") == "allow":
            assert case.expect["label"] == "no_injection_detected", case.name
            assert case.expect["reason_code"] == "clean_complete_scan", case.name


def test_table_and_fixtures_are_readable_json() -> None:
    assert isinstance(json.loads(Path(TABLE).read_text(encoding="utf-8")), dict)
