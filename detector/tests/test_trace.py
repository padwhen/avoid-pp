"""C33: trace context is read strictly, and reaches the log line.

The header arrives from the gateway, which is not an adversary - but the
gateway's own header is derived from one a public caller supplied, and a
trace id is written into every log line it touches. A parser that salvaged
what it could would propagate attacker-chosen bytes into log output through
a field nobody thinks of as content.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from translation_guard import trace
from translation_guard.api import create_app
from translation_guard.config import DetectorMode, Settings

VALID = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def test_a_valid_header_is_read() -> None:
    span = trace.parse(VALID)
    assert span is not None
    assert span.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert span.span_id == "00f067aa0ba902b7"
    assert span.sampled is True
    assert span.traceparent == VALID


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "not-a-traceparent",
        VALID[:-1],
        VALID + "0",
        "01" + VALID[2:],  # a version this code cannot interpret
        VALID.upper(),  # uppercase would be a second id for one trace
        "00-" + "0" * 32 + "-00f067aa0ba902b7-01",  # reserved all-zero trace
        "00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01",  # all-zero span
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 extra",
        '00-" injected="yes',
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\n",
        "00-" + "g" * 32 + "-00f067aa0ba902b7-01",
    ],
)
def test_anything_unparseable_yields_no_trace(header: str | None) -> None:
    assert trace.parse(header) is None
    assert trace.fields(header) == {}


def test_an_unsampled_upstream_decision_is_honoured() -> None:
    # A decision this service is not entitled to reverse.
    span = trace.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
    assert span is not None
    assert span.sampled is False
    assert span.traceparent.endswith("-00")


def test_fields_are_shaped_for_a_log_call() -> None:
    assert trace.fields(VALID) == {
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "span_id": "00f067aa0ba902b7",
    }


def scan_with_trace(header: str, capsys) -> list[dict]:
    """Post one assessment and return the log lines it produced.

    Reads the captured stream rather than caplog: `logs.configure` installs
    its own handler and sets propagate=False - deliberately, so nothing
    bypasses the allowlisting formatter - which also means caplog's handler
    never sees the record. Asserting against the real output is the stronger
    test anyway, since it is the text that would actually be shipped.
    """
    settings = Settings(mode=DetectorMode.FAKE)
    with TestClient(create_app(settings)) as client:
        client.post(
            "/internal/v1/assessments",
            headers={trace.HEADER: header},
            json={
                "request_id": "req-trace",
                "task_id": "translate_fi_en_v1",
                "content": {
                    "id": "p1",
                    "source_type": "translation_input",
                    "text": "Sää on tänään aurinkoinen.",
                },
            },
        )

    lines = []
    for line in capsys.readouterr().out.splitlines():
        try:
            lines.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return lines


def test_the_trace_id_reaches_the_log_line(capsys) -> None:
    lines = scan_with_trace(VALID, capsys)
    assert any(
        line.get("trace_id") == "4bf92f3577b34da6a3ce929d0e0e4736"
        and line.get("span_id") == "00f067aa0ba902b7"
        for line in lines
    ), f"no log line carried the trace id: {lines}"


def test_a_forged_trace_id_never_reaches_the_log_line(capsys) -> None:
    """The property the strict parser exists for."""
    lines = scan_with_trace('00-" injected="yes', capsys)

    assert lines, "the request produced no log output at all"
    for line in lines:
        assert "trace_id" not in line, line
        assert "injected" not in json.dumps(line), line


def test_a_trailing_newline_does_not_validate(capsys) -> None:
    """Python's `$` matches before a trailing newline; `\\Z` does not.

    A trace id ending in a newline would split one log line into two, the
    second of which an attacker chooses. The regex uses \\A and \\Z for
    exactly this, and the first draft of trace.py did not.
    """
    assert trace.parse(VALID + "\n") is None
    lines = scan_with_trace(VALID + "\n", capsys)
    for line in lines:
        assert "trace_id" not in line, line
