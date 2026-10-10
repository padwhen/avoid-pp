"""The shared expectations table, loaded.

Both language suites read sdk/contract-expectations.json. This module is only
the Python half of that: it resolves fixture paths, synthesises the passage a
case needs, and leaves the assertions to the test.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
TABLE = REPO_ROOT / "sdk" / "contract-expectations.json"
FIXTURES = REPO_ROOT / "contracts" / "fixtures"


@dataclass(frozen=True)
class Case:
    name: str
    status: int
    raw_body: str
    headers: dict[str, str]
    request_text: str
    expect: dict[str, Any]
    fixture: str | None


def load() -> list[Case]:
    table = json.loads(TABLE.read_text(encoding="utf-8"))
    default_text = str(table["harness"]["default_request_text"])
    cases: list[Case] = []

    for raw in table["cases"]:
        fixture = raw.get("fixture")
        if fixture is not None:
            body_text = (FIXTURES / fixture).read_text(encoding="utf-8")
            body: Any = json.loads(body_text)
        elif "body" in raw:
            body = raw["body"]
            body_text = json.dumps(body)
        else:
            body = None
            body_text = str(raw["raw_body"])

        if "request_text" in raw:
            request_text = str(raw["request_text"])
        elif isinstance(body, dict) and isinstance(body.get("coverage"), dict):
            # A passage of exactly the byte count the response claims, so the
            # client's byte cross-check participates in the case instead of
            # being the thing that trips every fixture.
            size = int(body["coverage"]["original_utf8_bytes"])
            request_text = "a" * size
        else:
            request_text = default_text

        cases.append(
            Case(
                name=str(raw["name"]),
                status=int(raw["status"]),
                raw_body=body_text,
                headers=dict(raw.get("headers", {})),
                request_text=request_text,
                expect=dict(raw["expect"]),
                fixture=fixture,
            )
        )
    return cases
