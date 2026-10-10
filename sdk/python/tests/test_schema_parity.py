"""The SDK's enums against the normative schema.

These constants are a hand transcription of contracts/schemas/*.json, and a
hand transcription drifts. C28 found exactly that: the gateway's Go struct had
been missing two response fields since C18, and nothing failed because the
only path that exercised them was the live one.

So the schema is read and compared rather than trusted to match. A value added
to the contract and not to this client fails here, before a caller meets it.
"""

from __future__ import annotations

import json
from pathlib import Path

from avoidpp import (
    CONTRACT_VERSION,
    MAX_CONTENT_ID_CHARS,
    MAX_TEXT_CHARS,
    Action,
    Category,
    ErrorCode,
    Label,
    ReasonCode,
    SourceType,
    TaskID,
)

SCHEMAS = Path(__file__).resolve().parents[3] / "contracts" / "schemas"


def defs() -> dict[str, dict]:
    return json.loads((SCHEMAS / "common.schema.json").read_text(encoding="utf-8"))[
        "$defs"
    ]


def test_actions_match_the_schema() -> None:
    assert {a.value for a in Action} == set(defs()["action"]["enum"])


def test_labels_match_the_schema() -> None:
    assert {label.value for label in Label} == set(defs()["label"]["enum"])


def test_categories_match_the_schema() -> None:
    assert {c.value for c in Category} == set(defs()["category"]["enum"])


def test_reason_codes_match_the_schema() -> None:
    assert {r.value for r in ReasonCode} == set(defs()["reason_code"]["enum"])


def test_task_ids_and_source_types_match_the_schema() -> None:
    assert {t.value for t in TaskID} == set(defs()["task_id"]["enum"])
    assert {s.value for s in SourceType} == set(defs()["source_type"]["enum"])


def test_error_codes_cover_the_schema_exactly_plus_unknown() -> None:
    """Every contract code, and exactly one addition.

    UNKNOWN is this client's own: a failure carrying a code from a later
    version is still a failure, and must be a value a caller can branch on
    rather than an absence that reads as "no error". The assertion pins that
    the set is the schema's plus that one, so a code quietly dropped from this
    enum - or an invented one added - fails.
    """
    schema = json.loads((SCHEMAS / "error.schema.json").read_text(encoding="utf-8"))
    declared = set(schema["properties"]["error"]["properties"]["code"]["enum"])
    assert {c.value for c in ErrorCode} == declared | {"unknown"}


def test_bounds_match_the_schema() -> None:
    request = json.loads(
        (SCHEMAS / "scan-request.schema.json").read_text(encoding="utf-8")
    )
    text = request["properties"]["content"]["properties"]["text"]
    assert MAX_TEXT_CHARS == text["maxLength"]
    assert MAX_CONTENT_ID_CHARS == defs()["content_id"]["maxLength"]


def test_the_contract_version_matches_the_gateway() -> None:
    """One string, two places, and a report quotes it.

    The gateway's contract package declares the version it implements. A
    client claiming a different one would make `versions.contract` in a scan
    response unattributable.
    """
    go_source = (
        Path(__file__).resolve().parents[3]
        / "gateway"
        / "internal"
        / "contract"
        / "contract.go"
    ).read_text(encoding="utf-8")
    assert f'const Version = "{CONTRACT_VERSION}"' in go_source
