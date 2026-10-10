"""The Pydantic models must not drift from the normative JSON Schema.

contracts/schemas/*.json is the contract; these models are its runtime
enforcement. Bounds and enum members are duplicated between the two by
necessity, so they are compared here rather than trusted to stay in step.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.conftest import CONTRACTS
from translation_guard import schemas


def common() -> dict[str, Any]:
    path = CONTRACTS / "schemas" / "common.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))["$defs"]


def scan_request() -> dict[str, Any]:
    path = CONTRACTS / "schemas" / "scan-request.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "enum_type,schema_key",
    [
        (schemas.Label, "label"),
        (schemas.Category, "category"),
        (schemas.TaskID, "task_id"),
        (schemas.SourceType, "source_type"),
    ],
)
def test_enum_members_match_the_contract(enum_type, schema_key):
    expected = set(common()[schema_key]["enum"])
    actual = {member.value for member in enum_type}
    assert actual == expected, (
        f"{enum_type.__name__} drifted from common.schema.json#{schema_key}: "
        f"only in models {actual - expected}, only in schema {expected - actual}"
    )


def test_request_id_bound_matches():
    assert schemas.MAX_REQUEST_ID_CHARS == common()["request_id"]["maxLength"]


def test_content_id_bound_matches():
    assert schemas.MAX_CONTENT_ID_CHARS == common()["content_id"]["maxLength"]


def test_quote_bound_matches():
    quote = common()["evidence_item"]["properties"]["quote"]
    assert schemas.MAX_QUOTE_CHARS == quote["maxLength"]


def test_text_bound_matches():
    text = scan_request()["properties"]["content"]["properties"]["text"]
    assert schemas.MAX_TEXT_CHARS == text["maxLength"]


def test_label_has_no_decision_values():
    """The detector assesses; it never decides. allow/flag/block are the
    gateway's vocabulary and must not leak into a detector label."""
    forbidden = set(common()["action"]["enum"])
    assert not {m.value for m in schemas.Label} & forbidden
