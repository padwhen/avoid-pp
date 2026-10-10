"""The wire contract, as Python types.

Mirrors ``contracts/schemas/*.json``, which stays normative. These types exist
because the schema is not reachable at runtime by a caller, and because the
useful part of a client is not the HTTP call - it is the set of distinctions
the result preserves.

Three of those distinctions are load-bearing, and all three are easy to lose:

  * **allow, flag and block are three answers, not a boolean.** Monitoring
    mode is the only mode this service can run in before its gates are met,
    and monitoring produces flags. A client that offered ``is_safe()`` would
    force every caller to pick a side for flag, silently, once.
  * **a failure is not an answer.** There is no code path in this module that
    produces a :class:`Verdict` from anything other than a complete, internally
    consistent HTTP 200 body. Failures raise.
  * **an unrecognised value is not a benign value.** Which way to fail depends
    on the field, and the contract says so per field rather than uniformly;
    see :func:`parse_verdict`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

# Mirrors contracts/schemas/common.schema.json. Asserted against the schema
# itself by tests/test_schema_parity.py rather than kept in step by hand.
CONTRACT_VERSION: Final = "1.0.0"
MAX_TEXT_CHARS: Final = 32768
MAX_CONTENT_ID_CHARS: Final = 128
MAX_REQUEST_ID_CHARS: Final = 64


class Action(StrEnum):
    """What the caller must do.

    ``flag`` is a real third value. In monitoring mode a suspicious passage is
    recorded and the application decides whether to proceed; in enforcement it
    becomes a block. That decision belongs to the application, so this client
    reports the action and makes no choice on its behalf.
    """

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class Label(StrEnum):
    """The detector's assessment. Not a decision."""

    NO_INJECTION_DETECTED = "no_injection_detected"
    SUSPICIOUS = "suspicious"
    UNCERTAIN = "uncertain"


class Category(StrEnum):
    TASK_REDIRECTION = "task_redirection"
    DETECTOR_TARGETING = "detector_targeting"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    OUTPUT_FORMAT_HIJACK = "output_format_hijack"


class ReasonCode(StrEnum):
    """Stable explanation of an action, for telemetry and branching."""

    CLEAN_COMPLETE_SCAN = "clean_complete_scan"
    SUSPICIOUS_MONITORING = "suspicious_monitoring"
    SUSPICIOUS_ENFORCED = "suspicious_enforced"
    UNCERTAIN_MONITORING = "uncertain_monitoring"
    UNCERTAIN_ENFORCED = "uncertain_enforced"


class ErrorCode(StrEnum):
    """Every failure the contract defines, plus one that it does not.

    ``UNKNOWN`` is not in ``error.schema.json``. It is what this client reports
    when a failure arrives carrying a code from a later contract version, no
    code at all, or a body written by something that is not the gateway. It
    exists so that "the call failed and we cannot say why" is a value a caller
    can branch on, rather than a ``None`` that reads as "no error".

    ``TOKEN_BUDGET_EXCEEDED`` is in the schema and has no constant in the
    gateway, so it cannot currently be emitted. Handled regardless: a code the
    contract permits is not a code a client may meet with a crash.
    """

    MALFORMED_JSON = "malformed_json"
    SCHEMA_INVALID = "schema_invalid"
    UNKNOWN_TASK_ID = "unknown_task_id"
    UNAUTHENTICATED = "unauthenticated"
    UNAUTHORIZED_TASK = "unauthorized_task"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"
    RATE_LIMITED = "rate_limited"
    DETECTOR_UNAVAILABLE = "detector_unavailable"
    OVERLOADED = "overloaded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    INTERNAL_ERROR = "internal_error"
    UNKNOWN = "unknown"


class TaskID(StrEnum):
    TRANSLATE_FI_EN_V1 = "translate_fi_en_v1"


class SourceType(StrEnum):
    TRANSLATION_INPUT = "translation_input"


@dataclass(frozen=True, slots=True)
class Evidence:
    """An exact quotation from the passage, bounded by the contract.

    Already verified to occur in the passage before it left the detector, so a
    fabricated citation cannot reach here. Still untrusted text: it is a
    fragment of the passage, which is attacker-controlled by definition, and
    rendering it anywhere needs the same escaping the passage would.
    """

    content_id: str
    quote: str
    category: Category | None = None


@dataclass(frozen=True, slots=True)
class Coverage:
    original_utf8_bytes: int
    scanned_utf8_bytes: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class Versions:
    """What produced this result. Every field is needed to reproduce it."""

    contract: str
    detector: str
    prompt: str
    policy: str


@dataclass(frozen=True, slots=True)
class Verdict:
    """A usable decision about a specific passage.

    Frozen, and there is deliberately no field for a confidence number. The
    schema forbids one because an LLM-invented probability is not calibrated,
    and the absence here is the second line of that: a gateway that started
    sending one could not publish it through this client.

    ``scanned_digest`` is over the exact UTF-8 bytes the client sent. It is
    what makes the verdict usable as a ticket - see :meth:`covers`.
    """

    action: Action
    label: Label
    reason_code: str
    request_id: str
    categories: tuple[Category, ...]
    evidence: tuple[Evidence, ...]
    coverage: Coverage
    versions: Versions
    scanned_digest: str
    # Set when the gateway sent an action from a later contract version. The
    # action above is then BLOCK, per the contract's client rule, and this
    # holds what actually arrived so telemetry can show that the enum moved
    # rather than that the passage was hostile.
    unrecognised_action: str | None = field(default=None)

    def covers(self, text: str) -> bool:
        """Whether this verdict is about exactly these bytes.

        The check an integration needs immediately before acting on the
        verdict. A scan and a translation can both be real while being about
        different text, and every realistic bug in that shape - a trim before
        display, a retry carrying an edit, an excerpt scanned and a document
        used - is this returning False.
        """
        return digest_of(text) == self.scanned_digest

    @property
    def reason(self) -> ReasonCode | None:
        """The reason code as an enum, or None if it is from a later version.

        None here is not a failure: the reason code is telemetry, and the
        action is what carries the decision.
        """
        try:
            return ReasonCode(self.reason_code)
        except (ValueError, TypeError):
            return None


def digest_of(text: str) -> str:
    """SHA-256 over the exact UTF-8 bytes.

    Not a normalised form, and that is the point. A digest that folded
    whitespace, case or Unicode composition would let a visually identical but
    different passage pass as the one that was scanned, which is precisely the
    careless pipeline this is here to detect.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ResponseRejected(Exception):
    """A 200 response this client will not derive a decision from.

    Carries a stable ``reason`` slug; the message is for humans and must not
    be branched on. Every reason is a refusal, so a caller that treats this
    exception as "do not proceed" is never wrong.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


# A note on wrong-typed fields.
#
# These helpers exist because the Go client and this one have to agree, and
# their decoders fail at different granularities. Go unmarshals into a struct,
# so `{"coverage": {"original_utf8_bytes": "103"}}` fails as a whole and the
# most specific thing it can say is "this body is not readable". Python would
# happily coerce that string to an integer and carry on.
#
# So the rule is stated once and applied in both: a field that is **absent**
# is a missing field, a field carrying the **wrong JSON type** makes the body
# unreadable, and only a field of the right type with an unrecognised value
# gets a specific answer. Without that rule the two clients would classify the
# same malformed response differently, which is exactly the divergence the
# shared expectations table exists to catch - and it did catch it.


def _string(raw: Any, field: str) -> str:
    if not isinstance(raw, str):
        raise ResponseRejected("unreadable_body", f"{field} is not a string")
    return raw


def _integer(raw: Any, field: str) -> int:
    # bool is a subclass of int in Python, and `true` is not a byte count.
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise ResponseRejected("unreadable_body", f"{field} is not an integer")
    return raw


def _boolean(raw: Any, field: str) -> bool:
    if not isinstance(raw, bool):
        raise ResponseRejected("unreadable_body", f"{field} is not a boolean")
    return raw


def _mapping(raw: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ResponseRejected("unreadable_body", f"{field} is not an object")
    return raw


def _sequence(raw: Any, field: str) -> list[Any]:
    if not isinstance(raw, list):
        raise ResponseRejected("unreadable_body", f"{field} is not an array")
    return raw


def parse_verdict(body: Any, *, sent_text: str) -> Verdict:
    """Turn a 200 body into a verdict, or refuse.

    The checks run in a fixed order, and the order is the contract's own
    reasoning rather than convenience:

    1. **Shape.** A body that is not an object with the required fields is not
       a scan response. An error envelope served with 200 lands here, which is
       what a proxy rewriting a status looks like.
    2. **Status.** ``scan_status`` has one legal value. Anything else forbids a
       clean verdict, so there is no verdict to read.
    3. **Coverage.** A scan of part of a passage is not a verdict about the
       passage, and a verdict about a different number of bytes is not about
       what we sent. This is the check that makes the client, rather than every
       caller, responsible for the scan-translate divergence.
    4. **Label.** An unrecognised label is refused outright, because the
       consistency check in step 6 cannot be performed against a label whose
       meaning is unknown. An unknown label is not a fourth kind of clean.
    5. **Action.** An unrecognised action becomes ``BLOCK``. This is the one
       place the contract tells clients what to do with data they cannot
       understand, and it says so explicitly, so that the enum can grow
       without every old client failing closed into an outage.
    6. **Consistency, in one direction only.** A non-clean label with an allow
       action is the exact failure this service exists to prevent, arriving as
       a well-formed response; it is refused. The mirror case - a clean label
       that was blocked anyway - is honoured, because a server being stricter
       than its schema is not a safety problem, and overriding it would be
       this client second-guessing a server-side decision.
    """
    if not isinstance(body, Mapping):
        raise ResponseRejected(
            "unreadable_body", "the response body is not a JSON object"
        )

    for required in ("request_id", "scan_status", "assessment", "decision", "coverage"):
        if required not in body:
            raise ResponseRejected("missing_field", f"the response has no {required!r}")

    if body["scan_status"] != "complete":
        raise ResponseRejected(
            "scan_not_complete",
            "scan_status is not 'complete', so no clean verdict is possible",
        )

    coverage = _coverage_of(body["coverage"])
    sent_bytes = len(sent_text.encode("utf-8"))
    if coverage.truncated:
        raise ResponseRejected(
            "coverage_truncated", "the gateway reported the passage truncated"
        )
    if coverage.scanned_utf8_bytes != coverage.original_utf8_bytes:
        raise ResponseRejected(
            "coverage_partial",
            f"{coverage.scanned_utf8_bytes} of {coverage.original_utf8_bytes} "
            "bytes were scanned",
        )
    if coverage.original_utf8_bytes != sent_bytes:
        raise ResponseRejected(
            "coverage_mismatch",
            f"the gateway scanned {coverage.original_utf8_bytes} bytes and "
            f"{sent_bytes} were sent, so this verdict is about other text",
        )

    assessment = _mapping(body["assessment"], "assessment")
    if "label" not in assessment:
        raise ResponseRejected("missing_field", "the assessment has no label")
    try:
        label = Label(_string(assessment["label"], "label"))
    except ValueError:
        raise ResponseRejected(
            "unknown_label", "the assessment label is not one this client defines"
        ) from None

    decision = _mapping(body["decision"], "decision")
    if "action" not in decision:
        raise ResponseRejected("missing_field", "the decision has no action")
    raw_action = _string(decision["action"], "action")
    unrecognised: str | None = None
    try:
        action = Action(raw_action)
    except ValueError:
        # common.schema.json: "any value not recognized by the client MUST be
        # treated as block". Not an error and not a rejection - a block.
        action = Action.BLOCK
        unrecognised = raw_action

    if "reason_code" not in decision:
        raise ResponseRejected("missing_field", "the decision has no reason_code")
    reason_code = _string(decision["reason_code"], "reason_code")
    if not reason_code:
        raise ResponseRejected("missing_field", "the decision has an empty reason_code")

    if action is Action.ALLOW:
        if label is not Label.NO_INJECTION_DETECTED:
            raise ResponseRejected(
                "allow_contradicts_label",
                f"the action is allow and the label is {label.value!r}",
            )
        if reason_code != ReasonCode.CLEAN_COMPLETE_SCAN:
            raise ResponseRejected(
                "allow_without_clean_reason",
                f"the action is allow and the reason code is {reason_code!r}",
            )

    return Verdict(
        action=action,
        label=label,
        reason_code=reason_code,
        request_id=str(body["request_id"]),
        categories=_categories_of(assessment.get("categories")),
        evidence=_evidence_of(assessment.get("evidence")),
        coverage=coverage,
        versions=_versions_of(body.get("versions")),
        scanned_digest=digest_of(sent_text),
        unrecognised_action=unrecognised,
    )


def _coverage_of(raw: Any) -> Coverage:
    coverage = _mapping(raw, "coverage")
    for name in ("original_utf8_bytes", "scanned_utf8_bytes", "truncated"):
        if name not in coverage:
            # Absent, which for `truncated` is not the same claim as false:
            # "we do not know whether this was truncated" and "it was not
            # truncated" are different statements, and only one of them is
            # safe to act on.
            raise ResponseRejected("missing_field", f"coverage has no {name}")
    return Coverage(
        original_utf8_bytes=_integer(
            coverage["original_utf8_bytes"], "original_utf8_bytes"
        ),
        scanned_utf8_bytes=_integer(
            coverage["scanned_utf8_bytes"], "scanned_utf8_bytes"
        ),
        truncated=_boolean(coverage["truncated"], "truncated"),
    )


def _categories_of(raw: Any) -> tuple[Category, ...]:
    """Known categories only.

    Categories are advisory - the label and action carry the decision - so one
    from a later contract version is dropped rather than made fatal. Dropping
    is safe here in a way it would not be for the action, because no branch
    anywhere may become permissive through a category being absent.
    """
    if raw is None:
        return ()
    out = []
    for item in _sequence(raw, "categories"):
        try:
            out.append(Category(_string(item, "category")))
        except ValueError:
            continue
    return tuple(out)


def _evidence_of(raw: Any) -> tuple[Evidence, ...]:
    if raw is None:
        return ()
    out = []
    for item in _sequence(raw, "evidence"):
        entry = _mapping(item, "evidence item")
        content_id = _string(entry.get("content_id"), "evidence content_id")
        quote = _string(entry.get("quote"), "evidence quote")
        category: Category | None = None
        if entry.get("category") is not None:
            try:
                category = Category(_string(entry["category"], "evidence category"))
            except ValueError:
                category = None
        out.append(Evidence(content_id=content_id, quote=quote, category=category))
    return tuple(out)


def _versions_of(raw: Any) -> Versions:
    """Version strings, with absent fields recorded as unknown.

    Not fatal, because versions identify a result rather than authorise
    anything. But not silently blank either: a report that cannot say which
    detector and prompt produced a number is not a report, so "unknown" is
    written where the value should be and is visible in any record of it.
    """
    versions: Mapping[str, Any] = {} if raw is None else _mapping(raw, "versions")

    def value(key: str) -> str:
        if key not in versions:
            return "unknown"
        got = _string(versions[key], f"versions.{key}")
        return got or "unknown"

    return Versions(
        contract=value("contract"),
        detector=value("detector"),
        prompt=value("prompt"),
        policy=value("policy"),
    )
