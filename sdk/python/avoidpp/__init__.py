"""A typed client for the avoid-pp scan API.

    async with ScanClient(
        base_url="https://gateway.internal",
        api_key=key,
        timeout_seconds=20.0,
    ) as client:
        verdict = await client.scan(passage, content_id="doc-17")

    if permits_translation(verdict) and verdict.covers(passage):
        await translate(passage)

Every failure raises. There is no return value from ``scan`` that means the
scan did not happen, and no attribute anywhere in this package that defaults
to ``allow``.

See docs/c41-sdk.md for the reasoning, and sdk/contract-expectations.json for
the behaviour this client is held to - the same table the Go client is tested
against.
"""

from .client import Retry, ScanClient, permits_translation, retry_delay
from .contract import (
    CONTRACT_VERSION,
    MAX_CONTENT_ID_CHARS,
    MAX_TEXT_CHARS,
    Action,
    Category,
    Coverage,
    ErrorCode,
    Evidence,
    Label,
    ReasonCode,
    ResponseRejected,
    SourceType,
    TaskID,
    Verdict,
    Versions,
    digest_of,
)
from .errors import (
    RETRYABLE_CODES,
    NotConfigured,
    ResponseUnusable,
    ScanFailed,
    ServiceFailed,
    TransportFailed,
)

__all__ = [
    "CONTRACT_VERSION",
    "MAX_CONTENT_ID_CHARS",
    "MAX_TEXT_CHARS",
    "RETRYABLE_CODES",
    "Action",
    "Category",
    "Coverage",
    "ErrorCode",
    "Evidence",
    "Label",
    "NotConfigured",
    "ReasonCode",
    "ResponseRejected",
    "ResponseUnusable",
    "Retry",
    "ScanClient",
    "ScanFailed",
    "ServiceFailed",
    "SourceType",
    "TaskID",
    "TransportFailed",
    "Verdict",
    "Versions",
    "digest_of",
    "permits_translation",
    "retry_delay",
]
