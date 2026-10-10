"""Failures, typed so that none of them can be mistaken for a decision.

The hierarchy exists because callers branch differently on the three kinds,
and because "the scan failed" and "the scan said block" are different
statements to make to a user - collapsing them hides a provider outage behind
a security message.

What every class here has in common is the absence of an ``action``. There is
no attribute on any exception in this module that a caller could read as
allow, and no default that fills in when a scan did not happen. A failure has
no verdict, so it carries none.
"""

from __future__ import annotations

from .contract import ErrorCode

# Codes for which this client will retry, and nothing else.
#
# The rule is narrow on purpose: retry only when the server has said the work
# definitively did not happen. A scan is a paid provider call, so retrying a
# request that may already have reached the model doubles the spend to buy a
# verdict the caller is about to turn into a block anyway.
#
# That excludes detector_unavailable - which reads transient but carries no
# retry guidance in the contract - and deadline_exceeded, which says nothing
# at all about whether the provider call completed. See docs/c41-sdk.md.
RETRYABLE_CODES: frozenset[ErrorCode] = frozenset(
    {ErrorCode.RATE_LIMITED, ErrorCode.OVERLOADED}
)

# A 429 is unambiguous about the request not having been served, whoever
# generated it, so it is retried on the status alone even with no readable
# body.
RETRYABLE_STATUS: frozenset[int] = frozenset({429})


class ScanFailed(Exception):
    """Base class. A scan that did not produce a usable verdict.

    A caller that catches only this and refuses to proceed is correct for
    every failure this client can report, now and after the contract grows.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)

    @property
    def retryable(self) -> bool:
        """Whether this client would retry the call that raised this.

        False here does not mean the condition is permanent. It means retrying
        is not this client's decision to make - see ``RETRYABLE_CODES``.
        """
        return False


class TransportFailed(ScanFailed):
    """The request did not complete: connection, TLS, or a client timeout.

    Not retried, and this is the uncomfortable case. A connection error can
    mean the request never arrived, or that it arrived, ran a paid scan, and
    the response was lost. The client cannot tell which, so it reports the
    failure and leaves the choice to a caller who knows whether a duplicate
    scan is worth the money.

    The provoking exception's type name is recorded; its message is not. An
    HTTP library's error text can embed the request URL, and a URL can carry
    userinfo.
    """

    def __init__(self, cause_type: str) -> None:
        super().__init__(f"the gateway could not be reached ({cause_type})")
        self.cause_type = cause_type


class ServiceFailed(ScanFailed):
    """The gateway answered with a failure.

    ``code`` is always set. ``ErrorCode.UNKNOWN`` covers a code from a later
    contract version, a body with no code, and a body written by something
    that is not the gateway - all of which are failures, and none of which may
    be reported as the absence of an error.
    """

    def __init__(
        self,
        *,
        status: int,
        code: ErrorCode,
        request_id: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(f"the gateway returned {status} ({code.value})")
        self.status = status
        self.code = code
        self.request_id = request_id
        self.retry_after_seconds = retry_after_seconds

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE_CODES or self.status in RETRYABLE_STATUS


class ResponseUnusable(ScanFailed):
    """HTTP 200, and no decision this client is willing to derive from it.

    Separate from :class:`ServiceFailed` because it means something different:
    the call succeeded and the contract was broken. A caller treating this as
    transient and retrying would get the same answer, which is why the reason
    slug is worth logging.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"the gateway returned an unusable scan ({reason}): {detail}")
        self.reason = reason


class NotConfigured(ScanFailed):
    """The client was built or used wrongly: no timeout, no key, not started.

    A subclass of :class:`ScanFailed` rather than a ValueError, so that a
    caller wrapping scans in ``except ScanFailed`` and refusing to proceed
    cannot be bypassed by a misconfiguration. Misconfiguration is one of the
    likelier ways a guard ends up not guarding.
    """
