"""W3C Trace Context, so one request is followable across both services.

The gateway sends a `traceparent` header on every assessment call. Reading it
here is what makes C33-AC1 true: a trace id in a gateway log line finds the
matching detector log line, which is the difference between "the scan took
nine seconds" and knowing which of the two services spent them.

## Why this parses rather than trusts

The header reaches this service from the gateway, which is not an adversary.
But the gateway's own header is derived from one a public caller supplied,
and a trace id is written into every log line it touches. A parser that
salvaged what it could would propagate attacker-chosen bytes into log
output - the exact class of problem `logs.py` exists to prevent, arriving
through a field nobody thinks of as content.

So: 32 lowercase hex digits for a trace id, 16 for a span id, the all-zero
values rejected as the specification requires, and anything else discarded
in favour of nothing. An absent trace is better than a forged one.

This deliberately mirrors `gateway/internal/telemetry/tracecontext.go`. The
two are small, and a shared implementation across two languages would be a
package to publish and version for sixty lines of string validation; the
cross-language integration test is what keeps them honest instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

HEADER: Final = "traceparent"

# version "00", trace id, span id, flags. Lowercase hex only: accepting
# uppercase would make one trace appear under two identifiers in anything
# that compares them as strings.
#
# `\Z` rather than `$`, which is not a detail. In Python `$` also matches
# immediately before a trailing newline, so `"00-...-01\n"` satisfied this
# pattern and a trace id carrying a newline reached the log line - the exact
# log-injection shape this module's strictness exists to prevent. The test
# found it; review had not.
_TRACEPARENT = re.compile(r"\A00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})\Z")

_ZERO_TRACE: Final = "0" * 32
_ZERO_SPAN: Final = "0" * 16


@dataclass(frozen=True, slots=True)
class SpanContext:
    """One request's position in a trace."""

    trace_id: str
    span_id: str
    sampled: bool

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{'01' if self.sampled else '00'}"


def parse(header: str | None) -> SpanContext | None:
    """Read a traceparent header, or return None.

    None rather than a partially populated context: a caller that forgets to
    check gets no trace id at all, which is visibly missing, instead of a
    plausible-looking one that correlates with nothing.
    """
    if not header:
        return None
    match = _TRACEPARENT.match(header)
    if match is None:
        return None

    trace_id, span_id, flags = match.groups()
    if trace_id == _ZERO_TRACE or span_id == _ZERO_SPAN:
        # Reserved as invalid by the specification, and exactly what a buggy
        # upstream emits.
        return None

    return SpanContext(
        trace_id=trace_id,
        span_id=span_id,
        sampled=bool(int(flags, 16) & 0x01),
    )


def fields(header: str | None) -> dict[str, str]:
    """Trace identifiers as log fields, or an empty dict.

    Shaped for `logger.info(..., extra=trace.fields(header))` so a handler
    does not have to branch on whether a trace was present.
    """
    span = parse(header)
    if span is None:
        return {}
    return {"trace_id": span.trace_id, "span_id": span.span_id}
