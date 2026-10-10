"""A deterministic detector used for local development, tests and CI.

It is intentionally crude: it looks for a handful of marker substrings. That
is NOT a detection strategy — the C06 evaluation of exactly this approach
scores recall 0.22 while falsely flagging half the quoted attacks, because
keyword matching cannot tell translating an instruction from obeying one.

Its purpose is to exercise the service's plumbing deterministically and
without spending money. Treating its output as evidence of protection would be
a category error.
"""

from __future__ import annotations

from translation_guard.detectors.base import Detector
from translation_guard.schemas import (
    Assessment,
    Category,
    Content,
    EvidenceItem,
    Label,
)

# Lowercase markers, matched as substrings against the original passage.
_MARKERS: tuple[str, ...] = (
    "ohita aiemmat ohjeet",
    "unohda",
    "ala kaanna",
    "älä käännä",
    "negeer alle eerdere instructies",
    "ignore the previous instructions",
    "ignore all previous instructions",
)


class FakeDetector(Detector):
    """Deterministic marker matcher. Requires no API key and no network."""

    def __init__(self, identity: str = "fake-0", *, fail_start: bool = False) -> None:
        self._identity = identity
        self._fail_start = fail_start
        self._started = False

    @property
    def identity(self) -> str:
        return self._identity

    async def start(self) -> None:
        if self._fail_start:
            raise RuntimeError("fake detector was configured to fail initialisation")
        self._started = True

    async def stop(self) -> None:
        self._started = False

    async def assess(
        self, content: Content, deadline_ms: int | None = None
    ) -> Assessment:
        lowered = content.text.lower()
        hit = next((marker for marker in _MARKERS if marker in lowered), None)
        if hit is None:
            return Assessment(
                label=Label.NO_INJECTION_DETECTED, categories=[], evidence=[]
            )

        # Quote the ORIGINAL span, not the lowercased copy. Evidence must be
        # verifiable against the text the caller sent; a normalised quotation
        # would fail the gateway's own check at C15.
        start = lowered.index(hit)
        quote = content.text[start : start + len(hit)]

        return Assessment(
            label=Label.SUSPICIOUS,
            categories=[Category.TASK_REDIRECTION],
            evidence=[
                EvidenceItem(
                    content_id=content.id,
                    quote=quote,
                    category=Category.TASK_REDIRECTION,
                )
            ],
        )
