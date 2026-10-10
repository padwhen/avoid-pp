"""The interface every detector implements.

Kept deliberately narrow: a detector receives the original passage and returns
an assessment. It is given no policy, no mode and no decision authority, so a
future implementation cannot quietly start deciding instead of assessing.

The interface is async because the real implementation at C13 performs network
I/O under a deadline. Establishing that now means the fake and the live client
are drop-in replacements rather than differently-shaped code paths.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from translation_guard.schemas import Assessment, Content


class DetectorUnavailable(RuntimeError):
    """The detector cannot produce an assessment.

    Raised for operational failures: a provider outage, an expired deadline, a
    malformed provider response. It is never a clean verdict, and the API maps
    it to 503 rather than to an assessment.
    """


@runtime_checkable
class Detector(Protocol):
    """Produces an assessment for one passage."""

    @property
    def identity(self) -> str:
        """Stable identifier recorded in reports, e.g. ``fake-0``."""
        ...

    async def start(self) -> None:
        """Prepare the detector. Raises if it cannot be made ready."""
        ...

    async def stop(self) -> None:
        """Release resources. Must be safe to call without a successful start."""
        ...

    async def assess(self, content: Content, deadline_ms: int | None) -> Assessment:
        """Assess one passage, or raise DetectorUnavailable."""
        ...
