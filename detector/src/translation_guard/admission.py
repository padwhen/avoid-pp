"""The detector's own concurrency bound.

The gateway already bounds how much inference runs at once, so this is
defence in depth rather than the primary control. It exists because the
gateway's bound is an assumption about a *different process*, and the
detector is the thing holding the provider connection and the API budget:

  * the detector is reachable from the internal network, and anything there
    could call it directly - a debug script, a second gateway, a future
    service that nobody remembered to tell about the limit;
  * a gateway deployed with two replicas admits twice its configured
    concurrency, and neither replica knows the other exists;
  * a misconfiguration in the gateway is a configuration mistake, not a
    reason for the detector to make unbounded provider calls.

The shape mirrors the Go side deliberately - a fixed number of slots and a
small bounded queue - so the two are reasoned about the same way rather than
being two different mechanisms that happen to be adjacent.

The bound here is set *above* the gateway's, so in normal operation the
gateway sheds first and this never fires. A detector that is rejecting while
the gateway thinks it has capacity is a signal that something is talking to
it directly, which is worth knowing rather than absorbing silently.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

logger = logging.getLogger("translation_guard.admission")


class AtCapacity(Exception):
    """Both the slots and the waiting queue are full."""


@dataclass
class Stats:
    """A snapshot, for logging and for the load tests."""

    active: int
    waiting: int
    max_active: int
    max_waiting: int
    peak_active: int
    peak_waiting: int
    admitted: int
    rejected: int


class Admission:
    """Bounds concurrent inference with a fixed number of slots.

    Not an ``asyncio.Semaphore`` alone: a semaphore's ``acquire`` waits
    without limit, so an overloaded service would grow an unbounded queue of
    waiters instead of refusing. The waiting count is tracked explicitly so
    there is a number to compare against a bound.
    """

    def __init__(self, max_active: int, max_waiting: int) -> None:
        if max_active < 1:
            raise ValueError("max_active must be at least 1")
        if max_waiting < 0:
            raise ValueError("max_waiting must not be negative")

        self._slots = asyncio.Semaphore(max_active)
        self._max_active = max_active
        self._max_waiting = max_waiting

        self._active = 0
        self._waiting = 0
        self._peak_active = 0
        self._peak_waiting = 0
        self._admitted = 0
        self._rejected = 0

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Hold a slot for the duration of the block.

        Raises AtCapacity when there is neither a slot nor room to wait.

        The slot is released in a finally, so a cancelled request - a caller
        that hung up, or a deadline that passed mid-call - gives its capacity
        back. A slot leaked on cancellation is worse than no bound at all,
        because capacity then drains monotonically at a rate set by how often
        clients disconnect.
        """
        if self._slots.locked() and self._waiting >= self._max_waiting:
            self._rejected += 1
            logger.warning(
                "assessment refused: at capacity (active=%d waiting=%d)",
                self._active,
                self._waiting,
            )
            raise AtCapacity(
                f"{self._active} active and {self._waiting} waiting, "
                f"limits {self._max_active}/{self._max_waiting}"
            )

        self._waiting += 1
        self._peak_waiting = max(self._peak_waiting, self._waiting)
        try:
            await self._slots.acquire()
        finally:
            # Decremented whether the acquire succeeded or was cancelled, so
            # an abandoned waiter does not hold a place in the queue forever.
            self._waiting -= 1

        self._active += 1
        self._admitted += 1
        self._peak_active = max(self._peak_active, self._active)
        try:
            yield
        finally:
            self._active -= 1
            self._slots.release()

    def stats(self) -> Stats:
        return Stats(
            active=self._active,
            waiting=self._waiting,
            max_active=self._max_active,
            max_waiting=self._max_waiting,
            peak_active=self._peak_active,
            peak_waiting=self._peak_waiting,
            admitted=self._admitted,
            rejected=self._rejected,
        )

    def describe(self) -> str:
        return f"max active {self._max_active}, max waiting {self._max_waiting}"
