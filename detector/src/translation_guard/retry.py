"""Bounded retries that share one deadline.

The dangerous property of retries is that they compose. A gateway that retries
twice, calling a detector that retries three times, over an SDK that retries
twice of its own accord, is nine provider requests for one scan — and nobody
wrote "nine" anywhere. Each layer looks reasonable in isolation.

So retrying happens in exactly one place, here, and the layers around it are
deliberately set to one attempt:

  * the provider SDK is constructed with ``max_retries=0`` (see claude.py);
  * the gateway does not retry a scan, it reports the failure;
  * this module is the only thing that tries again.

Every attempt shares a **single deadline** rather than getting its own clock.
A per-attempt timeout multiplies: three attempts at fifteen seconds is a
forty-five second request against a budget the caller believed was fifteen.
Here the deadline is absolute, checked before each attempt, and a retry that
cannot finish within what remains is not started.

Only transient failures are retried. Retrying an authentication error or a
rejected schema cannot succeed; it just spends the budget before returning the
same answer more slowly.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

logger = logging.getLogger("translation_guard.retry")

# Injected so tests run on a fake clock instead of sleeping.
Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class RetryableError(Exception):
    """A failure worth trying again: a timeout, a connection drop, a 429, a 5xx."""


class PermanentError(Exception):
    """A failure that retrying cannot fix: bad credentials, a rejected schema."""


class DeadlineExceeded(Exception):
    """The shared budget ran out."""


@dataclass(frozen=True)
class RetryPolicy:
    """How many attempts, and how long in total."""

    max_attempts: int = 3
    total_deadline_seconds: float = 15.0
    initial_backoff_seconds: float = 0.25
    max_backoff_seconds: float = 2.0
    # Jitter spreads a thundering herd when many requests fail together.
    jitter: float = 0.1

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.total_deadline_seconds <= 0:
            raise ValueError("total_deadline_seconds must be positive")

    def backoff_for(
        self, attempt: int, rand: Callable[[], float] = random.random
    ) -> float:
        """Exponential backoff for a 1-indexed attempt number."""
        base = min(
            self.initial_backoff_seconds * (2 ** (attempt - 1)),
            self.max_backoff_seconds,
        )
        return float(base + base * self.jitter * rand())


async def run[T](
    operation: Callable[[float], Awaitable[T]],
    policy: RetryPolicy,
    *,
    clock: Clock | None = None,
    sleeper: Sleeper | None = None,
    rand: Callable[[], float] = random.random,
) -> T:
    """Run ``operation`` with bounded retries inside one shared deadline.

    ``operation`` receives the seconds remaining, so the attempt it makes can
    be bounded by what is actually left rather than by a fresh timeout.
    """
    now = clock or asyncio.get_running_loop().time
    sleep = sleeper or asyncio.sleep

    started = now()
    deadline = started + policy.total_deadline_seconds
    last: Exception | None = None

    for attempt in range(1, policy.max_attempts + 1):
        remaining = deadline - now()
        if remaining <= 0:
            raise DeadlineExceeded(
                f"budget of {policy.total_deadline_seconds}s expired after "
                f"{attempt - 1} attempt(s)"
            ) from last

        try:
            return await operation(remaining)
        except PermanentError:
            # Retrying cannot change the answer, only the latency.
            raise
        except RetryableError as exc:
            last = exc
            if attempt == policy.max_attempts:
                break

            wait = policy.backoff_for(attempt, rand)
            # A sleep that would outlast the budget is pointless: waking up
            # past the deadline means the next attempt is never made.
            if now() + wait >= deadline:
                raise DeadlineExceeded(
                    f"budget of {policy.total_deadline_seconds}s would expire "
                    f"during backoff after attempt {attempt}"
                ) from exc
            logger.info(
                "attempt %d/%d failed (%s), retrying in %.2fs",
                attempt,
                policy.max_attempts,
                type(exc).__name__,
                wait,
            )
            await sleep(wait)

    raise RetryableError(f"all {policy.max_attempts} attempts failed: {last}") from last
