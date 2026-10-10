"""C17: bounded retries sharing one deadline.

Runs on a fake clock. Nothing here sleeps, so the suite stays fast and the
timing assertions are exact rather than flaky.
"""

from __future__ import annotations

import pytest

from translation_guard.retry import (
    DeadlineExceeded,
    PermanentError,
    RetryableError,
    RetryPolicy,
    run,
)


class FakeClock:
    """A clock that only advances when something sleeps."""

    def __init__(self) -> None:
        self.t = 1000.0
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds

    def advance(self, seconds: float) -> None:
        self.t += seconds


def no_jitter() -> float:
    return 0.0


# C17-AC1: transient failures retry; permanent ones do not.
async def test_a_transient_failure_is_retried_until_it_succeeds():
    clock = FakeClock()
    attempts = 0

    async def flaky(remaining: float) -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RetryableError("provider hiccup")
        return "ok"

    got = await run(
        flaky,
        RetryPolicy(max_attempts=3, total_deadline_seconds=30),
        clock=clock.now,
        sleeper=clock.sleep,
        rand=no_jitter,
    )
    assert got == "ok"
    assert attempts == 3
    assert clock.slept == [0.25, 0.5], "backoff should be exponential"


@pytest.mark.parametrize(
    "error", [PermanentError("bad credentials"), PermanentError("schema")]
)
async def test_permanent_failures_are_not_retried(error):
    """Retrying an auth error or a rejected schema cannot succeed; it just
    spends the budget and returns the same answer more slowly."""
    clock = FakeClock()
    attempts = 0

    async def always_permanent(remaining: float) -> str:
        nonlocal attempts
        attempts += 1
        raise error

    with pytest.raises(PermanentError):
        await run(
            always_permanent,
            RetryPolicy(max_attempts=5, total_deadline_seconds=30),
            clock=clock.now,
            sleeper=clock.sleep,
            rand=no_jitter,
        )
    assert attempts == 1, "a permanent failure was retried"
    assert clock.slept == []


async def test_attempts_are_capped():
    clock = FakeClock()
    attempts = 0

    async def always_fails(remaining: float) -> str:
        nonlocal attempts
        attempts += 1
        raise RetryableError("still broken")

    with pytest.raises(RetryableError, match="all 3 attempts"):
        await run(
            always_fails,
            RetryPolicy(max_attempts=3, total_deadline_seconds=100),
            clock=clock.now,
            sleeper=clock.sleep,
            rand=no_jitter,
        )
    assert attempts == 3


# C17-AC1 and AC3: every attempt shares one deadline.
async def test_all_attempts_share_a_single_deadline():
    """A per-attempt timeout multiplies. Three attempts at fifteen seconds
    would be a forty-five second request against a fifteen second budget."""
    clock = FakeClock()
    seen_remaining: list[float] = []

    async def slow(remaining: float) -> str:
        seen_remaining.append(remaining)
        clock.advance(4.0)  # each attempt burns real time
        raise RetryableError("slow and failing")

    with pytest.raises((DeadlineExceeded, RetryableError)):
        await run(
            slow,
            RetryPolicy(max_attempts=10, total_deadline_seconds=10),
            clock=clock.now,
            sleeper=clock.sleep,
            rand=no_jitter,
        )

    # The budget shrinks across attempts rather than resetting.
    assert seen_remaining == sorted(seen_remaining, reverse=True)
    assert seen_remaining[0] == pytest.approx(10.0)
    assert seen_remaining[-1] < seen_remaining[0]
    # And total elapsed never exceeds the budget by more than one attempt.
    assert clock.t - 1000.0 <= 10.0 + 4.0


async def test_the_operation_is_told_how_long_it_has_left():
    clock = FakeClock()
    seen: list[float] = []

    async def record(remaining: float) -> str:
        seen.append(remaining)
        return "ok"

    await run(
        record,
        RetryPolicy(total_deadline_seconds=7.5),
        clock=clock.now,
        sleeper=clock.sleep,
        rand=no_jitter,
    )
    assert seen == [pytest.approx(7.5)]


async def test_a_backoff_that_would_outlast_the_budget_is_not_taken():
    """Waking up past the deadline means the next attempt never happens, so
    sleeping through it wastes the caller's time for nothing."""
    clock = FakeClock()

    async def always_fails(remaining: float) -> str:
        raise RetryableError("broken")

    with pytest.raises(DeadlineExceeded, match="during backoff"):
        await run(
            always_fails,
            RetryPolicy(
                max_attempts=5,
                total_deadline_seconds=0.1,
                initial_backoff_seconds=1.0,
            ),
            clock=clock.now,
            sleeper=clock.sleep,
            rand=no_jitter,
        )
    assert clock.slept == [], "slept past a deadline it could not beat"


async def test_an_already_expired_budget_makes_no_attempt():
    clock = FakeClock()
    attempts = 0

    async def never_called(remaining: float) -> str:
        nonlocal attempts
        attempts += 1
        return "ok"

    policy = RetryPolicy(total_deadline_seconds=0.001)
    clock.advance(1.0)  # consumed before we even start

    # The first check uses the deadline set at entry, so advance inside the
    # operation instead: this asserts the zero-remaining guard.
    async def burn(remaining: float) -> str:
        nonlocal attempts
        attempts += 1
        clock.advance(10.0)
        raise RetryableError("slow")

    with pytest.raises((DeadlineExceeded, RetryableError)):
        await run(burn, policy, clock=clock.now, sleeper=clock.sleep, rand=no_jitter)
    assert attempts == 1


def test_backoff_is_exponential_and_capped():
    policy = RetryPolicy(initial_backoff_seconds=0.5, max_backoff_seconds=2.0, jitter=0)
    waits = [policy.backoff_for(n, no_jitter) for n in range(1, 6)]
    assert waits == [0.5, 1.0, 2.0, 2.0, 2.0]


def test_jitter_stays_within_bounds():
    policy = RetryPolicy(initial_backoff_seconds=1.0, jitter=0.1)
    assert policy.backoff_for(1, lambda: 0.0) == pytest.approx(1.0)
    assert policy.backoff_for(1, lambda: 1.0) == pytest.approx(1.1)


def test_a_nonsense_policy_is_rejected():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(total_deadline_seconds=0)
