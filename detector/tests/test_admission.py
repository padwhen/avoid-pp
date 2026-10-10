"""C22: the detector's own concurrency bound.

This is defence in depth behind the gateway's limit, and it is tested
separately because its reason to exist is that the gateway's bound is an
assumption about a different process.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from translation_guard.admission import Admission, AtCapacity
from translation_guard.api import create_app
from translation_guard.config import Settings

ASSESSMENT_PATH = "/internal/v1/assessments"


def wait_for(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    """Poll a condition rather than sleeping a guessed interval."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.005)
    raise AssertionError("condition not met within the timeout")


def test_rejects_unusable_configuration():
    with pytest.raises(ValueError):
        Admission(max_active=0, max_waiting=1)
    with pytest.raises(ValueError):
        Admission(max_active=-1, max_waiting=1)
    with pytest.raises(ValueError):
        Admission(max_active=1, max_waiting=-1)
    # One slot and no queue is tight but legal.
    Admission(max_active=1, max_waiting=0)


# C22-AC1: concurrency never exceeds the configured maximum.
@pytest.mark.asyncio
async def test_active_never_exceeds_the_limit():
    admission = Admission(max_active=3, max_waiting=20)
    release = asyncio.Event()
    peak = 0
    active = 0
    lock = asyncio.Lock()

    async def worker() -> None:
        nonlocal peak, active
        async with admission.slot():
            async with lock:
                active += 1
                peak = max(peak, active)
            await release.wait()
            async with lock:
                active -= 1

    tasks = [asyncio.create_task(worker()) for _ in range(20)]
    # Let the admitted ones reach the body and the rest queue.
    while admission.stats().active < 3:
        await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert admission.stats().active == 3
    release.set()
    await asyncio.gather(*tasks)

    # Counted independently of the admission object's own bookkeeping.
    assert peak == 3, f"observed {peak} concurrent holders, limit is 3"
    assert admission.stats().peak_active == 3
    assert admission.stats().active == 0


# C22-AC1: the waiting queue never exceeds its bound, and the excess is
# refused rather than queued.
@pytest.mark.asyncio
async def test_waiting_never_exceeds_the_limit():
    admission = Admission(max_active=1, max_waiting=2)
    release = asyncio.Event()

    async def worker() -> None:
        async with admission.slot():
            await release.wait()

    holder = asyncio.create_task(worker())
    while admission.stats().active < 1:
        await asyncio.sleep(0)

    waiters = [asyncio.create_task(worker()) for _ in range(2)]
    while admission.stats().waiting < 2:
        await asyncio.sleep(0)

    assert admission.stats().waiting == 2

    # The queue is full, so this one is refused immediately.
    with pytest.raises(AtCapacity):
        async with admission.slot():
            pass

    assert admission.stats().waiting == 2, "a refused request took a queue place"

    release.set()
    await asyncio.gather(holder, *waiters)
    assert admission.stats().peak_waiting == 2
    assert admission.stats().rejected == 1


@pytest.mark.asyncio
async def test_zero_queue_refuses_rather_than_waiting():
    admission = Admission(max_active=1, max_waiting=0)
    release = asyncio.Event()

    async def worker() -> None:
        async with admission.slot():
            await release.wait()

    holder = asyncio.create_task(worker())
    while admission.stats().active < 1:
        await asyncio.sleep(0)

    with pytest.raises(AtCapacity):
        async with admission.slot():
            pass

    release.set()
    await holder


# C22-AC2: a cancelled request gives its slot back. A slot leaked on
# cancellation is worse than no bound: capacity drains monotonically at a rate
# set by how often callers disconnect.
@pytest.mark.asyncio
async def test_cancellation_releases_the_slot():
    admission = Admission(max_active=1, max_waiting=4)
    entered = asyncio.Event()

    async def worker() -> None:
        async with admission.slot():
            entered.set()
            await asyncio.sleep(3600)

    task = asyncio.create_task(worker())
    await entered.wait()
    assert admission.stats().active == 1

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert admission.stats().active == 0, "a cancelled request kept its slot"

    # Capacity is usable again.
    async with admission.slot():
        assert admission.stats().active == 1


@pytest.mark.asyncio
async def test_cancellation_while_waiting_releases_the_queue_place():
    admission = Admission(max_active=1, max_waiting=1)
    release = asyncio.Event()

    async def holder_body() -> None:
        async with admission.slot():
            await release.wait()

    holder = asyncio.create_task(holder_body())
    while admission.stats().active < 1:
        await asyncio.sleep(0)

    async def waiter_body() -> None:
        async with admission.slot():
            pass

    waiter = asyncio.create_task(waiter_body())
    while admission.stats().waiting < 1:
        await asyncio.sleep(0)

    # The queue is full while that one waits.
    with pytest.raises(AtCapacity):
        async with admission.slot():
            pass

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    assert admission.stats().waiting == 0, "an abandoned waiter held its place"

    release.set()
    await holder


# Capacity must not drain over repeated cancellation, which is the failure
# that looks like a memory leak and is not one.
@pytest.mark.asyncio
async def test_capacity_does_not_drain_under_repeated_cancellation():
    admission = Admission(max_active=2, max_waiting=4)

    for round_number in range(200):
        entered = asyncio.Event()

        # Bound explicitly rather than captured: a closure over a loop
        # variable is correct here only because each round is awaited before
        # the next, and that is too subtle to leave implicit.
        async def worker(signal: asyncio.Event = entered) -> None:
            async with admission.slot():
                signal.set()
                await asyncio.sleep(3600)

        task = asyncio.create_task(worker())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert admission.stats().active == 0, (
            f"capacity drained by round {round_number}"
        )

    # Both slots still available.
    async with admission.slot():
        async with admission.slot():
            assert admission.stats().active == 2


@pytest.mark.asyncio
async def test_an_exception_in_the_body_still_releases_the_slot():
    admission = Admission(max_active=1, max_waiting=0)

    with pytest.raises(RuntimeError):
        async with admission.slot():
            raise RuntimeError("the provider call failed")

    assert admission.stats().active == 0
    # Usable again, so a failing provider does not drain capacity.
    async with admission.slot():
        assert admission.stats().active == 1


@pytest.mark.asyncio
async def test_stats_and_describe_report_the_configuration():
    admission = Admission(max_active=5, max_waiting=9)
    stats = admission.stats()
    assert stats.max_active == 5
    assert stats.max_waiting == 9
    assert stats.admitted == 0
    assert "5" in admission.describe()
    assert "9" in admission.describe()


# ---------------------------------------------------------------------------
# The endpoint, not just the primitive.
# ---------------------------------------------------------------------------


def test_the_endpoint_sheds_when_at_capacity(valid_request):
    """C22-AC1 and AC2 at the detector's own boundary.

    The gateway bounds concurrency too, so this path should never fire in
    normal operation. It is tested anyway because its whole reason to exist is
    that the gateway's bound is an assumption about a different process: a
    second gateway replica, a debug script on the internal network, or a
    future service nobody remembered to tell about the limit.
    """
    # One slot, no queue, and a detector that blocks until told otherwise.
    app = create_app(Settings(max_active=1, max_waiting=0))
    gate = threading.Event()

    with TestClient(app) as client:
        runtime = app.state.runtime
        original = runtime.detector.assess

        async def blocking_assess(content, deadline_ms=None):
            # A threading.Event, not an asyncio one: TestClient drives the app
            # on its own loop in another thread, and the release comes from
            # this one.
            await asyncio.get_running_loop().run_in_executor(None, gate.wait)
            return await original(content, deadline_ms)

        runtime.detector.assess = blocking_assess  # type: ignore[method-assign]

        held: list[int] = []

        def hold() -> None:
            response = client.post(ASSESSMENT_PATH, json=valid_request)
            held.append(response.status_code)

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        wait_for(lambda: runtime.admission.stats().active >= 1)

        # The slot is taken, so the endpoint must shed rather than queue.
        shed = client.post(ASSESSMENT_PATH, json=valid_request)
        assert shed.status_code == 503, shed.text

        body = shed.json()
        assert body["error"]["code"] == "overloaded"
        # Retry guidance in the header and the body, as the gateway does it.
        assert shed.headers.get("retry-after") == "1"
        assert body["error"]["retry_after_seconds"] == 1
        # An error envelope can never carry an assessment.
        assert "assessment" not in body
        # And the refusal must not echo the passage.
        assert valid_request["content"]["text"] not in shed.text

        gate.set()
        holder.join(timeout=5)
        assert held == [200], held

    stats = runtime.admission.stats()
    assert stats.peak_active == 1, f"peak_active = {stats.peak_active}, limit was 1"
    assert stats.rejected == 1
