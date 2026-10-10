# C22 · Capping inference concurrency and queued work

A rate limit and admission control answer different questions, and a service
calling a slow dependency needs both.

A rate limit bounds how fast requests **arrive**. It says nothing about how
many are still running — and that is the number that matters here. At a
measured 4.4 seconds per provider call, a perfectly compliant two requests per
second leaves roughly nine in flight at steady state. If the provider slows to
thirty seconds, sixty. Each one holds a connection, a goroutine and a buffer,
and nothing in the rate limiter notices, because every one of those callers
obeyed the limit.

So this bounds concurrency: how many calls may run, and how many may wait.

## Why a small bounded queue

Three options, and the middle one is right for a non-obvious reason.

**No queue.** A momentarily full set of slots rejects a request that would
have been served a few milliseconds later. That makes the service fragile
under ordinary jitter — a burst that the system could absorb produces errors
instead.

**An unbounded queue.** Every arrival is accepted, and the queue becomes the
place where latency and memory go to die. Callers wait behind work that will
outlive their own deadlines, the service reports healthy, and it serves
nobody. This is the failure mode that looks like "it got slow" and is actually
"it accepted more than it could ever finish".

**A small bounded queue** absorbs the jitter and refuses the overload. Eight
waiting requests at 4.4 seconds each is already a worst-case wait longer than
most callers' patience; anything larger would be latency pretending to be
capacity.

The refusal is the point. A 503 now is strictly better information than a
response that may arrive in two minutes.

## Sized from latency, not from cores

The usual "one worker per core" reasoning does not apply, because the work is
almost entirely waiting on a network call — a slot costs a goroutine and a
connection, not a core. What bounds it instead is what the dependency can be
trusted to do and what the budget allows.

Four slots at 4.4 seconds is a little under one completed scan per second,
which sits just above the global rate limit of two per second. That ordering
is deliberate: the rate limiter shapes traffic in normal operation, and
admission catches the abnormal case, which is a provider that has slowed down.

## Where the slot is held

Around the provider call only, not the whole handler.

A request that was going to be refused for a malformed body never occupies a
slot that a well-formed one could use. The scarce resource is the provider
call, not the parser. And the slot is released as soon as that call returns on
every path including failure — policy evaluation and serialisation are
microseconds and do not need capacity.

The context used to acquire is the one carrying the scan deadline, so a
request that runs out of budget while queued gives up its place rather than
waiting for a slot it could no longer use.

## Releasing on cancellation

A slot leaked on cancellation is worse than no limit at all. Capacity drains
monotonically and the service dies slowly, at a rate set by how often clients
disconnect — which looks like a memory leak and is not one.

Both implementations release in a `defer`/`finally`, and both have a test that
runs two hundred cancelled rounds and then asserts full capacity is still
available. That test is the one that would catch a regression here, because a
single leaked slot is invisible until the last one goes.

### Double release

`Acquire` returns a release function wrapped in `sync.Once`. A release called
twice would return a token the caller never held, raising the effective limit
permanently — a silent, cumulative failure. The cost of preventing it is one
allocation against an operation that takes seconds.

## Overload is not cancellation

`ErrQueueFull` is deliberately distinct from a context error:

| Situation | Status | Code |
| --- | --- | --- |
| Slots and queue both full | 503 | `overloaded` |
| Deadline passed while queued | 504 | `deadline_exceeded` |
| Caller hung up while queued | 503 | `detector_unavailable` |

Conflating the first two would make a server-side capacity problem look like a
client problem in every dashboard that counts them. The 503 carries retry
guidance in both the `Retry-After` header and `retry_after_seconds`, the same
way a 429 does.

Unlike a rate limit there is no bucket to compute an exact wait from — how
long until a slot frees depends on the provider, which is the thing that is
slow. One second is short enough to recover from a brief spike and long enough
not to amplify a sustained one into a retry storm.

## The detector bounds itself too

Defence in depth, and its reason to exist is that the gateway's bound is an
assumption about a *different process*:

- the detector is reachable from the internal network, and anything there
  could call it directly — a debug script, a second gateway, a future service
  nobody remembered to tell about the limit;
- a gateway deployed with two replicas admits twice its configured
  concurrency, and neither replica knows the other exists;
- a misconfiguration in the gateway is a configuration mistake, not a reason
  for the detector to make unbounded provider calls.

Its shape mirrors the Go side on purpose — fixed slots, small bounded queue —
so the two are reasoned about the same way rather than being two different
mechanisms that happen to be adjacent.

Not an `asyncio.Semaphore` alone: a semaphore's `acquire` waits without limit,
so an overloaded service would grow an unbounded queue of waiters instead of
refusing. The waiting count is tracked explicitly so there is a number to
compare against a bound.

The detector's limit is set **above** the gateway's, so in normal operation
the gateway sheds first and this never fires. A detector rejecting while the
gateway thinks it has capacity is a signal that something is talking to it
directly, which is worth knowing rather than absorbing.

## Verification

The acceptance criteria ask for a blocking fake detector under concurrent
load, which is what the fixture does — a fake that returned instantly could
not produce contention, so the concurrency would be unobservable.

- **C22-AC1.** Sixty concurrent requests against three slots and a queue of
  five. The assertion runs while the system is saturated, and the concurrency
  high-water mark is counted **by the fake detector itself**, independently of
  the controller's own counters — so the test does not trust the thing it is
  testing. Peaks rather than samples, because a sampled reading can miss an
  overshoot.
- **C22-AC2.** Cancellation and deadline both release the queue place, checked
  by polling the queue depth back to zero rather than sleeping. A shed request
  returns in milliseconds rather than waiting for the blocked call.
- **C22-AC3.** A maximal passage occupies exactly one slot, not zero and not a
  separate pool, and while it holds that slot a small request is shed like any
  other. An over-length passage is refused before admission, so it consumes no
  slot — asserted by comparing the admitted counter across the request.
- Fifty shed requests, then an assertion that the detector saw exactly the one
  admitted call. A shed request must cost nothing downstream.
- Health endpoints answer while saturated, which is exactly when someone is
  looking at them.

A note from writing these: the first version of the AC3 test built a passage
of 32,768 `ä` characters, which is 64 KiB of UTF-8 and exceeds the body limit
before admission is ever reached. The test failed, correctly, on the
interaction C20 documented — two limits in different units, and the smaller
binds.

## Two things the live check could not show

**The fake detector cannot contend its own slot.** Eighty concurrent requests
against a detector configured with one slot and no queue all returned 200,
including with 62 KB passages. That is correct: the fake is pure async and
returns without awaiting anything slow, and uvicorn runs one event loop — so
each `async with admission.slot()` completes before the next request is even
parsed, and there is never more than one request inside the slot.

The detector's bound only binds when the handler actually awaits something
slow, which is the real provider call. That is why the Python test substitutes
a detector that blocks until released, rather than relying on a load
generator. A load fixture against an instantaneous fake would pass whatever
the bound was set to, including a broken one.

**The detector's INFO logs do not reach output.** While verifying the startup
line, the `admission configured` message never appeared — and neither did
C08's `detector ready`, which has presumably been missing since it was
written.

The cause is that `logging.getLogger("translation_guard")` has no handler and
the root logger has none either under uvicorn, so Python falls back to its
`lastResort` handler, which emits at WARNING and above:

```
level that lastResort emits at: 30 = WARNING
a WARNING line (the AtCapacity refusal)      <- reaches stderr
an INFO line (startup, 'detector ready')     <- silently dropped
```

So the operationally important message here, the capacity refusal, is visible;
every informational one is not. This is a pre-existing gap rather than
something this commit introduced, and it is squarely C23's subject — logging
configuration is the first thing that commit has to establish, or the fields
it carefully designs will not be emitted at all.
