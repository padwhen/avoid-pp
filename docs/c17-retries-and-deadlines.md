# C17 — bound retries and overall inference time

Scope: narrowly bounded provider retries owned by the detector, with every
attempt sharing one total deadline.

## Acceptance criteria

1. Transient failures retry only within the configured attempt and time
   budget; schema and authentication errors do not retry.
2. Go, Python and provider SDK automatic retries cannot multiply into an
   undocumented retry storm.
3. Expired requests terminate local work promptly and produce an explicit
   error; document any provider-side cancellation and billing limits.

## AC2 — retries compose, and that is the danger

A gateway that retries twice, calling a detector that retries three times,
over an SDK that retries twice of its own accord, is **nine** provider
requests for one scan. Nobody wrote "nine" anywhere; each layer looks
reasonable alone.

So retrying happens in exactly one place, and the layers around it are set to
one attempt deliberately:

| Layer | Attempts | Where |
| --- | --- | --- |
| Gateway | 1 — reports the failure, does not retry | `internal/detector/client.go` |
| Detector | **3** — the only layer that tries again | `translation_guard/retry.py` |
| Provider SDK | 1 — constructed with `max_retries=0` | `detectors/claude.py` |

Worst case is three provider requests per scan, and that number is written
down.

## AC1 — one shared deadline, not one per attempt

A per-attempt timeout multiplies. Three attempts at fifteen seconds is a
forty-five second request against a budget the caller believed was fifteen.

Here the deadline is absolute. It is computed once on entry, checked before
each attempt, and the remaining time is **passed into** the attempt so the
provider call is bounded by what is actually left rather than by a fresh
timeout. A test asserts the remaining budget strictly decreases across
attempts rather than resetting.

A backoff that would outlast the budget is not taken at all: waking up past
the deadline means the next attempt never happens, so sleeping through it
spends the caller's time for nothing.

### What is retried, and what is not

| Failure | Retried | Why |
| --- | --- | --- |
| Timeout | yes | the same request may succeed shortly |
| Connection error | yes | transient network |
| 429 rate limit | yes | transient by definition |
| 5xx | yes | provider-side, usually transient |
| 401 authentication | **no** | retrying cannot change the answer |
| 4xx other | **no** | the request itself is wrong |
| Schema violation in the reply | **no** | an identical request recurs identically |

Retrying a permanent failure just spends the budget and returns the same
answer more slowly.

## AC3 — abandoning a request does not stop the provider billing for it

This is worth stating plainly because it is easy to assume otherwise.

When the deadline expires, the detector stops waiting and returns an explicit
error. It does **not** follow that the provider stopped working. Closing an
HTTP connection does not reliably cancel server-side generation, and a request
that was already in flight may be completed and billed in full.

The practical consequences:

- A tight deadline against a slow model **does not** cap spend. It caps
  latency. Cost is bounded by the number of requests made, which is why the
  attempt cap matters more than the deadline for budgeting.
- Retrying a timeout can mean paying for two completions and using neither.
  That is the honest price of the retry policy, and the reason `max_attempts`
  is three rather than something larger.
- The measured 4.2 to 9.2 second live latency from C13 sits close enough to a
  15 second budget that timeouts are a realistic operating condition, not a
  hypothetical.

C32 is where these numbers get set from measurement rather than from the
plan's development defaults.

## Verification

```sh
make check-python     # 138 tests
```

The retry suite runs on a **fake clock**: nothing sleeps, so the timing
assertions are exact rather than flaky and the suite stays fast. Backoff is
asserted to be exponential and capped, and jitter is asserted to stay within
its bounds.

The adapter tests construct a single-attempt policy by default. They assert
request shape and response mapping, and leaving the real policy in place would
have made every failure case sleep through a backoff — the suite jumped from
0.2 to 3.4 seconds before that was fixed.
