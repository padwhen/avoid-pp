# C21 · Bounded per-caller rate limits

Three buckets, all allocated at startup: one per configured caller, one shared
by all authenticated traffic, one shared by all unauthenticated traffic.

Rates and the per-process caveat are in
[configuration.md](configuration.md). This document covers the design.

## Why the state cannot grow

The usual shape of a rate limiter is a map from some request attribute to a
token bucket, filled in on first sight. That map is the vulnerability. If the
key is anything the caller controls — an IP, a header, a body field — then
sending a million distinct values allocates a million buckets, and a rate
limiter becomes a memory-exhaustion primitive. The thing meant to bound load
becomes the thing that fails under it.

So nothing is created on demand. The caller buckets come from the configured
caller list, which only a restart can change. A name with no bucket is refused
outright rather than given one, which keeps the property true even if some
future code path reaches the limiter with a name from somewhere else.

The map is written once and only read afterwards, so concurrent lookups need
no lock, and `rate.Limiter` is itself safe for concurrent use.

A test sends ten thousand distinct unknown caller names and ten thousand
unauthenticated requests, then asserts the bucket count is unchanged. Another
sends five hundred requests from distinct `RemoteAddr` values, with distinct
`X-Forwarded-For` and `X-Real-IP` headers, in case anything were ever tempted
to read them.

## Eviction

There is none, because there is nothing to evict.

Eviction exists to bound state that would otherwise grow without limit. State
that cannot grow does not need it, and an LRU here would be machinery guarding
against a condition the design makes unreachable — more code, more locking,
and a cache-size parameter nobody could choose well.

That reasoning depends entirely on callers coming from configuration. If
callers ever become dynamic — per end user, per tenant loaded from a database
— this stops being true and bounded eviction becomes necessary. The test
asserting the bucket count never changes is what will fail at that point,
which is the intended way to find out.

## A refused request consumes nothing

`AllowCaller` reserves from the caller's bucket, then from the global bucket,
and cancels both if either refuses.

Without that rollback, a caller refused by the global limit would still pay a
token from its own bucket. One busy caller would then throttle another twice
over: once by the shared limit, and again by a bucket drained for requests
that were never served. The second effect would outlast the first, and would
be invisible in any per-request log.

A test drains the shared bucket from one caller, takes twenty refusals for a
second caller, and then checks the second caller still has its full burst.

## Why the global scope is reachable at all

Startup refuses a global limit below the per-caller limit, which raises the
question of how the global bucket can ever be the binding one.

The answer is that it binds when callers compete, not when it is configured
tighter. With equal limits, one caller spending the shared budget leaves
another refused while its own bucket is still full. That is the realistic
shape of this refusal, and the test uses a configuration the service would
actually accept rather than one the validation rejects.

## Where each check runs

```
Authenticate ──► RateLimit ──► Scan
   │                │             │
   │                │             └─ parse, authorise, call the detector
   │                └─ per-caller and global buckets
   └─ unauthenticated bucket, on a failed credential
```

The unauthenticated limit lives inside `Authenticate` because that is the only
place that knows a credential failed. The caller limit lives in its own
middleware because the caller name has to come from a verified credential.
They are split because the information each needs arrives at a different
point, not by preference.

Both run before the body is parsed, so a refused request costs no parsing, no
authorisation check and no detector call. The tests assert a detector call
count of zero across twenty rate-limited requests, and that a 429 wins over
bodies that would otherwise be a 400 or 422.

It also means a caller cannot probe its task grants for free: authorisation
happens in the handler, behind the limiter.

## The response

| | |
| --- | --- |
| Status | 429 |
| Code | `rate_limited` |
| `Retry-After` header | whole seconds |
| `retry_after_seconds` in the body | the same number |

The retry hint is computed from the bucket rather than being a fixed guess. A
fixed guess is either too short, and the client retries into another
rejection, or too long, and the client waits for capacity that already exists.

It rounds up and floors at one second. Rounding down would tell a client to
retry before capacity exists; a `Retry-After` of zero invites an immediate
retry, which is the same mistake written differently. A test asserts the
reported value is never less than the real wait.

The guidance appears twice because a header is what proxies and well-behaved
clients honour automatically, while the body field is what an application
reads when its client library does not surface response headers on an error
path. A test asserts the two always agree.

**The response never says which bucket was hit.** Telling a caller it was the
global limit rather than its own discloses that other callers are busy, which
is information about traffic that is not theirs. The scope goes to the log,
where it is what makes a complaint about an unexplained 429 diagnosable. A
test produces a caller-scoped and a global-scoped refusal and asserts the two
response bodies are identical.

## Health endpoints are not limited

A readiness probe that began failing because it polled too often would take
the instance out of service for no reason — the limiter would have caused the
outage it exists to prevent. A test polls both endpoints fifty times against
a limiter configured at one request per second.

## Fail-closed

A nil limiter means the scan route is not registered, so it 404s rather than
serving unlimited traffic. The `RateLimit` middleware refuses a request whose
context carries no caller, so a chain assembled in the wrong order fails
loudly instead of becoming an unlimited one.

A caller holding two keys during a rotation shares one bucket. Two buckets
would double its effective rate for as long as the rotation lasted.

## The first external dependency

`golang.org/x/time/rate` is the gateway's first non-stdlib import. It is
maintained by the Go team, is a few hundred lines, and its `Reserve`/`Cancel`
API is what makes the rollback above expressible — a hand-rolled token bucket
would have to reimplement that, and the interesting part of this commit is the
composition, not the arithmetic.

Every method takes an explicit time, which is why the tests drive a frozen
clock instead of sleeping. A limiter test that sleeps is slow when it passes
and flaky when it fails.
