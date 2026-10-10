# Gateway configuration

Every variable below is read once at startup. Invalid configuration stops the
process before a port is bound, and all problems are reported together so a
misconfigured service does not have to be restarted once per mistake.

No error message in this path quotes a configured value. Configuration carries
credentials, and a message like `invalid value "sk-ant-..."` is a helpful error
that has just written a secret into the logs. Tests enforce that rather than
trusting it.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `AVOIDPP_ADDR` | no | `:8080` | Listen address. Must include a port. |
| `AVOIDPP_DETECTOR_URL` | yes | — | Base URL of the private detector. |
| `AVOIDPP_API_KEYS` | yes | — | Caller credentials. Format below. |
| `AVOIDPP_RATE_CALLER` | no | `1/5` | Per-caller rate/burst. |
| `AVOIDPP_RATE_GLOBAL` | no | `2/10` | Shared rate/burst across all callers. |
| `AVOIDPP_RATE_UNAUTHENTICATED` | no | `2/10` | Rate/burst for all failed credentials together. |
| `AVOIDPP_MAX_ACTIVE` | no | `4` | Concurrent inference calls. |
| `AVOIDPP_MAX_QUEUED` | no | `8` | How many may wait for a slot. |
| `AVOIDPP_POLICY_MODE` | no | `monitoring` | `monitoring` or `enforcement`. |
| `AVOIDPP_SCAN_TIMEOUT` | no | `15s` | End-to-end scan budget, max 60s. |
| `AVOIDPP_SHUTDOWN_TIMEOUT` | no | `10s` | Drain budget on shutdown. |
| `AVOIDPP_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error`. |

## AVOIDPP_API_KEYS

```
name:task[+task...]:key[,name:task[+task...]:key]
```

- Entries are separated by commas, fields within an entry by colons, and
  multiple tasks by plus signs.
- Surrounding whitespace is trimmed, so the value can be wrapped across lines
  in a `.env` file.
- Keys may not contain a comma or a colon. They are generated, not typed, so
  this costs nothing, and an entry with a colon in the key is rejected rather
  than silently truncated.
- Keys must be at least 32 characters. The check exists because the failure it
  prevents is a human one: a key like `test` added during development and
  never rotated.

One variable rather than one per caller, because configuration is read through
an injected accessor that cannot enumerate the environment. A per-caller
scheme would need a second variable listing the caller names, which is the
same packing problem with an extra step.

### Generating a development key

```sh
make dev-key              # writes AVOIDPP_API_KEYS into the gitignored .env
make dev-key CALLER=lukea # names the caller
```

There is deliberately no default key anywhere in this repository. A committed
development credential is a public one, however it is labelled, so Compose
fails to start when the variable is unset rather than substituting a value.

### Replacing a key

A caller name may appear more than once with a different key each time, and
that overlap is what makes a replacement possible without a window where the
caller's requests fail:

1. Add a second entry for the same caller with the new key.
2. Restart the gateway. Both keys now authenticate as that caller.
3. Move the caller onto the new key.
4. Remove the first entry and restart. The old key stops working immediately.

`configured_keys` in the startup log line reports how many keys are live
across all callers, which is the number to check after step 4 to confirm the
old one is gone.

Repeated entries for one name must list the same tasks. Otherwise which tasks
a caller could use would depend on which of its own keys it happened to
present, and nothing in the configuration would predict that.

### Revoking a key

Remove its entry and restart. There is no revocation list and no expiry: the
configured set is the whole truth, so a key that is absent from it cannot
authenticate, and there is no second place to check.

## Rate limits

Each value is a `rate/burst` pair: `1/5` admits one request per second
sustained, with up to five arriving at once. Two numbers in one variable
because the pair is meaningless split up — a rate without its burst does not
describe a limit, and nothing good happens when half a pair is overridden.

The defaults come from what a scan costs, not from web-service habit. A live
Opus scan measured 4.4 seconds and about 1,100 input plus 170 output tokens,
roughly a cent at the rates recorded in `evals/live_eval.py`. The global
default of two per second therefore caps a runaway caller near a dollar a
minute. "A few hundred per second" would put that figure in the thousands.
These are a spend bound first and a fairness mechanism second.

Startup refuses a global limit below the per-caller limit, in either the rate
or the burst. Such a configuration reads like a working one and behaves like a
much tighter one, because no caller could reach its own stated limit.

### These limits are per process

Each gateway instance keeps its own buckets. Two replicas admit twice the
configured rate; three admit three times. There is no shared counter and no
coordination.

A deployment that needs a cluster-wide limit must either run a single instance
or divide the configured rate by the replica count. Which of those is right is
a deployment decision, not something the gateway can discover about itself.

### Unauthenticated traffic

All failed credentials share one bucket, keyed by nothing at all. Keying by
source address would be fairer, and would also hand an attacker an unbounded
map: a million distinct sources would allocate a million buckets, turning the
rate limiter into a memory-exhaustion primitive.

The cost of one shared bucket is that a flood from a single source can exhaust
the unauthenticated budget for every other unrecognised caller. That is
acceptable, because legitimate traffic is authenticated and unaffected, and
the visible consequence is that unrecognised callers receive 429 instead of
401 — which discloses less, not more.

## Admission control

A rate limit bounds how fast requests *arrive*. It says nothing about how many
are still running, and that is the number that matters against a dependency
measured in seconds: at a measured 4.4 seconds per call, a perfectly compliant
two requests per second leaves roughly nine in flight at steady state — and if
the provider slows to thirty seconds, sixty. Each one holds a connection, a
goroutine and a buffer, and nothing in the rate limiter notices.

`AVOIDPP_MAX_ACTIVE` bounds concurrency; `AVOIDPP_MAX_QUEUED` bounds how many
may wait for a slot. Both are fixed at startup.

The queue is deliberately small. With no queue at all, a momentarily full set
of slots rejects a request that would have been served milliseconds later,
which makes the service fragile under ordinary jitter. With an unbounded queue,
every arrival is accepted and the queue becomes where latency and memory go to
die — callers wait behind work that will outlive their own deadlines while the
service reports healthy and serves nobody. A small bounded queue absorbs the
jitter and refuses the overload.

Excess work receives 503 `overloaded` with retry guidance, immediately. A 503
now is better information than a response that may arrive in two minutes.

The default of four slots is a little under one completed scan per second,
which sits just above the global rate limit — so the rate limiter shapes
traffic in normal operation and admission catches the abnormal case, a provider
that has slowed down. Note these are sized from measured latency, not from CPU
count: the work is almost entirely waiting on a network call, so a slot costs a
goroutine and a connection rather than a core.

### The detector bounds itself too

| Variable | Default | Meaning |
| --- | --- | --- |
| `AVOIDPP_DETECTOR_MAX_ACTIVE` | `8` | Concurrent assessments. |
| `AVOIDPP_DETECTOR_MAX_WAITING` | `16` | How many may wait. |

This is defence in depth, not the primary control, and its reason to exist is
that the gateway's bound is an assumption about a *different process*. The
detector is reachable from the internal network, so a debug script or a future
service could call it directly; and a gateway deployed with two replicas admits
twice its configured concurrency without either replica knowing.

The detector's bound is set **above** the gateway's on purpose. In normal
operation the gateway sheds first and this never fires, which means a rejection
here is a signal that something is talking to the detector directly — worth
knowing rather than absorbing silently.

## What is not configurable

A request cannot influence any of the above. There is no field in the scan
request for a policy mode, a caller name, a tenant, a role, a task grant, or a
trust level; unknown fields are rejected by the decoder, so an attempt to add
one fails with a 400 rather than being quietly ignored.
