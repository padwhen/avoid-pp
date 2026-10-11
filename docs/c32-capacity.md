# C32 — capacity and cost budgets

> **C32-AC1** The report includes p50/p95/p99, throughput, queue wait, peak
> memory, error rate and cost per 1,000 scans.
> **C32-AC2** Rate, concurrency, queue and token limits are selected from
> measured behavior rather than copied defaults.
> **C32-AC3** A numeric latency/cost SLO is agreed and recorded before the
> beta gate; provider work and gateway overhead are reported separately.

```sh
make capacity                           # gateway profile, free, ~20s
make provider-profile CONFIRM=yes       # provider profile, ~USD 0.13
```

Reports: [`c32-capacity.json`](../evals/reports/milestones/c32-capacity.json),
[`c32-provider-profile.json`](../evals/reports/milestones/c32-provider-profile.json).
Both are snapshots in `milestones/`, which is the only part of
`evals/reports/` that is tracked: working runs are ignored, and a report a
document cites has to survive the next run.
Hardware: Apple M2, 8 cores, 8 GiB, macOS 13.5, Go 1.27.2.

---

## The separation AC3 asks for

A load test against a live stack measures the provider, the network and the
machine's mood together, and cannot say which part of a latency number is
yours. So the two halves are measured apart, by construction:

- **Gateway**: the real router in-process against a detector whose latency is
  a parameter. Injected latency is provider work; everything above it is the
  gateway. Costs nothing, so it can be run as often as anyone likes.
- **Provider**: nine real scans across three input sizes. USD 0.13.

The answer is lopsided enough that it settles several other questions.

| | p50 | p99 | throughput |
|---|---|---|---|
| **Gateway overhead**, typical passage | **0.078 ms** | 0.194 ms | 11 726/s |
| **Gateway overhead**, maximum passage | 0.377 ms | 0.611 ms | 2 608/s |
| **Provider**, typical passage | 3 736 ms | — | 1.41/s (4 slots) |

The gateway is **0.002%** of a scan. Parsing, duplicate-key checking,
authentication, rate limiting, admission, an internal HTTP round trip,
response validation and policy together cost less than a tenth of a
millisecond. Nothing in this service is worth optimising for speed, and any
future latency complaint is a provider complaint until proven otherwise.

---

## Provider work, by input size

Three repetitions each, so minimum/median/maximum and no percentiles — three
samples cannot support a p95 and printing one would invite it to be quoted.

| size | chars | input tokens | output | median | USD/scan | USD/1 000 |
|---|---|---|---|---|---|---|
| short | 50 | 1 122 | 125 | 2 811 ms | 0.0087 | **8.73** |
| typical | 150 | 1 176 | 127 | 3 736 ms | 0.0090 | **9.05** |
| effective maximum | 5 324 | 3 995 | 136 | 3 019 ms | 0.0234 | **23.38** |

Two things worth reading twice.

**Latency does not scale with input size.** The largest passage the service
accepts is 35× the typical one and was *faster* than it in this sample
(3 019 ms against 3 736 ms). Latency is dominated by output generation and
fixed overhead, so a timeout sized from input length would be sized from the
wrong variable.

**Cost does scale, and the prompt dominates small requests.** A 50-character
passage is about 25 tokens against roughly 1 100 for the instructions: **98%
of the input cost of a short scan is the prompt**, paid again on every
request. Prompt caching is the obvious lever and is not implemented;
C32 records it rather than adding it, because it changes what a scan *is*
for reproducibility purposes and that belongs with a prompt version.

**The tail is real and unrelated to size.** One short scan took 5 962 ms
against a 2 811 ms median — 2.1× — and an earlier discarded run saw 13 252 ms.
Identical input, same model.

---

## Saturation, and the queue-wait number that did not exist

Queue wait was unmeasured before C32. It is the number that separates "the
provider is slow" from "we are overloaded" — the two look identical in
end-to-end latency and have opposite remedies — so `admission.Controller` now
records it: summed wait and count for requests that queued at all, plus the
maximum, which is the one a mean would hide.

Profiled at the injected measured median of 2 833 ms against the shipped
bounds:

| offered | throughput | errors | peak queued | mean wait | max wait |
|---|---|---|---|---|---|
| 4 | 1.41/s | 0% | 0 | — | — |
| 16 | 4.23/s | 66.7% `overloaded` | 4 | 2 834 ms | 2 835 ms |
| 64 | 11.28/s | 87.5% `overloaded` | 4 | 2 835 ms | 2 835 ms |

Throughput at capacity is 1.411/s against a predicted 1.4119/s. Shedding is
bounded, labelled `overloaded`, and never degrades to an allow.

**Memory does not scale with offered load.** Peak heap was 2.5–3.7 MiB across
a 16× range of offered concurrency, because the number of passages in the
system is bounded by admission rather than by traffic. Allocation per request
tracks passage size — 26 KB typical, 755 KB at the maximum — so a completely
full system holds under 8 MiB.

---

## What the measurements changed — C32-AC2

### MaxQueued: 8 → 4, and the derivation that was wrong first

A request at the back of the queue waits for the queue to clear and then
needs its own call. If that total exceeds the scan budget it is admitted with
too little time, starts a **paid** provider call and is cancelled mid-flight:
money spent on an answer nobody receives.

The first derivation modelled the wait as a division — slots free at
`MaxActive/L` per second, so the wait is `(MaxQueued/MaxActive) × L` — and
chose 6. **The profile contradicted it.** Measured maximum wait was 5 670 ms
at MaxQueued 6 and the identical 5 670 ms at MaxQueued 8: two whole batches of
2 833 ms in both cases.

Under a burst, which is the case a queue exists for, in-flight requests start
together and therefore finish together, so slots are released in groups of
`MaxActive` rather than smoothly:

```
wait = ceil(MaxQueued / MaxActive) × L
```

A step function. 6 and 8 sit on the same step, so lowering the queue from 8 to
6 would have changed nothing and looked like a fix. At the measured p95 of
5 851 ms against a 15 s budget only `ceil = 1` fits, which is **MaxQueued 4**.
Re-profiled, the maximum wait is 2 835 ms — exactly one batch.

### The tail exposure this does not fix

No queue depth is free of it:

| | p50 | p95 | p99 |
|---|---|---|---|
| Q = 4 | completes | completes | **wastes a paid call** |
| Q = 6 | completes | **wastes a paid call** | times out queued |
| Q = 8 | completes | **wastes a paid call** | times out queued |

Four wastes rarely; six and eight waste often. At p99 a queue of 4 admits a
request with 4.8 s left that needs 10.2 s, and a queue deep enough to avoid
that instead admits doomed requests at p95.

The real remedy is **deadline-aware admission** — refusing a slot when the
remaining budget cannot cover a call. That is a behaviour change, so C32
records it as the next step rather than making it silently. A coherence test
asserts the exposure stays confined to the tail.

### Global rate: 2/s → 1/s, burst 8

Admission completes at most 1.41/s, so a limiter admitting 2/s was permitting
traffic the service could not serve, and the excess was shed by admission as
`overloaded` rather than by the limiter as `rate_limited`.

Both fail closed, so nothing was unsafe. What was wrong is the **signal**: a
service shedding as `overloaded` reads as a capacity incident, and
`rate_limited` reads as a caller sending too fast. The second was the true
statement. It also made the rate limiter decorative as a spend bound, since
admission was already the tighter of the two.

The burst is now `MaxActive + MaxQueued = 8` — exactly enough to fill every
slot and every queue position once, and no more.

The per-caller rate is unchanged at 1/5. One caller can consume about 71% of
the ceiling, which is right for a service with one caller and wrong for one
with ten. Noted rather than pre-solved for a tenancy that does not exist.

### Three connection deadlines that were missing

`server.go` set only `ReadHeaderTimeout` and said C32 would size the rest. Go
defaults the others to *no limit*, so a client could send one byte of body per
minute indefinitely.

| | value | derived from |
|---|---|---|
| `ReadTimeout` | 10 s | the 64 KiB body cap — 6.5 KiB/s, which no honest client is under |
| `WriteTimeout` | scan budget + 10 s | must outlast the handler or it truncates work already paid for |
| `IdleTimeout` | 120 s | keep-alives between scans |

`IdleTimeout` is the subtle one: Go falls back to `ReadTimeout` when it is
unset, so adding only `ReadTimeout` would have closed every keep-alive after
ten seconds and forced a fresh handshake per scan — a regression nobody would
connect to the timeout they had just added.

### The derivations are tests, not comments

Every number above is derived from a constant in
[`measured.go`](../gateway/internal/config/measured.go), and
`coherence_test.go` asserts each derivation still holds. Changing `MaxQueued`
without re-deriving against the scan timeout and the measured p95 fails the
build with the arithmetic in the message. Reverting to 8 fails two tests.

---

## The size limits do not agree with each other

Four bounds apply to one passage, in three units:

| | value | unit | where |
|---|---|---|---|
| `contract.MaxTextChars` | 32 768 | characters | public schema |
| `api.MaxRequestBytes` | 65 536 | bytes | gateway body cap |
| `limits.MAX_PASSAGE_BYTES` | 32 768 | bytes | detector |
| `limits.DEFAULT_MAX_SOURCE_TOKENS` | 4 096 | tokens | detector |

**The token budget binds first, at about 5 324 characters — 16% of the
documented ceiling.** The schema advertises six times what the service
accepts.

It is also tighter than its own safety margin requires. The budget assumes a
conservative 1.3 characters per token; measured against the real tokenizer at
that size (3 995 input tokens for 5 324 characters, of which ~1 100 are the
prompt) Finnish runs at **1.84**, so the same 4 096 tokens would hold roughly
7 100 characters.

A smaller incoherence sits underneath. The character ceiling and the byte cap
are exactly a factor of two apart, so a passage of 32 768 two-byte characters
fills the body cap precisely with its text and is carried over it by the JSON
envelope — inside the documented character limit and refused as
`payload_too_large`. Asserted by test rather than fixed; raising the cap would
let a caller reserve a 128 KiB buffer, which is a trade worth making
deliberately.

### What a caller used to be told

The detector enforced its budget correctly. `claude.py` then wrapped
`InputTooLarge` as `DetectorUnavailable`, the service answered **503**, and
the gateway passed on **`detector_unavailable`**.

So a caller sending 6 000 characters — well inside the documented limit — was
told the detector was down. A permanent, caller-fixable condition reported as
a transient outage, and one a well-behaved client retries forever against
something that will never clear.

### What it is told now

The contract already defined both codes:

| condition | status | code |
|---|---|---|
| over the byte ceiling | 413 | `payload_too_large` |
| over the token budget | 422 | **`token_budget_exceeded`** |

`token_budget_exceeded` had existed in `error.schema.json` since C03 with no
emitter anywhere. C41 noted that and made both SDK clients handle it on the
principle that *a code the contract permits is not a code a client may meet
with a crash*. Three weeks later it has an emitter.

`limits.py` now raises `PassageTooLarge` and `TokenBudgetExceeded` separately,
because "send fewer bytes" and "send a shorter passage" are different
instructions and a caller cannot convert between them without knowing which
bound it hit. Both remain catchable as `InputTooLarge`.

**The 32 768 figure in the schema is left as it is.** Raising the token budget
to honour it would make a ceiling-sized scan cost about USD 0.13 — 14× a
typical one — and lowering the schema is a breaking contract change. Neither
is a capacity decision, so C32 makes the error truthful and records the gap.

---

## The agreed SLO — C32-AC3

Targets, with roughly 20% headroom over measurement so ordinary provider
variation does not breach them:

| | target | measured |
|---|---|---|
| end-to-end p95 | **≤ 7 s** | 5.9 s |
| end-to-end p99 | **≤ 12 s** | 10.2 s |
| error rate | **≤ 1%** | 0.46% |
| cost, typical passage | **≤ USD 10 / 1 000 scans** | 9.05 |

Scope and caveats, because an SLO quoted without them is a liability:

- **Unsaturated operation only.** Under saturation the queue adds up to one
  provider call to p95 by design, and shed requests return `overloaded`
  rather than waiting. Those are the capacity numbers above, not these.
- **The 15 s scan timeout is the hard ceiling**, above the p99 target.
- **Typical passages.** At the effective maximum the cost target is USD 23.38
  per 1 000; latency is unchanged.
- **One model, one prompt**, `claude-opus-5` with `translate_fi_en-v1`
  (`5f42eb70…`). Changing either invalidates every number.
- The error rate is measured from 436 scans in which both failures were the
  same reproducible provider refusal, not from a distribution of failures.

### Spend ceiling

At 1.41 scans/second and USD 0.0090 each, the shipped limits bound sustained
spend at about **USD 1 145/day**. That is what the rate limits exist to cap,
and it is asserted by a test so the defaults cannot drift an order of
magnitude without someone looking at the figure.

---

## What C32 does not establish

1. **No real-traffic load profile.** The synthetic profile uses a stub
   detector; a burst from a real client over a real network is unmeasured.
2. **One machine.** Every gateway number is from an M2 laptop. Throughput is
   bounded by provider latency rather than by CPU, so the figures should
   travel — but that is an argument, not a measurement.
3. **Three samples per size** on the provider side. Enough for the shape,
   not for an interval.
4. **No sustained soak.** Nothing here runs long enough to show a leak, and
   peak heap over 20 seconds is not evidence of its absence.
5. **Prompt caching is unmeasured**, and it is the largest available cost
   reduction given that 98% of a short scan's input is the prompt.
6. **Deadline-aware admission is not implemented**, so the p99 tail can still
   start a paid call it cannot finish.
