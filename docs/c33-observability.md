# C33 — tracing the gateway and inference safely

> **C33-AC1** A request can be traced across Go and Python using a
> request/trace identifier.
> **C33-AC2** Dashboards or documented queries distinguish overload, provider
> error, uncertainty and actual policy blocks.
> **C33-AC3** Metrics/traces contain no passages or secrets, and request IDs
> are not metric labels.

```sh
curl -s -H "Authorization: Bearer $KEY" localhost:8099/metrics
```

---

## There is no OpenTelemetry SDK here, and that is a decision

The criterion says "add OpenTelemetry spans and low-cardinality metrics". What
it asks those to *achieve* is the three things above. This commit implements
the **W3C Trace Context** specification — the propagation format OpenTelemetry
itself uses — and a metrics registry whose label sets are fixed at compile
time, without the SDK.

Two reasons, and the second is the one that decided it.

**Proportion.** An SDK plus exporters in two languages is a large dependency
surface for a service with no collector to export to. Nothing in it would be
exercised, and this repository has spent four commits arguing that unexercised
code is worse than absent code.

**Auto-instrumentation is a privacy hazard for this service specifically.**
Adopting the SDK is usually worth it because the instrumentation libraries
capture spans without being asked. An HTTP server instrumentor records request
attributes by default — which here means a Finnish passage chosen by an
attacker. C23 built an allowlisting log handler precisely so that a field has
to be *named* before it can be emitted. Telemetry that captures by default
undoes that, and the remedy would be configuring the instrumentation to
suppress things, which is a denylist. So instrumentation stays manual and the
allowlist stays the gate.

What is therefore **not** here: span export, span events, baggage, and any
sampling decision beyond honouring an upstream one. The wire format is
interoperable, so adding an exporter later is additive rather than a rewrite.

---

## C33-AC1: one request, two services

The gateway accepts an inbound `traceparent`, or starts a trace if there is
none, and sends one to the detector with **a fresh span id** — the two hops
are different spans, and sharing an id would collapse them in anything reading
them.

```
caller          00-4bf92f35…4736-00f067aa0ba902b7-01
  gateway log   trace_id=4bf92f35…4736 span_id=00f067aa0ba902b7
  → detector    00-4bf92f35…4736-b7ad6b7169203331-01
    detector log  trace_id=4bf92f35…4736 span_id=b7ad6b7169203331
```

`request_id` is unchanged and still does its own job: the caller's handle on
one call to this gateway. A trace id spans the caller, the gateway and the
detector. C33 added the second without replacing the first.

### The parser refuses more than it accepts

The header is attacker-controlled on the public endpoint, and whatever
survives parsing is written into every log line on both sides and forwarded
downstream. So a malformed header starts a fresh trace rather than being
salvaged — propagating attacker-chosen bytes on the strength of a guess is
the failure here.

Rejected: any version but `00`, uppercase hex, the specification's reserved
all-zero trace and span ids, wrong lengths, wrong separators, trailing
content, and embedded whitespace or newlines.

**One of those was a real bug.** The Python regex first used `^…$`, and in
Python `$` also matches immediately before a trailing newline — so
`"00-…-01\n"` validated, and a trace id containing a newline would split one
log line into two, the second chosen by an attacker. It uses `\A…\Z` now. The
test found it; review had not. The Go implementation checks the length first
and was never exposed.

---

## C33-AC2: four conditions that look alike from outside

Overload, provider error, uncertainty and a policy block all reach the caller
as "no translation", and they have nothing in common operationally. Each is a
separate series.

| condition | query |
|---|---|
| **overload** | `avoidpp_scans_total{outcome="shed"}` |
| **provider error** | `avoidpp_scans_total{outcome=~"detector_unavailable\|invalid_response"}` |
| **uncertainty** | `avoidpp_decisions_total{label="uncertain"}` |
| **policy block** | `avoidpp_decisions_total{action="block"}` |

Uncertainty lives on the decisions metric rather than the outcome one because
it is a property of the verdict, not of the request: an uncertain scan
*completed*.

Some queries worth having written down:

```promql
# Is the service shedding, or is the dependency down? Opposite remedies.
rate(avoidpp_scans_total{outcome="shed"}[5m])
rate(avoidpp_scans_total{outcome="detector_unavailable"}[5m])

# How much of a scan is ours? C32 measured 0.002%; this is the live version.
  histogram_quantile(0.95, rate(avoidpp_scan_duration_seconds_bucket[5m]))
- histogram_quantile(0.95, rate(avoidpp_detector_duration_seconds_bucket[5m]))

# Queue wait, which separates "the provider is slow" from "we are full".
histogram_quantile(0.95, rate(avoidpp_admission_queue_wait_seconds_bucket[5m]))

# The SLO agreed at C32: p95 <= 7s, p99 <= 12s.
histogram_quantile(0.95, rate(avoidpp_scan_duration_seconds_bucket[30m]))

# Flag rate in monitoring mode - the number that decides whether enforcement
# would have been disruptive.
  sum(rate(avoidpp_decisions_total{action="flag"}[1h]))
/ sum(rate(avoidpp_decisions_total[1h]))
```

Histogram buckets are taken from the C32 measurements rather than a default
ladder: the provider median is 2.8 s, p95 5.9 s, p99 10.2 s against a 15 s
timeout, so the buckets cluster there. A ladder that did not bracket those
points would produce a p95 that is an artefact of the ladder.

**Every series exists before its first event.** A counter that is absent until
something happens cannot answer "were there any blocks in the last hour" — the
query returns no data, which reads identically to a broken exporter.

---

## C33-AC3: nothing a passage touched

Three mechanisms, each asserted rather than reviewed.

**Label values are enumerated, not validated.** Every label this registry can
emit is declared with its complete set of permitted values. A value outside
the set becomes `other`; a label nobody declared is ignored. The total
cardinality of the gateway is therefore 350 series, computable from one file,
and no input can raise it. `Count` and `Observe` cannot allocate.

**`request_id` is loggable and cannot be a label.** That is C33-AC3's sentence
and it is also the easy mistake, because the field is *correct* in a log line
— correlating one request is what a log is for — and catastrophic as a label,
where it is one time series per request. The two lists are separate and a test
asserts both halves.

**The canary.** A registry is driven with a hostile passage and a credential
pushed at every entry point — as an outcome, as an error code, as a label
name, as a gauge state — and the exposition is then checked for every
fragment of both, and re-parsed to confirm it is still well formed. The
end-to-end version scans an actual attack through the real router and greps
the output.

One more, quieter check: every metric label name must also appear in
`obs.AllowedKeys`. Not because a label has to be loggable, but because a name
outside that list is a name nobody vetted.

---

## `/metrics` is authenticated, which is unconventional

Convention puts `/metrics` on an open port that is not routable from outside.
This gateway has one listener, and the counters are not neutral for *this*
service:

```
avoidpp_decisions_total{action="block",…}
```

That is an **oracle**. An attacker probing the guard watches the counter and
learns, per attempt, whether the passage was caught — which is exactly the
feedback a detection system must not hand out, and far more informative than
the 200 they receive in monitoring mode. The outcome counters leak the same
thing more coarsely.

So it sits behind the same bearer token as the scan route. Prometheus supports
`bearer_token` in a scrape config directly, so the cost is one line. It is not
rate limited: a scraper polls on a fixed interval and reading a counter costs
nothing, so the limiter could only ever refuse a legitimate scrape.

---

## What this does not do

1. **No spans are exported**, because nothing collects them. Trace *context*
   propagates and both services log it; a collector would need an exporter,
   which is additive.
2. **No detector-side metrics.** All four AC2 conditions are visible from the
   gateway, and the detector is private with no scraper. Its contribution is
   trace-correlated logs.
3. **No dashboards.** The queries above are the documented form the criterion
   allows; a dashboard JSON for a Grafana nobody runs would be the unexercised
   artefact this commit's opening argument is about.
4. **The two trace parsers are separate implementations**, in Go and Python.
   Sixty lines of string validation each, kept honest by the cross-language
   integration test rather than by a shared package to publish and version.
5. **Gauges are sampled at admission**, not at scrape time, so occupancy can
   be one request stale. The histograms are exact.
