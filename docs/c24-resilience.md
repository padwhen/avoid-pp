# C24 · Cross-service failure behaviour

A failure matrix driven through the real gateway, the real detector client and
a real HTTP connection, against a stand-in service built to misbehave.

Substituting a fake `Assessor` would have skipped the client — and the client
is where timeouts, size limits, body draining and connection reuse live, which
is most of what can go wrong between two services.

## The invariant

**No failure becomes an allow.** A guard that fails open has not failed, it has
stopped guarding, and that is indistinguishable from success in every log and
dashboard.

Every case asserts it twice: once by parsing the body as an error envelope,
which forbids an assessment field by construction, and once by searching the
raw body for decision vocabulary — `"action"`, `"allow"`, `"assessment"`,
`"scan_status"`, `"label"`, `"decision"`. A body that merely *contained*
`allow` would be a contract violation even if the envelope parsed cleanly.

## The 21 faults

| | |
| --- | --- |
| Timing | slow (answers past the deadline), hang (never answers) |
| Transport | hangup before any bytes, hangup mid-body with a promised Content-Length |
| Shape | empty body, malformed JSON, truncated JSON, trailing JSON, 3 MiB body, mismatched request id, unknown label, unknown category, blank versions, incomplete coverage, HTML instead of JSON |
| Status | 500, 502, 429, 401, 204 |
| Deceptive | a clean verdict in an undefined shape |

The last one is the most dangerous and the reason the list is not just status
codes. `{"verdict":"no_injection_detected","ok":true,"allow":true}` is a
200 with a reassuring body, and the risk is a client that finds
`no_injection_detected` somewhere and acts on it. The contract requires the
whole shape or nothing.

`hangup_mid` is the subtle transport case: it promises 4096 bytes, sends forty,
and closes. A naive client treats that as a short read rather than a failure.

### Mapping

A deadline is 504 `deadline_exceeded`. Everything else is 503
`detector_unavailable` — including every upstream status code, because the
caller's relationship is with the gateway and a detector 401 is not the
caller's authentication problem.

The whole matrix passed on the first run. That is a result about C09 and C10
rather than about this commit: the client was written to treat anything
unexpected as an error, and it does.

## Recovery

Each fault is followed by a healthy request, which must succeed. A client that
gave up on a connection, or a limiter that counted a failure permanently,
would show up here and not in the matrix.

## C24-AC2 — bounded resources

A leaked goroutine per failure is the classic form of this bug: a response body
never closed, or a context never cancelled. It is invisible at small scale and
fatal at large, so the only way to see it is to fail many times and count.

```text
168 failures across 21 fault modes: goroutines 8 -> 17
```

Bounded, not proportional. The test warms up first, because the HTTP client,
the connection pool and the test server all create goroutines on first use and
counting those as leaks would fail for the wrong reason. It polls for a settled
count rather than sleeping a guessed interval.

**Response-body memory**, 20 replies of 3 MiB each:

```text
20 oversized replies (3 MiB each): heap delta 210328 bytes
```

Buffered, that would have been 60 MB. 210 KB is the size limit holding.

**Admission state** is returned on every failure path, checked by running the
whole matrix repeatedly through a controller with a small bound: a slot leaked
on any path would make later rounds shed for capacity rather than attempt, and
a shed request has a different error code from the fault being injected.

**Log hygiene** across the matrix, since these are the paths that carry error
values from another service — exactly where C23's guarantee most needs to hold.

## C24-AC3 — shutdown under in-flight work

```text
drained 4 in-flight scans in 1.47ms (budget 3s)
incomplete drain reported after 302ms: drain within 300ms: context deadline exceeded
```

The first test holds four requests inside the detector call, so work is
*provably* in flight when the signal arrives rather than probably. All four
complete; none is cut off mid-response.

The second gives the drain less time than the work needs and asserts the error
is reported rather than swallowed. Exiting zero would make a routinely
too-short budget invisible — the operator would see clean shutdowns and
truncated responses, and never connect the two.

Readiness is asserted to fail the instant draining begins, so a load balancer
routes new traffic away while accepted work finishes.

## The bounded soak

264 requests across 22 modes with varied synthetic text, asserting the
invariant on every iteration rather than at the end:

```text
soak: 264 requests across 22 modes, statuses map[200:12 503:228 504:24],
      goroutines 6 -> 21
```

Bounded on purpose. A soak that runs for an hour finds more and does not belong
in a suite that has to pass on every commit; this one is sized to catch
per-iteration leaks, which are the kind that matter here.

## The Python side

The same invariant from the other direction: seven provider failure shapes,
each asserted to produce a failure and never a verdict.

One of them is an exception whose `__str__` raises. Not contrived — an SDK
exception whose `__str__` touches a half-initialised response object behaves
exactly like that, and code which formats an error message *inside* an error
handler turns a clean 503 into a crash. It passes because only the type name
is ever read, which is the same decision C23 made for a different reason.

200 consecutive failures then assert the admission counters are zero and a
healthy request succeeds. The status mapping is written down in both suites, so
if either service changes it unilaterally one of them fails.

## Three mistakes worth recording

**A one-shot channel read twice.** Both the test body and its cleanup wanted
`Run`'s error from a buffered channel of size one. The second read blocked
forever, and the suite hung with no output. Now cached behind a `sync.Once`.

**A latent deadlock saved by a timeout.** One test closed its release channel
in a `defer`, which runs *after* `wg.Wait()` — so the wait was on a request
waiting on that close. It only completed because the scan timeout fired at ten
seconds. Releasing explicitly before the wait took it from 10s to 0.31s.

**Sleeps that outlived their clients.** The slow and hanging faults used a
plain `Sleep`, so the handler stayed busy after the client had given up — and
`httptest.Server.Close` waits for outstanding requests, meaning the suite paid
for every timeout twice. Making them respect request cancellation is both
faster and more realistic, since a real server notices a hangup. 31s to 13s
under `-race`.
