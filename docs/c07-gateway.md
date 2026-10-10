# C07 — gateway HTTP lifecycle and health

Scope: the Go server entry point, validated configuration, liveness and
readiness, structured request IDs, and bounded shutdown.

There is no scan endpoint, no detector call and no policy. This commit
establishes the lifecycle that later behaviour is added to, because
configuration validation, readiness and cancellation are expensive to retrofit
into working handlers.

```sh
AVOIDPP_DETECTOR_URL=http://localhost:9000 go run ./gateway/cmd/server
curl -i localhost:8080/healthz
curl -i localhost:8080/readyz
```

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `AVOIDPP_ADDR` | `:8080` | Must include a port |
| `AVOIDPP_DETECTOR_URL` | — | Required; http or https with a host |
| `AVOIDPP_SCAN_TIMEOUT` | `15s` | End-to-end budget; capped at 60s |
| `AVOIDPP_SHUTDOWN_TIMEOUT` | `10s` | Drain budget |
| `AVOIDPP_LOG_LEVEL` | `info` | debug, info, warn, error |

Development settings, not promised production behaviour. C32 revises them
against measured provider latency.

## Acceptance criteria

1. Liveness answers without external model calls; readiness represents
   initialization status.
2. Invalid configuration prevents startup with a useful error that does not
   reveal secrets.
3. Shutdown stops accepting requests and drains accepted work within a
   configured bound.

## Verification

```sh
cd gateway && go test -race ./...
```

### AC1 — two questions, two endpoints

Liveness and readiness are not interchangeable:

| | Question | Failure means |
| --- | --- | --- |
| `/healthz` | Is the process alive? | Restart it |
| `/readyz` | Can it serve traffic now? | Route traffic away, leave it running |

Merging them causes a specific outage: a server waiting on a dependency
reports itself dead, gets killed, restarts, and waits again.

`/healthz` makes no external call, so a probe neither bills a provider on
every scrape nor declares the process dead when that provider has a bad
minute. `TestLivenessIgnoresReadiness` asserts it answers 200 before
initialisation; `TestReadinessTracksInitialisation` asserts `/readyz` moves
503 to 200 to 503 across init and drain.

`TestScanEndpointDoesNotExistYet` asserts `/v1/scans` returns 404. A route
that exists but does nothing is indistinguishable from protection that
silently fails open, so it is not registered until C09 gives it behaviour.

### AC2 — errors name variables, never values

Configuration carries credentials: a detector URL can embed userinfo. One rule
governs every message in `internal/config` — name the variable and the
requirement, never the value. `invalid value "sk-ant-..."` is a helpful error
that has just written a secret to the logs.

`TestLoadErrorsNeverEchoValues` pastes a recognisable secret into four
different variables and fails if it appears in the error. Observed:

```
$ AVOIDPP_DETECTOR_URL="ftp://user:sk-ant-SECRET@d:1" \
  AVOIDPP_LOG_LEVEL=verbose go run ./cmd/server
gateway: invalid configuration: AVOIDPP_DETECTOR_URL: scheme must be http or https
AVOIDPP_LOG_LEVEL: must be one of debug, info, warn, error
exit status 1
```

Both problems are reported together rather than one per restart. The secret
appears zero times. `Config.Redacted()` strips userinfo for the startup log:

```json
{"msg":"gateway starting","detector_url":"https://redacted@detector.internal:9000"}
```

### AC3 — drain lets accepted work finish

`Shutdown` closes listeners first and only then waits, so cancellation stops
new connections without cutting short a request already being handled.

- `TestDrainLetsInFlightRequestsFinish` starts a 300ms handler, cancels mid
  flight, and requires the response to arrive with 200 and the handler to have
  run to completion.
- `TestDrainBudgetExpiryIsReported` gives a 50ms budget to 800ms of work and
  requires `Run` to return an error. A routinely-too-short budget must be
  visible, not a silent clean exit.
- `TestOnDrainRunsBeforeWaiting` requires readiness to fail the moment draining
  begins, so a load balancer stops sending new requests while existing ones
  finish.

Observed against the real binary on SIGTERM:

```json
{"msg":"gateway draining","budget":"10s"}
{"msg":"gateway stopped"}
```

## Request IDs

`X-Request-Id` is read and written, so a caller's own correlation id survives
the gateway boundary. An inbound id is attacker-controlled and reaches logs —
and later traces and reports — so it is accepted only within the contract's
64-character bound and a conservative charset, and otherwise **replaced**
rather than sanitised: a rewritten id would no longer match the caller's
records, which defeats the purpose silently.

`TestRequestIDPropagationAndRejection` covers newline injection, control
characters, ANSI escapes, spaces and over-long values.

## Not yet

No scan endpoint, detector client, policy, authentication or rate limiting.
Read and write timeouts are development defaults sized at C32. Readiness turns
ready immediately because nothing initialises asynchronously; from C09 it
becomes ready only after the detector client is usable.
