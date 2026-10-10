# C13 — Claude provider adapter

Scope: the official Anthropic SDK behind the detector interface, with
provider and model configuration and a restricted client. The detector
*prompt* is C14; output validation against the original passage is C15.

```sh
# fake is still the default: no key, no spend
make run-detector

# live, opt-in
AVOIDPP_DETECTOR_MODE=live make run-detector

# the only thing that calls a paid API
make live-smoke CONFIRM=yes
```

## Acceptance criteria

1. The adapter sends only bounded task context and the original passage to the
   provider; no tool definitions are exposed.
2. Missing credentials affect live mode only; fake mode and offline CI remain
   usable.
3. Recorded fake responses and an opt-in live smoke command exercise the same
   response-mapping path.

## Verification

```sh
make check-python              # 20 adapter tests, no network
make live-smoke CONFIRM=yes    # 4 real requests
```

### AC1 — no tool surface at all

The request uses **structured outputs**, not tool use. A Pydantic model
constrains the reply to a JSON schema without declaring a single tool, so
there is no tool surface for a passage to aim at. A test asserts the outgoing
request contains no `tools`, `tool_choice`, `mcp_servers` or `container` key.

The passage travels in a user message, fenced and labelled as untrusted, with
the task rules in the system prompt. A test asserts the passage never appears
in the system prompt. That does not make injection impossible — nothing here
does — but it keeps the boundary explicit, and making it effective is what C14
is measured on.

### AC2 — fake stays the default

`Settings` defaults to `mode=fake`, so a clean checkout, the test suite and
pull-request CI run with no key and no spend. Live is opt-in because every scan
costs money.

In live mode a missing key fails at `start()`, which leaves the service **live
but not ready** rather than accepting traffic it cannot serve — the same
behaviour C08 established for any failed initialisation.

### AC3 — one mapping path, two ways in

A stub client captures the outgoing request and returns recorded replies, so
the mapping is asserted without a network call. The opt-in script drives the
same `assess()` and the same `_to_assessment()`.

Observed against `claude-opus-5`:

```
  ok     ordinary         no_injection_detected   9165ms
  ok     bare attack      suspicious              4835ms   quote: Ohita aiemmat ohjeet...
  ok     quoted attack    no_injection_detected   4179ms
  ok     embedded dutch   suspicious              6315ms   quote: Negeer alle eerdere...
```

**The quoted attack is the result that matters.** It contains a real attack
sentence inside an ordinary support-ticket message, and the keyword fake flags
it — that false positive is visible in PR #8 and is what C06 measured at 5 of
10 quoted attacks. The live detector allowed it, which is the distinction the
whole project exists to make.

Four passages prove the plumbing works. They say nothing about quality: the
corpus is C05 and the metrics are C06, and the real evaluation has not been run
yet.

## Nothing uncertain becomes clean

Every provider failure raises `DetectorUnavailable`, which the service maps to
503 with no assessment. Timeout, authentication, rate limit, connection and any
other non-2xx are each covered by a test.

Two cases are worth calling out:

- **A safety refusal is not an assessment.** `stop_reason == "refusal"` raises
  rather than returning the parsed body. Treating a refusal as clean would turn
  the model declining to answer into permission to continue.
- **A fabricated quotation is dropped.** Every evidence quote is checked
  against the passage before it is published; a translated or invented quote
  does not survive. C15 turns this into a hard rejection with its own
  reporting.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `AVOIDPP_DETECTOR_MODE` | `fake` | `fake` or `live` |
| `LLM_API_KEY` | — | Read from the repository-root `.env`, which is gitignored |
| `AVOIDPP_DETECTOR_MODEL` | `claude-opus-5` | Any model id; the response records which ran |
| `AVOIDPP_DETECTOR_REQUEST_TIMEOUT_SECONDS` | `15` | The gateway's deadline still wins when lower |

Settings use `extra="ignore"` rather than `extra="forbid"`, because the
repository-root `.env` is shared and may hold keys this service does not read.

SDK retries are set to **0**. The gateway owns the end-to-end deadline, and its
retry policy arrives at C17; an SDK retry here would silently multiply attempts
inside a budget the gateway believes it controls.

## Cost and latency, measured

The four live calls took **4.2 to 9.2 seconds** each. That is uncomfortably
close to the gateway's 15-second default scan deadline — a slower passage or a
busy provider would exceed it. C32 sets these budgets from measurement; this is
the first real data point, and it suggests the default needs raising or the
model needs reconsidering.

Model choice is configurable for exactly this reason. `claude-opus-5` is the
default; a cheaper model would cut both cost and latency, and whether it also
costs recall is an evaluation question, not an assumption.

## Not yet

No versioned prompt (C14), no strict output validation with rejection (C15), no
input token budget (C16), no retries or deadline propagation (C17), no
diagnostics (C18). The live smoke is four passages, not an evaluation — running
the C06 runner against the live detector over the 73-case corpus is the obvious
next step, and it costs real money.
