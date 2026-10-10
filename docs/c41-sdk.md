# C41 — minimal Python and Go clients

> **C41-AC1** Clients preserve allow/flag/block and error distinctions; no
> helper silently turns failure into allow.
> **C41-AC2** Timeout, authentication and retry behavior are documented and
> tested against contract fixtures.
> **C41-AC3** Examples enforce decisions server-side and preserve exact
> scanned text.

The plan puts C41 after C30 because a client should follow a real integration
rather than precede one. The integration exists — C28 built it — so this
commit is written before the gate report rather than after it, which is a
deliberate departure from strict order and the only one in this project.

## Why a client at all

The wire types already existed, twice: `gateway/internal/contract` in Go and
`detector/src/translation_guard/schemas.py` in Python. Neither is reachable by
a caller. `internal` is a compiler-enforced wall, and the detector's models
describe the private assessment API rather than the public scan API.

So anyone integrating this service wrote the client C28's example wrote: build
a JSON body, post it, check the status, read `decision.action`. That is about
forty lines, and the interesting part is not any of them. The interesting part
is the set of distinctions the result preserves, and all three are easy to lose
while writing code that looks finished.

## The three distinctions

**allow, flag and block are three answers.** Monitoring mode is the only mode
this service can run in before its quality gates are met, and monitoring
produces flags. A client offering `is_safe()` would force every caller to
settle the flag question once, silently, at a call site — and the answer is a
property of the deployment, not of the verdict. So the policy is an argument:

```python
permits_translation(verdict, translate_on_flag=False)
```
```go
verdict.PermitsTranslation(false)
```

Both are written as allowlists, so an action added to the contract has to be
considered here deliberately. Until it is, it does not translate.

**A failure is not an answer.** No code path returns a usable verdict from
anything other than a complete, internally consistent 200 body. Python raises;
Go returns an error wrapping `ErrScanFailed`, so a caller can write "any scan
failure means refuse" once rather than enumerate types it will later forget to
extend.

The Go side has an extra property worth stating. `Action` is a string type, so
the zero `Verdict` has `Action == ""`, which is not `ActionAllow`:

```go
verdict, _ := client.Scan(ctx, in) // error ignored
verdict.PermitsTranslation(true)   // false
verdict.Covers(passage)            // false
```

A caller who ignores the error gets a refusal rather than a permission. That is
why `Action` is a string type rather than an int enum where `0` would have had
to mean something.

**An unrecognised value is not a benign value** — and which way to fail
depends on the field, because the contract says so per field.

## Where the contract tells clients what to do

`common.schema.json` on `action`:

> CLIENT RULE: any value not recognized by the client MUST be treated as
> `block`.

This is the one place the contract instructs clients about data they cannot
understand, and the instruction is **not** "reject". That is correct, and it
took a moment to see why: the enum is append-only, and a client that refused
unknown actions would turn every future addition into an outage at every
deployed caller simultaneously. Treating it as a block is both fail-closed and
survivable.

So an action from a later version becomes a block, with the original string
retained in `unrecognised_action` / `UnrecognisedAction`, so telemetry can show
that the enum moved rather than that the passage was hostile.

An unrecognised **label** is refused instead, and the asymmetry is the point:
the consistency check below cannot be performed against a label whose meaning
is unknown. An unknown label is not a fourth kind of clean.

An unrecognised **category** is dropped. Categories are advisory, and no branch
anywhere becomes permissive through one being absent.

An unrecognised **reason code** is kept as a string. It is telemetry; the
action carries the decision.

## Consistency, in one direction only

The schema's rules are two-sided — a clean label always allows, a suspicious
one never does. The clients enforce one side:

| response | client |
|---|---|
| `suspicious` + `allow` | refused (`allow_contradicts_label`) |
| `allow` + a reason code other than `clean_complete_scan` | refused (`allow_without_clean_reason`) |
| `no_injection_detected` + `block` | **honoured** |

Refusing the first is the whole point of the service, arriving as a
well-formed 200. Honouring the third is the less obvious half: a server being
stricter than its own schema is not a safety problem, and overriding it would
be the client second-guessing a server-side decision — which is the thing
C41-AC3 says not to do, applied to the client itself.

## The text binding, moved into the client

C28 established that "scan the text, then translate the text" is easy to write
and easy to get subtly wrong, because nothing in that sentence says the two
texts are the same one. It solved that with a ticket bound to a digest.

That logic is not application logic. Binding a verdict to the bytes it was made
about is a property of a scan result, so the client does it:

- it sends the passage byte for byte — no trimming, no normalisation, no
  whitespace collapsing;
- it refuses a response whose `coverage.original_utf8_bytes` does not equal
  what it sent (`coverage_mismatch`), whose coverage is partial, or which
  reports truncation;
- it returns `scanned_digest` and `covers(text)`, over the exact UTF-8 bytes
  and nothing normalised.

An application built on the SDK gets all of that without having written it,
which is the difference between a property and a rule someone has to remember.

## Timeouts, authentication, retries

**There is no default timeout.** `timeout_seconds` is a required keyword in
Python and a required field in Go. The right value depends on the gateway's
configured scan budget, which the client cannot know, and the failure of
omitting it is a stalled application rather than an error — so it has to be
stated. A test asserts that constructing a client without one fails.

**Authentication** is a bearer token in the `Authorization` header and nowhere
else. A key in a query string lands in access logs, proxy logs, browser history
and referrer headers. Three refusals go with it:

- plain `http` to a non-loopback host, because the key would be in clear text
  (loopback is allowed: `make up` serves the gateway on a local port);
- credentials embedded in the base URL;
- redirects, which on an authenticated POST invite sending the token to
  whatever host the `Location` header names.

Both clients redact the key in their own string rendering, because a client
value reaches a log line, a panic dump or a debugger eventually.

**Retries default to none**, and the rule for the ones you can enable is
narrow: retry only where the server has said the work definitively did not
happen.

| failure | retried |
|---|---|
| HTTP 429, any body | yes |
| `rate_limited`, `overloaded` | yes |
| `detector_unavailable` | **no** |
| `deadline_exceeded` | no |
| `internal_error`, 5xx | no |
| a transport failure or client timeout | no |
| a contradictory 200 | no |

`detector_unavailable` is the one worth arguing about. A 503 reads as
transient, and most clients would retry it. This one does not, because the
contract attaches no retry guidance to it and **a scan is a paid provider
call**: retrying a request that may already have reached the model buys one
verdict for two prices, and the caller is about to turn it into a block anyway.
The transport case is the same reasoning with less information — a connection
error can mean the request never arrived, or that it ran a paid scan whose
response was lost, and the client cannot tell which.

A server-advised delay is honoured up to a cap. A gateway under load can
legitimately ask for 30 seconds, and a client that obeys silently has converted
one slow scan into a hang. An HTTP-date `Retry-After` is deliberately not
parsed: a date means trusting the server's clock against ours, and the fallback
delay is a safe answer.

## The shared expectations table

Two independently written test suites that happen to agree are not a
cross-language contract test; they are two opinions.

[`sdk/contract-expectations.json`](../sdk/contract-expectations.json) is the
single statement of required client behaviour — 48 cases, most pointing at
`contracts/fixtures/`, each naming the outcome, the action, the error code or
the rejection reason. Both suites read it and implement the same assertions
against it.

For fixture cases the harness synthesises a passage of exactly the byte count
the response claims, so the client's byte cross-check participates in every
case rather than tripping all of them.

Each case says two things at once: what the normative schema makes of the body,
and what a client that does not run a JSON Schema validator at runtime makes of
it. Those answers differ, and the differences are the useful part — the
invented-confidence fixture is schema-invalid and the clients accept the
verdict, because unknown response fields are forward compatibility rather than
smuggling when the client is the only reader. What matters there is that the
number cannot reach an application: neither `Verdict` type has a field for it.

### It found a disagreement

The two clients classified wrong-typed JSON fields differently, and
`mypy --strict` is what led to it. Go unmarshals into a struct, so
`{"coverage": {"original_utf8_bytes": "45"}}` fails as a whole and the most
specific thing it can say is that the body is unreadable. Python's `int("45")`
would have accepted it and built a verdict on a number the gateway never sent
as one. `"truncated": "false"` was worse — a true-ish string.

The rule both now follow, stated in both files and pinned by eight table cases:

- a field that is **absent** is a missing field;
- a field carrying the **wrong JSON type** makes the body unreadable;
- only a right-typed, unrecognised **value** gets a specific answer.

## The example

[`examples/sdk_integration.py`](../examples/sdk_integration.py) is C28's
integration rebuilt on the client. What disappears is everything that was never
application code: the HTTP call, the status mapping, the error-code handling,
and the ticket. What remains is the only part that was ever that file's
business — what to do about a flag, and what to say when a translation did not
happen.

It keeps C28's three outcomes, because they are still three different things to
tell a user:

```
BLOCKED      the guard decided this must not be translated
TRANSLATED   the guard allowed it and the translator produced text
UNAVAILABLE  the guard allowed it and no translation was produced
```

C28's own version is **kept rather than rewritten**. It is the code the C26 and
C29 measurements actually ran through, and replacing it would leave those
documents describing something that no longer exists. The duplication is
deliberate and `examples/README.md` says which one to copy.

Seventeen tests cover it, including every status a scan can fail with, each
asserting the translator was not called; the Dutch-in-Finnish preservation case
from C03/C10; and a provider refusal, which must stay visibly distinct from a
block.

### A test that proved nothing

The first attempt at the digest test substituted the passage before the scan.
It passed as TRANSLATED, and that was correct: the substituted text was then
simply the text that got scanned, so translating it was right. A divergence is
only a divergence if it happens *between* the scan and the handover. The
surviving test builds a verdict whose digest is over one passage and presents it
for another **of identical length**, so the byte cross-check cannot tell them
apart and the digest is the only thing standing. It raises `TicketMismatch`
rather than returning a block, because a caller who reaches it has a bug and
not a hostile passage.

## Two contract gaps found while writing this

A client is written from the documents, so writing one reads them properly.

**`415` was undocumented.** `openapi.yaml` listed 400, 401, 403, 413, 422, 429,
503 and 504. The gateway has returned 415 with `unsupported_media_type` since
C20 — six tests in `decode_test.go` assert it — and the code is in
`error.schema.json`. A client written from the OpenAPI document alone would
have had no mapping for a status it can certainly receive. Added, with a note
saying when and why.

**`token_budget_exceeded` cannot be emitted.** It is in `error.schema.json` and
documented at 422 in `openapi.yaml`, and `gateway/internal/contract` has no
constant for it. Not a bug — the code is reserved for a budget check that does
not exist yet — but a client must handle it regardless, because a code the
contract permits is not a code a client may meet with a crash. Both clients
define it and a table case covers it; this document is the record that nothing
currently produces it.

## Schema parity, in both directions

The clients' enums are a hand transcription of `contracts/schemas/*.json`, and
a hand transcription drifts. C28 found exactly that: the gateway's Go struct had
been missing two response fields since C18, and nothing failed because the only
path exercising them was the live one.

So both suites read the schemas and compare — a value in the schema and missing
from the client, **and** a value in the client the schema never defined. The Go
side needed `Actions()`, `Labels()` and friends to make the second direction
checkable, which is why they exist. The error-code set is pinned as "the
schema's, plus exactly `unknown`", so a code quietly dropped or invented fails.
Both also assert the contract version string matches the gateway's declaration,
because a report quotes it.

## What is not here

- **No sync Python client.** The repository is async throughout and a
  `ScanClient` that was secretly synchronous would be the only thing in it that
  blocked an event loop.
- **No batching.** The request schema takes one passage as an object rather than
  an array, so a request carrying two cannot be expressed. Batch scanning, if
  ever added, gets its own endpoint and its own method.
- **No published package.** One lockfile for four Python files, or a tagged Go
  module for a personal learning project, would cost more than it explains.
  Vendor the directory; the README says so.
