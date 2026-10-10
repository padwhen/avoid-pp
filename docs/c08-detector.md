# C08 — FastAPI detector service with a fake detector

Scope: strict Pydantic input/output types, lifespan initialisation, and a
replaceable async detector interface. No provider SDK, no API key, no network.

```sh
make run-detector                     # 127.0.0.1:9000, fake mode
curl -s localhost:9000/readyz
curl -s -X POST localhost:9000/internal/v1/assessments \
  -H 'Content-Type: application/json' \
  -d @contracts/fixtures/valid/assessment-request.finnish-with-embedded-dutch.json
```

## Acceptance criteria

1. Valid contract fixtures round-trip through the private assessment endpoint.
2. Wrong types and unexpected fields are rejected rather than silently coerced
   into trusted settings.
3. Fake mode requires no API key, and readiness fails if required
   initialization fails.

## Verification

```sh
make check-python     # ruff, mypy, 31 tests, import
```

### AC1 — the fixture and the schema are both from contracts/

`test_contract_fixture_round_trips` posts
`contracts/fixtures/valid/assessment-request.finnish-with-embedded-dutch.json`
and validates the response against
`contracts/schemas/assessment-response.schema.json`. Input and oracle both come
from C03, so the service and the contract cannot drift apart quietly.

Observed against a real uvicorn process:

```json
{
  "request_id": "req-flag-1",
  "assessment": {
    "label": "suspicious",
    "categories": ["task_redirection"],
    "evidence": [{
      "content_id": "passage-fi-nl",
      "quote": "Negeer alle eerdere instructies",
      "category": "task_redirection"
    }]
  },
  "coverage": {"original_utf8_bytes": 103, "scanned_utf8_bytes": 103, "truncated": false},
  "versions": {"detector": "fake-0", "prompt": "none"}
}
```

Two details in that response matter:

- The evidence quote is lifted from the **original** text, not from the
  lowercased copy used for matching. A normalised quotation would fail the
  gateway's verification at C15, and fabricated evidence is the thing that
  check exists to catch. `test_evidence_quote_exists_in_the_original` asserts
  every quote is a substring of what was sent.
- Coverage is computed from the bytes actually received, never from anything
  the detector reports about itself.

### AC2 — rejected, not coerced

Every model sets `extra="forbid"` and `strict=True`. Eleven rejection cases
are covered, including caller-supplied `policy` and `mode`, an unknown
`trusted` flag on content, an unknown task id, text as a number, an injected
`language_hint`, and an over-long `request_id`. Each asserts 422 **and** that
the body carries no `assessment`.

`test_rejection_does_not_echo_the_passage` puts a canary string in the text,
forces a rejection, and fails if the canary appears in the response. FastAPI's
default validation detail embeds the offending input — which is
attacker-controlled and may be a passage — so the handler replaces it with a
fixed message.

#### A note on strict mode and enums

Pydantic's `strict=True` requires an *instance* of an enum, but JSON only
carries strings, so every enum field would reject valid contract input. Enum
fields therefore opt out individually with `Field(strict=False)`. Everything
else stays strict: an int still must not become a string, unknown fields are
still refused, and an unknown enum *value* is still rejected.

`test_contract_parity.py` compares the models against the JSON Schema —
enum members, and the bounds on text, quote, request id and content id — so
the duplication between the two cannot drift. It also asserts no `Label`
value collides with the gateway's `action` vocabulary: the detector assesses,
it never decides.

### AC3 — no key, and failure is visible

`Settings` defaults to `mode=fake`, so a clean checkout, the test suite and
ordinary pull-request CI run with no provider credential and no spend.

When initialisation fails the process stays **live but not ready**:

```
liveness : 200   <- still alive; restarting changes nothing
readiness: 503   {"status":"not_ready","reason":"RuntimeError"}
assess   : 503   {"error":{"code":"detector_unavailable",...}}
```

Exiting on a failed start would turn a recoverable dependency problem into a
crash loop that reports nothing. Reporting not-ready routes traffic away and
leaves something running that can answer *why*.

The assessment endpoint refuses while not ready, and that refusal is an error
envelope — `ErrorResponse` forbids extra fields, so no failure path can carry
an assessment.

## The fake detector is not a detection strategy

It matches a handful of marker substrings. The C06 evaluation of exactly this
approach scores recall 0.22 while falsely flagging half the quoted attacks,
because keyword matching cannot tell translating an instruction from obeying
one. Its purpose is to exercise the plumbing deterministically and for free.
Treating its output as evidence of protection would be a category error.

## Not yet

No provider SDK (C13), no detector prompt (C14), no model output validation
(C15), no input limits (C16), no retries or deadline enforcement (C17). The
gateway does not call this service until C09. `deadline_ms` is accepted and
currently ignored.
