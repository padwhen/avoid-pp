# C18 — versioned inference diagnostics

Scope: bounded model and prompt metadata plus internal latency and token usage,
so a recorded result can be attributed and costed.

## Acceptance criteria

1. Every live evaluation can identify model, prompt, inference settings and
   contract version.
2. External responses expose only intended stable fields; provider credentials
   and raw prompts never appear.
3. Unknown model usage is recorded as unavailable, not zero, and no
   LLM-generated confidence percentage is presented as calibrated.

## What a result now carries

Observed from a real scan:

```json
{
  "model": "claude-opus-5",
  "latency_ms": 4371,
  "input_tokens": 1119,
  "output_tokens": 174,
  "attempts": 1,
  "max_tokens": 2048
}
```

`attempts` is the number of provider requests including retries, so a report
can tell a scan that succeeded first time from one that cost three calls. That
matters more than the deadline for budgeting, because C17 established that
abandoning a request does not stop the provider billing for it.

The contract gained `versions.prompt_fingerprint`, `diagnostics.attempts` and
`diagnostics.max_tokens`. The schema is the normative definition and the
Pydantic models mirror it; the C08 parity test keeps them in step.

## AC3 — absent is not zero

Reporting an unknown token count as `0` would quietly understate cost in every
report that aggregates it. Every diagnostics field is optional and omitted
when unknown, and a test asserts that a genuinely zero value is still
representable — absent and zero must stay distinguishable, because a free call
is not the same as an unmeasured one.

There is deliberately no confidence, score or probability field. A test
asserts all three are absent from the model, so adding one is a visible change
rather than a quiet one. An LLM-invented probability is not calibrated, and
exposing it would invite a caller to treat it as though it were.

## AC2 — a fingerprint identifies without disclosing

`versions.prompt_fingerprint` is the SHA-256 of the prompt that ran. It lets a
saved report be checked against the repository — the same bytes produce the
same hash — without reproducing the prompt in every response.

Tests assert that a serialised result contains no credential, no `sk-ant`
substring, and no span of the prompt text, and that the whole block stays
under 500 bytes. `Diagnostics` forbids unknown fields, so a future field
cannot be smuggled in without changing the model.

## Verification

```sh
make check-python     # 147 tests
```

One live scan was run to confirm the numbers are real rather than plumbing:
latency 4371ms, 1119 input and 174 output tokens, one attempt, and no
credential anywhere in the serialised diagnostics.

## Not yet

C23 covers logging and redaction on the gateway side, and C33 adds tracing.
This commit exposes diagnostics on the assessment; it does not yet aggregate
them into the evaluation reports, which is C25.
