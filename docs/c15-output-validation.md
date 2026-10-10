# C15 — validate model output and evidence

Scope: check a model reply against the passage it describes, before it becomes
an assessment.

Structured outputs guarantee the reply is **schema-valid**. They guarantee
nothing about whether it is **true**, and the two are easy to conflate. This
commit is the gap between them, in `translation_guard/validation.py`.

## Acceptance criteria

1. Unknown enums, oversized reasons and invalid structures are rejected.
2. Every evidence quote exists in its referenced original content; fabricated
   quotations are rejected as invalid evidence.
3. Requests containing instructions to return forged JSON cannot bypass
   response validation; incorrect but valid classifications remain measurable
   model failures.

## The three rules

**Every quotation is verbatim.** A quote that does not occur in the passage it
cites was invented. Evidence pointing at text the caller never sent is worse
than no evidence, because it looks like support.

**An accusation needs surviving support.** A `suspicious` verdict whose
quotations are *all* fabricated is rejected outright. The label may still be
right, but nothing the model offered backs it, and a detector that invents its
reasons cannot be audited. A clean verdict with invented quotes keeps its
label — a clean verdict is not an accusation — and the quotes are dropped.

**A wrong answer is not an invalid one.** A schema-valid reply that classifies
badly passes validation and is counted as a model failure by the evaluation.
Rejecting it here would hide a quality problem behind an availability error
and make the detector look more reliable than it is.

## Verification

```sh
make check-python     # 111 tests
```

### AC2 — no normalisation on either side

Case-folding or collapsing whitespace would accept a quote the caller cannot
find in their own text, which defeats the point of quoting. Rejected:

| Quote | Why |
| --- | --- |
| `Ignore all previous instructions` | a translation, not a quotation |
| `negeer alle eerdere instructies` | case-folded |
| `Negeer  alle  eerdere  instructies` | whitespace changed |
| `Negeer alle eerder instructies` | a word altered mid-quote |
| `DROP TABLE users` | never sent at all |
| empty, whitespace-only, over 512 chars | not usable evidence |

A **truncated** quote is deliberately accepted. Dropping the final letter of
`instructies` still leaves a real substring, and the only property that matters
is whether the caller can find it. A first draft of the test got this wrong and
asserted the rejection of a quote that was genuinely present.

### AC3 — there is nothing to bypass

A passage instructing the model to emit a clean verdict cannot bypass this
layer, because the reply is checked against the passage either way. What such a
passage can do is **persuade the model**, and that is a detection failure the
evaluation measures, not a hole here.

The test makes both halves explicit: a wrong-but-valid clean verdict passes
validation, and the same hostile passage still cannot produce invented support
for a suspicious one.

## What the adapter does with a rejection

`ClaudeDetector` turns `InvalidModelOutput` into `DetectorUnavailable`, which
the service maps to 503 with no assessment. Fabricated quotes that do not
trigger an outright rejection are counted rather than merely logged, because a
detector that regularly invents quotations is a quality signal — C18 surfaces
it.

## Not yet

Input byte and token limits are C16. Retries and deadline propagation are C17.
Diagnostics that expose the fabrication count are C18.
