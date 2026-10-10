# C06 — deterministic evaluation runner

Scope: a runner that scores a detector adapter over the seed dataset and writes
a machine-readable report. No model is called. The adapters are fakes, so the
arithmetic is verifiable by hand before any live-model tuning begins at C13+.

```sh
make check-evals-runner                       # assert the arithmetic
uv run --project detector python evals/runner.py --adapter keyword
uv run --project detector python evals/runner.py --adapter oracle \
  --out evals/reports/oracle.json
```

## Two metric views, deliberately

| View | Over what | Answers |
| --- | --- | --- |
| `conditional` | cases that produced a definite label | How accurate is the classifier *given that it answered*? |
| `operational` | every scored case | What does the application actually experience? |

The split exists because the two can disagree completely. `always_uncertain`
scores `recall: null` over **0** answered cases on the conditional view — no
mistakes, because it never commits — while the operational view shows
`attack_caught_rate 0.0` and `uncertainty_rate 1.0`.

A detector cannot look effective here by abstaining. An abstention is never a
correct benign answer, and neither is an operational error; each is its own
outcome with its own count.

## Acceptance criteria

1. Hand-calculated toy cases produce the expected confusion counts, uncertainty
   count and operational-error count.
2. A report records dataset hash, detector identity, prompt/config version and
   per-case outcomes.
3. Deferred-quality cases are reported separately and are not silently counted
   as passes or included in Finnish MVP quality claims.

## Verification

### AC1 — the arithmetic is pinned

`evals/fixtures/toy-10.yaml` sets `scripted_output` per case, so the confusion
counts are a property of the file. 10 cases: 8 scored, 2 deferred.

```
attacks scored (4):  2 caught, 1 missed, 1 abstention
benign  scored (4):  2 passed, 1 false alarm, 1 operational error
```

Expected, by hand, and asserted by `evals/selftest.py`:

```
TP 2   FN 1   FP 1   TN 2   uncertain 1   error 1
conditional : recall 0.6667   fpr 0.3333   precision 0.6667  (6 answered)
operational : caught 0.5   passed 0.5   uncertainty 0.125   error 0.125
```

The self-test also pins the degenerate adapters, since each encodes a way a
detector could flatter itself:

| Adapter | Must report |
| --- | --- |
| `always_uncertain` | `recall: null` over 0 answered; `caught 0.0`; `uncertainty 1.0` |
| `always_clean` | `recall 0.0` — zero, never "no data" |
| `always_suspicious` | `recall 1.0` **and** `fpr 1.0` |

### AC2 — reports are reproducible

Each report records the dataset's SHA-256, its repo-relative path, scored and
deferred counts, detector identity, prompt version, config version, generation
timestamp, all eight outcome counts, both metric views, and a per-case row
carrying expected label, predicted label and outcome.

### AC3 — deferred cases cannot move a headline number

The toy fixture contains one deferred case the detector gets **right** and one
it gets **wrong**, so a leak in either direction would shift a metric. The
self-test asserts `scored_cases == 8` with `deferred_quality.count == 2`, and
that neither deferred id appears in `per_case`.

## What the dataset says about a naive detector

Running the keyword baseline over the 73 seed cases:

```
scored 68 cases (23 attack, 45 benign); 5 deferred, excluded
TP 5   FN 18   FP 8   TN 37
conditional : recall 0.2174   fpr 0.1778   precision 0.3846
```

The false positives are the point:

```
false positives by category: quoted_attack 5, imperative 3
false negatives by category: task_redirection 12, detector_targeting 6
```

A keyword matcher falsely flags **5 of the 10 quoted attacks** and three
legitimate imperatives, while missing 18 of 23 real attacks. That is exactly
the failure mode threat model section 3 describes: it cannot tell translating
an instruction from obeying one.

This is also evidence about the corpus. A dataset that could not separate a
naive detector from a real one would be unable to support any later claim; this
one visibly can.

## Not yet

No live model, no provider adapter, no prompt. Metrics are unweighted counts
over a 73-case corpus — far too small for the confidence intervals a release
gate would need. Latency and cost reporting arrive at C25, the expanded and
frozen holdout at C26.
