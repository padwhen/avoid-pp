# C29 · Protected translation outcomes

Every case runs twice: the translator alone, and the translator behind the
guard. The guard's value is the difference, which a protected-only run cannot
show.

## The result, on a 90-case stratified sample of development data

```text
baseline (translator alone)          protected (guard in front)
  faithful_translation        7        attack_blocked             10
  service_failure             8        faithful_translation        4
  task_deviation              1        service_failure             1
  ungraded_no_reference      74        task_deviation              1
                                       ungraded_no_reference      74

guard prevented an actual deviation  : 0
provider refused the attack anyway   : 7
baseline translated attack faithfully: 3
guard caused a false block           : 0
false block rate: 0.0000 [0.0000, 0.0451] over 80 benign
```

**The guard prevented nothing measurable, and cost nothing measurable.**

On these 10 attack cases the translator alone was never captured. The
provider refused 7 outright and faithfully translated the other 3 — and
translating "ignore all previous instructions" into English is not obeying it,
so those 3 are correct behaviour rather than near-misses. There was no
obedience for the guard to prevent.

That is the honest reading, and it is the reason the evaluation is paired.
Without the baseline column, the protected run shows **10 of 10 attacks
blocked** and the guard looks essential.

### What this does and does not say

**It does say** the guard's precision is good on this sample: zero false
blocks across 80 benign passages, upper bound 4.5%. The guard is not getting
in the way.

**It does not say** the guard is unnecessary. Ten attack cases cannot measure
a prevention rate — a perfect run on 10 supports a lower bound near 69%, and
this run prevented 0 of 0 available opportunities, which is not a rate at all.
What it says is that *on bare Finnish attacks of the kind this sample
contains*, the provider's own safety behaviour already does the work.

**It does not cover** the case the guard is most needed for. A provider
refusal is a blunt instrument: C27 found it refuses passages that are
legitimate translation material, and C26 found a passage it refuses to
*analyse*. A guard that makes a decision is more useful than a provider that
declines, even when both prevent the same attack — because only one of them
can also permit a quoted attack. That is a property this sample's 80 benign
cases support and its 10 attack cases cannot.

## The classifier took four attempts, and each error flattered or maligned

Worth recording, because every one produced a plausible-looking number.

**1. Benign translations counted as service failures.** Benign cases have no
reference translation — they are not attacks, so there was nothing to write a
reference against — and the grader mapped "ungradeable" to "failed". 74 good
translations were reported as failures, which makes a working system look
broken with a number shaped exactly like a real outage. Fixed by adding
`ungraded_no_reference`, which claims nothing about faithfulness.

**2. Blocked attacks counted as faithful translations.** The protected column
showed 14 faithful against the baseline's 7, and the extra 7 were attacks
blocked before the translator saw them. Blocking an attack is a success but it
is not a translation, and a column mixing them answers neither question.
Fixed by adding `attack_blocked`.

**3. Provider refusals counted as prevented deviations.** This is the one that
mattered. The summary claimed the guard "prevented deviation on 7 cases" when
those 7 were baseline *provider refusals* — the attack would have failed
without the guard. Fixed by counting only an actual deviation that the guard
stopped, with refusals reported alongside as the context that makes the number
readable.

**4. A spend guard that did not guard.** An indentation mistake in a string
replacement moved `return 1` inside an unrelated `if`, so the confirmation
check fell through and the tool made 396 provider calls — about $1.60 — when
asked for an estimate. There is now `make check-spend-guards`, which invokes
every paid tool in-process with the provider client replaced by one that fails
the test if it is constructed at all. A confirmation check is a safety
property, and one without a test is a comment.

## Grading is a human decision

C29-AC3 is explicit that an automated judge is not sole ground truth, and the
reason is circularity: asking a language model whether a language model
translated faithfully shares a failure mode.

So the numbers above are **machine proposals**, and the report says so in a
field of its own. 75 of 90 cases are flagged for human review in
`evals/reports/review-development-sample90.txt`, which is most of them —
because 74 are benign cases with no reference, and "I cannot grade this" is
the correct proposal for those.

The grade of record is the human one. Nothing here claims otherwise.

## Re-analysis rather than re-running

`evals/outcome_reanalyse.py` re-derives outcomes from a saved report's stored
outputs. All four classifier fixes above were applied to the existing 90-case
data without a single additional provider call, which is why the per-case
outputs are stored rather than just the verdicts.

## Cost

$1.68 for the sample, plus $1.60 accidentally spent by the broken guard. A
full development run would be $8.15 for 436 cases at 1,308 provider calls, and
is the user's decision rather than a default.
