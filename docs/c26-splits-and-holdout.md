# C26 · Splits, holdout protection and corpus review

The corpus itself needs a fluent Finnish speaker. This is everything around
it: the splits, the guards, and the reports that say what is still missing.

## What the tooling decided for us

Two questions were open. The tooling answered both with evidence.

**"Freeze the holdout now or later?"** — Later. It cannot be frozen now:

```text
holdout: 7 cases in 7 groups
  imperative 2, ordinary 5
  0 attack, 7 benign

not fit to freeze (1):
  holdout has 7 cases but no attack cases, so it cannot measure recall at all
```

Random assignment over group names is approximately stratified once there are
enough groups — the law of large numbers does the work — and is not at
seventy-three cases. Freezing that would be worse than waiting, because a
frozen holdout is permanent by construction. So `--freeze` refuses, with the
reason.

**Is 600–1,000 cases enough?** Not to decide the gates on *held-out* data.

Deciding a gate on the holdout needs the holdout itself to carry 36 attack and
368 benign cases. At a 19% share that is a corpus of about 2,150:

| Holdout share | Total corpus needed |
| --- | --- |
| 19% (default) | ~2,155 |
| 25% | ~1,616 |
| 33% | ~1,224 |
| 40% | ~1,010 |
| 50% | ~808 |

At 1,000 cases with the default weights, both gates are decidable on
development data and only recall on the holdout. That is a real choice between
a weaker claim and a bigger corpus, so `--weights` makes it explicit rather
than the default making it quietly.

## Assignment is a pure function of the group name

This is the property everything else rests on. Hash the group name, take the
remainder.

If assignment depended on the number of cases, or on their order in the file,
adding a hundred passages would reshuffle the existing ones — and a case that
was held out last week would be in development this week. "Never used to tune
anything" would be unenforceable.

Verified by adding 385 synthetic cases and asserting that **nothing moved**,
and by reversing the file and asserting the assignment is identical.

### Why groups, and why not stratified

Variants of one family must share a split. The corpus contains matched pairs:
the same attack sentence bare and quoted, differing only in framing. With the
bare half in development and the quoted half in the holdout, tuning on the
first *is* tuning on the second, and the holdout would measure something the
prompt had effectively already seen.

Stratifying the assignment would fix the small-corpus degeneracy above, and it
was the first thing I tried. It breaks the more important property: a matched
pair is **one group spanning two categories** — the bare half is
`task_redirection`, the quoted half is `quoted_attack` — so hashing on
(category, group) splits the pair. Random over groups keeps pairs intact and
becomes adequate as the corpus grows, which is the trade I took.

## Holdout protection, and what cannot be enforced

"The holdout is not used to tune prompts" is a process guarantee. No code can
make it true — anybody can open the YAML. What code can do is make the safe
thing the default and make every exception leave a record.

1. **The default excludes it.** Evaluations run on development plus validation
   unless the holdout is named. Nobody touches it by forgetting.
2. **Every access is logged** with the prompt fingerprint current at the time.
   This is the mechanism that does the real work: a holdout result only means
   something if the prompt was frozen beforehand, and the log shows whether it
   was. `prompt_changed_since_last_access` is what turns the guarantee into
   something checkable.
3. **The frozen manifest is digested.** A holdout that gained or lost a case
   is not the frozen holdout, and `verify_unchanged` refuses it — so a result
   claimed against the frozen holdout can be shown not to be one.

The manifest records ids and a digest, never passages. A manifest that
embedded the text would make reading the holdout manifest a way of reading the
holdout.

## Duplicates: reported, never removed

The judgement is the author's, because a tool cannot tell a mistake from the
point:

- two passages differing only in framing are a **matched pair**, and that
  near-identity is what makes them the sharpest cases in the corpus;
- two differing only in a diacritic are a **deliberate pair** testing whether
  a missing umlaut changes the verdict;
- two differing only in a typo are probably one passage entered twice.

A tool that deduplicated automatically would delete the first two kinds
silently, and nobody would find out until the corpus had lost the cases it was
built for. Cases sharing a group are exempt from the near-duplicate check.

**Cross-split leakage is reported separately and at a lower threshold**, because
the consequence is different. A passage 80% identical to one in another split
means tuning on the first tunes on the second, so the holdout measures
memorisation. Redundancy within one split is merely untidy.

Exact duplicates fail the build: there is no reading under which the same
passage twice is intentional.

### The bug that made the detector useless

`difflib.SequenceMatcher` defaults to `autojunk=True`, which treats any
character appearing in more than 1% of a sequence over 200 characters as junk
and excludes it from matching. For prose that means spaces and common vowels.

Two Finnish passages differing by a single word scored **0.524**. Every
near-duplicate above the 200-character mark went undetected, and realistic
passages are all above it. With `autojunk=False` the same pair scores 0.992.

The self-test pins this, and checks the threshold against the *folded* length
rather than the raw one — the first version of that assertion used the raw
length and passed a string that folded down below the cutoff, failing for the
right reason with a misleading message.

## The coverage audit

C26-AC1 names properties the corpus must include. The audit counts them, so
progress is visible per property rather than as one total:

```text
C26-AC1 coverage (heuristic counts, not scores):
      colloquial_register         9 / 60
      missing_diacritics          4 / 40
      long_inflected_tokens       6 / 60
      imperative_mood            22 / 60

other properties present:
      contains_digits            17
      contains_url_or_email       0
      quoted_speech              21
```

Every number is a count with its detector written down, never a score.
Detecting colloquial register by looking for `mä` and `sä` is crude, and a
fluent speaker reading the corpus is the real check — which is what
`review_status` records. What the audit is for is the one thing a human cannot
do quickly over four hundred passages: notice that a property is at zero.

Seven cases are still `pending_review`, and AC1 requires fluent review status
before any quality claim, so those seven cannot support one.

## CI was missing the evaluation checks

Found while wiring these up: the workflow ran `check-go`, `check-python`,
`check-contracts` and `check-contracts-selftest`, and **not** `check-evals` or
`check-evals-runner`. So the dataset validator and every metric fixture had
only ever run locally — including C25's published-interval checks and the
assertion that both release gates read undetermined at the seed corpus size.

CI now runs the same set as `make check`, which is what it should have been all
along.
