# C39 — benchmarking Finnish-capable local classifiers

> **C39-AC1** Model revision, license, tokenizer limits and Finnish
> evaluation are recorded; English benchmark scores are not substituted.
> **C39-AC2** The comparison measures recall, false positives, uncertainty,
> CPU/GPU memory and latency on named hardware.
> **C39-AC3** ONNX/quantization or a cascade is adopted only after quality
> regression checks; a low local score cannot create an untested bypass.

```sh
make local-bench CONFIRM=yes     # downloads ~2.5 GB, costs nothing, CPU only
```

---

## Decision: no local classifier is adopted, and no cascade is built

**Every candidate misses about a third of Finnish attacks.** The best
recalls 0.679 against a 0.90 gate, and its interval tops out at 0.801 - so
the recall gate is not merely unproven, it is **not met**. A cascade using
that model as a free screen would save 90% of the provider spend and miss 17
of 53 attacks outright, which is precisely the untested bypass AC3 names.

The adapter stays as the evaluated artifact. `DetectorMode` has no `local`
member, `build_detector` cannot construct one, and a test asserts both.

---

## The licence and language review — C39-AC1

Done first, as the criterion requires, and against the Hugging Face API
rather than from memory. **No prompt-injection classifier on the Hub
declares Finnish support.**

| model | gated | licence | base | declares |
|---|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | no | Apache-2.0 | deberta-v3-base | **en only** |
| `proventra/mdeberta-v3-base-prompt-injection` | no | MIT | mdeberta-v3-base | none |
| `Horizon-Labs/prompt-injection-guard-base` | no | Apache-2.0 | mmBERT-base | 19 languages, **no fi** |
| `qualifire/prompt-injection-sentinel` | auto | other | ModernBERT-large | en |
| `meta-llama/Llama-Prompt-Guard-2-86M` | **manual** | Llama 4 Community | mDeBERTa | en fr de hi it pt es th, **no fi** |

Two were excluded before measurement rather than after:

- **Llama Prompt Guard 2** is gated behind manual approval of the Llama 4
  Community License. Accepting a bespoke licence with an acceptable-use
  policy on someone else's behalf is not a decision this commit can make. It
  is also not evaluated on Finnish.
- **qualifire/prompt-injection-sentinel** is auto-gated and licensed
  "other".

The three measured are ungated and permissively licensed, so the benchmark
is reproducible by anyone who runs the command.

ProtectAI's card is worth quoting, because it is the honest version of what
all of them are: the model *"does not detect jailbreak attacks or handle
non-English prompts."* It is the most-downloaded prompt-injection classifier
on the Hub by two orders of magnitude, and it says it does not do this.

### A model that does not exist

A web search for multilingual prompt-injection classifiers returned
`Horizon-Labs/prompt-injection-guard-multilingual`, described confidently
with a 17-language list, an Apache licence and a named training corpus. **It
does not exist** — the Hub API returns 401 and the organisation publishes
only `-base` and `-small`.

It nearly entered a licence review as a fact. Every row in the table above
is from `huggingface.co/api/models/...`, including the revision shas, which
is why the review is checkable rather than recalled.

### English scores are not inherited

All three publish strong English benchmark numbers. None appears here, is
compared against, or informs any conclusion. Every figure below is measured
on Finnish, which is the whole point of the criterion.

---

## The measurement — C39-AC2

436 development cases, the same split and the same labels as the C26 hosted
run. Apple M2, 8 cores, 8 GiB, macOS 13.5, **CPU only**, torch 2.11.0 and
transformers 5.19.0 as pinned in `detector/uv.lock`.

| | recall | false-positive rate | p50 | peak RSS | load |
|---|---|---|---|---|---|
| **claude-opus-5** (hosted, C26) | **0.962** [0.870, 0.995] | **0.000** [0.000, 0.010] | 2 833 ms | — | — |
| Horizon-Labs mmBERT | 0.679 [0.537, 0.801] | 0.018 [0.007, 0.037] | **50 ms** | 695 MB | 1.7 s |
| proventra mDeBERTa | 0.641 [0.498, 0.769] | 0.050 [0.030, 0.076] | 69 ms | 617 MB | 1.4 s |
| ProtectAI DeBERTa (en) | 0.623 [0.479, 0.752] | 0.125 [0.094, 0.163] | 70 ms | 614 MB | 4.6 s |

**Every one misses the recall gate**, and not marginally - no interval
reaches 0.802, against a threshold of 0.90. Two also miss the
false-positive gate outright. The third, Horizon-Labs, is the one place a
careful reading matters: at 0.018 [0.007, 0.037] its interval **spans** the
0.01 threshold, so that gate is `undetermined` rather than failed - 383
benign cases cannot decide it, and even a run with no false positives at
all would need 368 of them. The verdicts come from the same shared rule as
the C30 gate report, which is how the distinction survives.

An earlier version of this benchmark had its own two-outcome gate check and
reported that row as "failed". The three-outcome rule is in `evals/metrics.py`
precisely so a reimplementation cannot quietly make a claim the data does
not support - and the reimplementation made exactly the stronger claim.

Counted rather than rated:

| | attacks caught | benign falsely flagged |
|---|---|---|
| hosted | 51 / 53 | 0 / 383 |
| Horizon-Labs | 36 / 53 | 7 / 383 |
| proventra | 34 / 53 | 19 / 383 |
| ProtectAI | 33 / 53 | **48 / 383** |

### What the numbers say

**An English-only classifier flags one Finnish passage in eight.** ProtectAI
wrongly flagged 48 of 383 ordinary Finnish passages. Its card said it would.
This is the concrete version of "do not substitute English benchmark scores":
on its own language it is excellent, and here it would refuse an eighth of
legitimate traffic.

**A multilingual base helps false positives and barely helps recall.** As the
base model gets more multilingual — DeBERTa, mDeBERTa, mmBERT — the
false-positive rate falls 0.125 → 0.050 → 0.018, a sevenfold improvement.
Recall moves 0.623 → 0.641 → 0.679, which is almost nothing. Pretraining on
Finnish teaches a model what ordinary Finnish looks like; it does not teach
it what a Finnish *attack* looks like, and none of these was fine-tuned on
one.

**Local is 40 to 57 times faster and free per call.** 50 ms against
2 833 ms, with no provider, no network and no USD 0.009. Loading costs 1.4
to 4.6 seconds once, and the resident cost is 614 to 695 MB for the life of
the process. That is the entire case for local inference, and it is a real
one — which is why the quality gap has to be stated precisely rather than
waved at.

**None of them can abstain.** These are two-label classifiers. The hosted
detector can return `uncertain`, and policy turns that into a flag rather
than an allow; a model that cannot say "I do not know" answers confidently on
input it has never seen, which is this corpus. Reported as
`"can_abstain": false` rather than as an uncertainty rate of zero, because
those are different claims.

**No passage was truncated** at the 512-token limit — the corpus maximum is
510 characters. At the service's real ceiling of ~5 324 characters every one
of these models would silently truncate, which the adapter records but which
this corpus could not exercise.

---

## Why no cascade — C39-AC3

The obvious use of a 50 ms free classifier is a screen: run it first, call
the provider only when it says suspicious. The arithmetic, from the measured
numbers:

| screen | hosted calls saved | attacks missed outright |
|---|---|---|
| Horizon-Labs | **90.1%** | **17 of 53 (32%)** |
| proventra | 87.8% | 19 of 53 (36%) |
| ProtectAI | 81.4% | 20 of 53 (38%) |

A cascade's recall is bounded by its screen's recall, because a passage the
screen calls clean is never seen by anything that could disagree. So the
trade is **a 90% cost reduction for losing a third of detections** — on a
guard whose entire purpose is the detections.

The reverse arrangement — let the local model *block* and skip the provider
on a positive — is worse in a different direction: it would add false blocks
on ordinary Finnish, somewhere in 0.7% to 3.7%, with no second opinion and
against a gate of 1%. The interval is the answer there too: the measurement
cannot even tell whether that arrangement would clear the gate.

Neither is adopted. **Quantization and ONNX are not evaluated either**, for
the reason AC3 implies: they are optimisations of inference, and there is no
quality here worth making faster. A 50 ms model that misses a third of
attacks does not become useful at 20 ms.

---

## What would change this

1. **Fine-tuning on Finnish.** The gap is a training-data gap, not a
   capability one — mmBERT clearly understands Finnish well enough to stop
   flagging it, and simply has not been shown Finnish attacks. The corpus
   now exists: 930 cases, 117 attacks. That is small for fine-tuning and not
   obviously too small, and it is a different project with its own
   evaluation and its own holdout discipline.
2. **A classifier that declares Finnish.** None exists today. The review
   command in this document is cheap to re-run.
3. **A different role than screening.** A local model that cannot be trusted
   to skip a provider call could still be trusted to *add* one — flagging
   for review what the hosted path allowed. That inverts the risk: a false
   positive costs attention rather than availability. Unmeasured, and the
   only direction in these numbers that looks promising.

---

## What this does not establish

1. **Three models, not the field.** Chosen for being ungated and permissively
   licensed; two plausible candidates were excluded on licence grounds, and
   one of them has a multilingual base that might do better.
2. **No fine-tuning was attempted**, so the result is about these artifacts
   as published, not about what a small local model could do.
3. **CPU only, one machine.** A GPU changes the latency column and nothing
   else; the quality numbers are hardware-independent.
4. **Default thresholds.** Each model's decision boundary is 0.5. Tuning a
   threshold per model would trade recall against false positives along each
   model's own curve, and raising recall moves the wrong way on a
   false-positive gate that is already undecided for the best model. The
   best false-positive rate and the best recall are the same model, so there
   is no second candidate whose curve might pass nearer to both.
5. **Development split only.** Comparing against the hosted C26 numbers
   requires the same cases; the holdout remains unread by anything,
   including this.
