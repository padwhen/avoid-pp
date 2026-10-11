# C35 — failure and rollback runbooks

> **C35-AC1** Runbooks explain provider outage, elevated false positives,
> rate exhaustion, model drift and token-limit failures.
> **C35-AC2** A rollback identifies the prior model, prompt and policy
> versions together with compatible contracts.
> **C35-AC3** Raw passages are not retained by default; any diagnostic opt-in
> has an owner, access controls and expiration.

```sh
deploy/kubernetes/smoke.sh up
deploy/kubernetes/runbooks.sh     # 18 checks, all passing
```

**A runbook nobody has run is a guess written in the imperative mood.** Every
command below appears in `runbooks.sh`, which asserts what the procedure
claims will happen. Two of the drills failed first, for reasons recorded at
the end.

---

## 1. Provider outage

**Symptom.** Scans return `503` with `"code":"detector_unavailable"`. In the
metrics:

```promql
rate(avoidpp_scans_total{outcome="detector_unavailable"}[5m]) > 0
```

**First: confirm it is the dependency and not capacity.** These reach a
caller identically and have opposite remedies.

```promql
rate(avoidpp_scans_total{outcome="shed"}[5m])    # capacity - see runbook 3
rate(avoidpp_scans_total{outcome="detector_unavailable"}[5m])
```

**Check the detector directly.** It is not publicly reachable by design, so
this is from inside the cluster:

```sh
kubectl -n avoid-pp get pods -l app=detector
kubectl -n avoid-pp logs deploy/detector --tail=50
kubectl -n avoid-pp get events --sort-by=.lastTimestamp | tail -20
```

**What is already true, and does not need an operator.** Drilled:

- the gateway reports `detector_unavailable` and **never produces an allow**;
- it recovers on its own when the detector returns — **no gateway restart**;
- `/readyz` on the gateway stays **ready**.

That last one is deliberate and the instinct runs the other way. Failing
readiness during a dependency outage would have Kubernetes withdraw the
endpoint, and callers would get connection errors instead of a structured
`detector_unavailable` they can act on. Every replica shares the same
detector, so failing readiness everywhere converts a legible refusal into an
opaque outage. The gateway is healthy; its dependency is not, and the
response says so.

**If the detector is crash-looping**, check readiness rather than liveness:
`/healthz` makes no external call precisely so a provider outage cannot
restart the pod into a crash loop.

**Do not** switch to monitoring mode to "get traffic flowing". A scan that
did not happen is not an allow, and the mode does not change that — it
changes what happens to a *suspicious* verdict, not to a missing one.

---

## 2. Elevated false positives

**Symptom.** Legitimate Finnish is being flagged or blocked.

```promql
# Flag rate, which is the number that matters in monitoring mode.
  sum(rate(avoidpp_decisions_total{action="flag"}[1h]))
/ sum(rate(avoidpp_decisions_total[1h]))

# Split by why: a suspicious label and an uncertain one are different bugs.
sum by (label) (rate(avoidpp_decisions_total{action!="allow"}[1h]))
```

C26 measured a false-positive rate of 0.0 with a 95% upper bound of 0.0096 on
383 development benign cases. **A sustained flag rate materially above 1% on
benign-looking traffic is outside what was measured**, and is the trigger for
this runbook.

**First, establish what changed**, because the detector is a model and the
model is not the only thing that moves:

```sh
# The deployed triple, from any response. See runbook 4.
kubectl -n avoid-pp get deploy/gateway -o jsonpath='{.spec.template.spec.containers[0].env}'
```

| if this changed | then |
|---|---|
| `prompt` | roll back the prompt version — runbook 6 |
| `detector` (model) | roll back the model — runbook 6 |
| `policy` | a mode change turns flags into blocks; it does not create them |
| nothing | the **traffic** changed, not the service |

That last row is the common one and the easiest to misdiagnose. A new caller
sending a different kind of Finnish is not a regression in the guard.

**The response is a rollback, not a threshold.** There is no tunable
sensitivity in this service, deliberately: the detector returns a label and
policy maps it to an action. Loosening would mean editing the prompt, which
is a new version requiring its own measurement — `prompts/__init__.py` makes
each version immutable once a measurement exists against it.

**Collecting evidence without retaining passages** is the awkward part. See
runbook 7: there is no diagnostic capture, so a false positive is
investigated from the `content_id` the caller supplied and their own records,
not from anything this service stored.

---

## 3. Rate exhaustion

**Symptom.** Callers see `429` with `"code":"rate_limited"`.

**This is the service working.** The limits are a spend bound before they are
a fairness mechanism: at USD 0.0090 a scan, the shipped global ceiling is
about USD 1 145 a day. Drilled:

- a 12-request burst against the 1/s limit was refused 7 times;
- every refusal carried `Retry-After: 1`;
- the caller recovered once the bucket refilled, **with no operator action**.

**Decide which of three things is happening:**

```promql
rate(avoidpp_errors_total{code="rate_limited"}[5m])   # the limiter
rate(avoidpp_errors_total{code="overloaded"}[5m])     # admission
```

| | meaning | action |
|---|---|---|
| `rate_limited` only | a caller is sending too fast | tell the caller; they have `Retry-After` |
| `overloaded` too | the service cannot keep up | runbook 3b below |
| both at once | the limits are inconsistent | C32 aligned them; re-derive before changing either |

**3b — raising the limits is a spend decision.** The admission ceiling is
`MaxActive / provider p50` = 4 / 2.833 s = **1.41 scans per second**. Raising
the rate limit above that does not add capacity; it converts `429` into
`503 overloaded`, which reads as a capacity incident rather than a caller
problem. Raise `AVOIDPP_MAX_ACTIVE` first, and read the cost before doing so:

```sh
kubectl -n avoid-pp set env deploy/gateway AVOIDPP_MAX_ACTIVE=8
# 8 / 2.833s = 2.82 scans/sec = about USD 2,190/day sustained.
```

The coherence tests in `gateway/internal/config` will refuse a combination
that lets a queued request start a provider call it cannot finish.

---

## 4. Model drift

**Symptom.** Behaviour changed and nothing was deployed.

**Every response says what produced it.** Drilled — the triple is on every
scan:

```json
"versions": {"contract":"1.0.0","detector":"fake-0","prompt":"none","policy":"monitoring-1"}
```

In live mode `detector` is `claude:claude-opus-5` and the detector's own
response carries `prompt_fingerprint`, a SHA-256 over both halves of the
prompt. That is what makes drift *detectable* rather than suspected: a
version name cannot prove which bytes ran, and a fingerprint can.

**Compare against the measurement.** The C26 development run — the one the
gate report's numbers come from — is pinned to:

| | |
|---|---|
| model | `claude-opus-5` |
| prompt | `translate_fi_en-v1` |
| fingerprint | `5f42eb70d04f6fc5579e7e709ed7b5810afbdfef8e42d2937ee4ade63f16210a` |
| contract | `1.0.0` |

```sh
make provenance      # the corpus those numbers are a claim about
make check-gate-report
```

**If the fingerprint differs from the above, the published rates do not
describe what is deployed.** That is not necessarily an incident — adopting
`translate_fi_en-v2` is a deliberate choice — but it means the gate report is
stale and says so.

**If nothing on this side changed**, the provider moved. There is no version
pin available for a hosted model beyond the model name, which is a real
limitation and the main argument C39 would weigh for a local classifier.
Re-run the development evaluation (~USD 4.10) and compare; that is the only
instrument this project has.

---

## 5. Token-limit failures

**Symptom.** A caller reports failures on long passages.

Four bounds apply to one passage, in three units, and **the tightest is far
below the documented one**:

| | value | unit |
|---|---|---|
| `contract.MaxTextChars` | 32 768 | characters (the public schema) |
| `api.MaxRequestBytes` | 65 536 | bytes (gateway body cap) |
| `limits.MAX_PASSAGE_BYTES` | 32 768 | bytes (detector) |
| `limits.DEFAULT_MAX_SOURCE_TOKENS` | **4 096** | tokens (detector) — **binds first** |

The effective maximum is about **5 324 characters, 16% of the advertised
32 768**.

**What the caller should see:** `422` with `"code":"token_budget_exceeded"`,
or `413 payload_too_large` for the byte ceiling. Both are permanent and
caller-fixable.

**What they used to see:** `503 detector_unavailable` — a permanent sizing
error dressed as a transient outage, which a well-behaved client retries
forever. Fixed at C32. The drill asserts the regression has not returned:

```
PASS fake mode has no token budget and scans it; not mistaken for an outage
```

**If a caller is hitting this, they chunk — because there is nothing an
operator can change.**

Writing this runbook turned up that the token budget is **not configurable at
runtime**. `DEFAULT_MAX_SOURCE_TOKENS` is a constant in
`detector/src/translation_guard/limits.py`, `Settings` has no field for it,
and the Claude adapter constructs `Budget()` with no override. So the one
limit an operator is most likely to want to move is the one that needs a code
change, a rebuild and a deploy.

The first draft of this runbook told an operator to set
`AVOIDPP_DETECTOR_MAX_SOURCE_TOKENS`, which does not exist. A runbook naming a
variable that is not read is worse than no runbook: it sends someone to edit a
Deployment, watch the pod roll, and conclude the limit did not take effect for
some other reason.

Raising it is in any case a product decision rather than an operational one,
and costs linearly: a ceiling-sized scan at the full 32 768 characters would
be roughly USD 0.13, about 14× a typical one. Recorded as open in
[C32](c32-capacity.md). Until then the honest instruction is "chunk at 5 000
characters", and `MAX_ACTIVE` / `MAX_WAITING` remain the detector settings
that *are* configurable:

```sh
kubectl -n avoid-pp set env deploy/detector AVOIDPP_DETECTOR_MAX_ACTIVE=16
```

---

## 6. Rollback — C35-AC2

**What has to move together.** A rollback that restores one of these and not
the others produces a configuration that was never measured:

| | where it lives | how to read it live |
|---|---|---|
| **model** | `AVOIDPP_DETECTOR_MODEL` on the detector | `versions.detector` |
| **prompt** | `prompts.DEFAULT_VERSION` in the image | `versions.prompt` + fingerprint |
| **policy** | `AVOIDPP_POLICY_MODE` on the gateway | `versions.policy` |
| **contract** | compiled into both | `versions.contract` |

**The contract is the compatibility constraint.** Both services implement
`1.0.0`, asserted from both sides: `detector/tests/test_contract_parity.py`
reads the normative schema, `gateway/internal/detector/parity_test.go` does
the same, and both SDK clients check it. **Rolling one service back across a
contract version requires rolling the other too** — the gateway decodes the
detector's response with `DisallowUnknownFields`, so a mismatch is a
`detector_unavailable`, not a silent degradation. That is the failure mode
C28 found the expensive way.

**Procedure.** Drilled end to end, including reading the result from a live
response rather than from the manifest:

```sh
# 1. Record what is deployed, from a response and not from the spec.
curl -s -X POST "$GATEWAY/v1/scans" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d "$BODY" | jq .versions

# 2. Identify the revision to return to.
kubectl -n avoid-pp rollout history deploy/gateway

# 3. Undo. Without --to-revision this is the immediately previous one.
kubectl -n avoid-pp rollout undo deploy/gateway
kubectl -n avoid-pp rollout status deploy/gateway --timeout=180s

# 4. Confirm from a response, not from the spec. A spec that says
#    monitoring and a service answering enforcement is the case worth
#    catching, and only step 4 catches it.
curl -s ... | jq .versions
```

Drilled result:

```
PASS the change is visible in the response: monitoring-1 -> enforcement-1
PASS rollback restored policy monitoring-1, confirmed from a live response
```

**A rolled-back deployment drops no requests**, because `maxUnavailable: 0`
and `AVOIDPP_PREDRAIN` apply to an undo exactly as they do to a rollout —
C34 measured 40 requests across a rolling restart with zero dropped.

**Rolling back a credential is a different procedure**: changing the Secret
does nothing until the deployment is rolled. See C34's rotation drill.

---

## 7. Retention and privacy defaults — C35-AC3

**No raw passage is retained anywhere, and this is enforced rather than
promised.** Drilled:

```
PASS the gateway cannot write to its filesystem
PASS the detector cannot write to its filesystem
PASS the only volume is an emptyDir that dies with the pod (tmp=16Mi)
PASS no passage appears in 200 lines of gateway log
```

| | retained? | mechanism |
|---|---|---|
| the passage | **no** | never logged (C23 allowlist); no writable filesystem |
| evidence quotations | **no** | returned to the caller, never logged |
| the API key | **no** | compared as a SHA-256 digest; redacted in every rendering |
| trace and request ids | yes, in logs | generated or strictly validated; bounded |
| sizes, labels, actions, durations | yes, in logs and metrics | counts and enum members |

Three independent mechanisms, because one would be a policy and three are a
property:

1. **The log handler allowlists field names** (C23). A field not on the list
   is dropped and the drop is reported.
2. **Metric label values are enumerated at compile time** (C33). An
   undeclared value becomes `other`; cardinality is 350 series and no input
   can raise it.
3. **Neither container can write to disk** (C34). `readOnlyRootFilesystem`,
   and the detector's only volume is a 16 MiB `emptyDir` that dies with the
   pod.

### There is no diagnostic opt-in

AC3 requires any opt-in to have an owner, access controls and expiration.
**There is none**, so the requirement is satisfied by absence — and that is
worth stating as a decision rather than an oversight, because the absence is
what makes runbook 2 awkward: a false positive cannot be investigated from
captured text, only from the caller's `content_id` and their own records.

If one were added, it would need, at minimum: a named owner; an explicit
per-caller opt-in rather than a global flag; a retention expiry enforced by
deletion rather than by policy; access control separate from the service's
own credentials; and a scan response that *says* the passage was captured,
so the caller knows. None of that exists and none of it should be added
casually — the service processes attacker-chosen text, and a diagnostic
store is a place that text accumulates.

**The evaluation corpus is a separate matter and is deliberately synthetic.**
All 870 cases are `rights: synthetic-authored`. The C29 reports do contain
model outputs, which is why they are committed under `evals/reports/milestones/`
as evidence rather than being production data. No real user text has ever
entered this project.

---

## The drills that failed first

Two failures, both in the harness, and both worth recording because each
produced a plausible wrong conclusion.

**`error: Invalid JSON Patch`, reported as "the quota is not being
enforced".** The rate-limit drill built its pod command inline into
`--overrides` JSON, and `tr -d '\r'` put a raw control character into a JSON
string. The pod never ran, the drill saw no 429s, and it reported a security
finding. A harness failure wearing a security finding's clothes is the worst
kind. Both affected drills now avoid backslashes entirely — the burst uses
curl's own `-w '%header{retry-after}'` rather than grep and tr, and the long
passage is built in the parent shell.

**The same error in the oversize drill**, from nested `awk` quoting, with the
same shape of wrong conclusion available.

Neither was a failure of the service. Both were failures of the thing
checking the service, which is the argument for drills that can fail loudly
rather than runbooks that cannot fail at all.

**And one failure in the prose, which no drill caught.** Runbook 5 originally
told an operator to raise `AVOIDPP_DETECTOR_MAX_SOURCE_TOKENS`. There is no
such variable — the token budget is a constant in `limits.py` with no
`Settings` field behind it. The drills exercise commands that *are* in the
script; a wrong command in the document alone slips through, which is the
residual risk of this whole approach and the reason every env var named here
was checked against the code rather than remembered.
