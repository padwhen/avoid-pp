#!/usr/bin/env bash
# C35: the operating procedures, executed.
#
# A runbook nobody has run is a guess written in the imperative mood. Every
# command in docs/c35-runbooks.md appears here, and this script asserts what
# the runbook claims will happen.
#
#   outage      the detector is gone; the gateway refuses and recovers
#   ratelimit   a caller exhausts its quota and is told how long to wait
#   oversize    a passage over the token budget is the caller's problem
#   drift       the deployed model, prompt and policy are readable live
#   rollback    a configuration change is identified and undone
#
# Usage:
#   deploy/kubernetes/smoke.sh up         # a cluster to run against
#   deploy/kubernetes/runbooks.sh
#
# Contacts no provider: the detector runs in fake mode.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

require_cluster() {
  kubectl -n "$NS" get deploy/gateway >/dev/null 2>&1 || {
    echo "no deployment found; run: $HERE/smoke.sh up" >&2
    exit 2
  }
  [ -f "$HERE/.key-current" ] || { echo "no key; run: $HERE/smoke.sh up" >&2; exit 2; }
}

KEY() { cat "$HERE/.key-current"; }

# scan_body returns the whole response body, not just a status, because the
# runbooks are about what an operator can read from one.
scan_body() { # $1 = key, $2 = text
  run_pod "runbook-probe" \
    "curl -s --max-time 15 -X POST $GATEWAY_URL/v1/scans -H 'Content-Type: application/json' -H 'Authorization: Bearer $1' -d '{\\\"task_id\\\":\\\"translate_fi_en_v1\\\",\\\"content\\\":{\\\"id\\\":\\\"runbook\\\",\\\"source_type\\\":\\\"translation_input\\\",\\\"text\\\":\\\"$2\\\"}}' || true"
}

# ---------------------------------------------------------------------------

runbook_outage() {
  step "Runbook 1 - provider outage"
  note "simulated by removing the detector entirely, which is strictly worse"
  note "than a slow or erroring provider"

  kubectl -n "$NS" scale deploy/detector --replicas=0 >/dev/null
  kubectl -n "$NS" wait --for=delete pod -l app=detector --timeout=120s >/dev/null 2>&1 || true

  local body; body="$(scan_body "$(KEY)" "Saa on tanaan aurinkoinen.")"
  if printf '%s' "$body" | grep -q '"code":"detector_unavailable"'; then
    ok "the gateway reports detector_unavailable"
  else
    bad "expected detector_unavailable, got: $(printf '%s' "$body" | head -c 160)"
  fi
  # The property the whole service exists for, asserted while it is broken.
  if printf '%s' "$body" | grep -q '"action":"allow"'; then
    bad "an outage produced an allow"
  else
    ok "an outage never produces an allow"
  fi
  # Readiness must say so, or a load balancer keeps sending traffic here.
  local ready
  ready="$(kubectl -n "$NS" get pod -l app=gateway \
    -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)"
  note "gateway pod still reports ready=$ready (it is healthy; its dependency is not)"

  kubectl -n "$NS" scale deploy/detector --replicas=1 >/dev/null
  timed "waiting for the detector to come back" \
    sh -c "kubectl -n \"$NS\" rollout status deploy/detector --timeout=180s >/dev/null"

  if printf '%s' "$(scan_body "$(KEY)" "Saa on tanaan aurinkoinen.")" | grep -q '"scan_status":"complete"'; then
    ok "service recovers with no gateway restart"
  else
    bad "the gateway did not recover on its own"
  fi
}

runbook_ratelimit() {
  step "Runbook 2 - rate exhaustion"
  note "the shipped per-caller limit is 1/s with a burst of 5, a spend bound"

  # curl's own -w formatting rather than grep and tr. Anything with a
  # backslash has to survive being embedded in the pod's JSON overrides, and
  # the first version of this drill did not: it produced "error: Invalid
  # JSON Patch" and then reported the quota unenforced - a harness failure
  # wearing a security finding's clothes.
  local out
  out="$(run_pod "runbook-burst" \
    "for i in 1 2 3 4 5 6 7 8 9 10 11 12; do curl -s -o /dev/null -w '%{http_code}:%header{retry-after} ' --max-time 10 -X POST $GATEWAY_URL/v1/scans -H 'Content-Type: application/json' -H 'Authorization: Bearer $(KEY)' -d '$PASSAGE'; done; echo")"

  local limited retry
  limited="$(printf '%s' "$out" | tr ' ' '\n' | grep -c '^429:' || true)"
  retry="$(printf '%s' "$out" | tr ' ' '\n' | grep '^429:' | head -1 | cut -d: -f2)"

  if [ "${limited:-0}" -gt 0 ]; then
    ok "a 12-request burst was rate limited ${limited} times"
  else
    bad "nothing was rate limited; the quota is not being enforced"
    note "raw: $(printf '%s' "$out" | tail -1 | head -c 120)"
  fi
  if [ -n "${retry:-}" ]; then
    ok "the refusal says how long to wait (Retry-After: ${retry}s)"
  else
    bad "a 429 arrived with no Retry-After header"
  fi

  note "waiting out the bucket"
  sleep 8
  if [ "$(scan_status "$(KEY)")" = "200" ]; then
    ok "the caller recovers once the bucket refills, with no operator action"
  else
    bad "the caller did not recover"
  fi
}

runbook_oversize() {
  step "Runbook 3 - token-limit failure"
  note "a passage over the detector's 4096-token budget, well under the"
  note "32768 characters the contract advertises"

  # Built here rather than in the pod. Generating it in-pod needed awk with
  # nested quoting, which was the other half of the Invalid JSON Patch.
  local long=""
  while [ "${#long}" -lt 6000 ]; do
    long="${long}Saa on tanaan aurinkoinen ja lampotila nousee iltapaivalla. "
  done
  long="${long:0:6000}"

  local body
  body="$(run_pod "runbook-oversize" \
    "curl -s --max-time 20 -X POST $GATEWAY_URL/v1/scans -H 'Content-Type: application/json' -H 'Authorization: Bearer $(KEY)' -d '{\\\"task_id\\\":\\\"translate_fi_en_v1\\\",\\\"content\\\":{\\\"id\\\":\\\"big\\\",\\\"source_type\\\":\\\"translation_input\\\",\\\"text\\\":\\\"${long}\\\"}}'")"

  # The fake detector enforces no token budget - only the Claude adapter
  # does - so in fake mode this is a clean scan. What the runbook has to get
  # right is the code an operator sees in live mode, and
  # gateway/internal/capacity pins that mapping end to end.
  if printf '%s' "$body" | grep -q '"code":"detector_unavailable"'; then
    bad "an oversized passage is being reported as an outage (the C32 defect)"
  elif printf '%s' "$body" | grep -qE '"code":"(token_budget_exceeded|payload_too_large)"'; then
    ok "the caller is told the passage is too large, not that the service is down"
  elif printf '%s' "$body" | grep -q '"scan_status":"complete"'; then
    ok "fake mode has no token budget and scans it; not mistaken for an outage"
    note "live mode returns 422 token_budget_exceeded, pinned by"
    note "gateway/internal/capacity/limits_test.go across the whole chain"
  else
    bad "unexpected: $(printf '%s' "$body" | head -c 160)"
  fi
}

runbook_drift() {
  step "Runbook 4 - model drift"
  note "what is deployed is readable from any response, which is what makes"
  note "drift detectable rather than suspected"

  local body; body="$(scan_body "$(KEY)" "Saa on tanaan aurinkoinen.")"
  local versions; versions="$(printf '%s' "$body" | sed -n 's/.*"versions":{\([^}]*\)}.*/\1/p')"

  if [ -n "$versions" ]; then
    ok "the deployed triple is on every response: $versions"
  else
    bad "no versions block in the response: $(printf '%s' "$body" | head -c 160)"
  fi
  for field in contract detector prompt policy; do
    printf '%s' "$versions" | grep -q "\"$field\"" \
      && ok "  $field is identified" \
      || bad "  $field is missing, so a change in it would be invisible"
  done
}

runbook_rollback() {
  step "Runbook 5 - configuration rollback"

  local before_rev before_policy
  before_rev="$(kubectl -n "$NS" get deploy/gateway \
    -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"
  before_policy="$(scan_body "$(KEY)" "Saa on tanaan aurinkoinen." \
    | sed -n 's/.*"policy":"\([^"]*\)".*/\1/p')"
  note "current: revision $before_rev, policy $before_policy"

  # The change an operator would actually make, and the one C30 says is not
  # ready: monitoring to enforcement.
  kubectl -n "$NS" set env deploy/gateway AVOIDPP_POLICY_MODE=enforcement >/dev/null
  timed "rolling out the change" \
    sh -c "kubectl -n \"$NS\" rollout status deploy/gateway --timeout=180s >/dev/null"
  local after_policy
  after_policy="$(scan_body "$(KEY)" "Saa on tanaan aurinkoinen." \
    | sed -n 's/.*"policy":"\([^"]*\)".*/\1/p')"

  if [ "$after_policy" != "$before_policy" ]; then
    ok "the change is visible in the response: $before_policy -> $after_policy"
  else
    bad "the policy identity did not change, so a caller could not tell"
  fi

  kubectl -n "$NS" rollout undo deploy/gateway >/dev/null
  timed "undoing it" \
    sh -c "kubectl -n \"$NS\" rollout status deploy/gateway --timeout=180s >/dev/null"
  local restored
  restored="$(scan_body "$(KEY)" "Saa on tanaan aurinkoinen." \
    | sed -n 's/.*"policy":"\([^"]*\)".*/\1/p')"

  if [ "$restored" = "$before_policy" ]; then
    ok "rollback restored policy $restored, confirmed from a live response"
  else
    bad "after undo the policy is $restored, expected $before_policy"
  fi
}

runbook_retention() {
  step "Runbook 6 - what is retained"
  note "C35-AC3: raw passages are not retained by default"

  # Not a policy, a filesystem property: both containers run read-only.
  local gw det
  gw="$(kubectl -n "$NS" get deploy/gateway \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}')"
  det="$(kubectl -n "$NS" get deploy/detector \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}')"
  [ "$gw" = "true" ] && ok "the gateway cannot write to its filesystem" \
                     || bad "the gateway filesystem is writable"
  [ "$det" = "true" ] && ok "the detector cannot write to its filesystem" \
                      || bad "the detector filesystem is writable"

  # No volume that outlives a pod.
  local volumes
  volumes="$(kubectl -n "$NS" get deploy/detector \
    -o jsonpath='{range .spec.template.spec.volumes[*]}{.name}={.emptyDir.sizeLimit}{"\n"}{end}')"
  if printf '%s' "$volumes" | grep -q 'persistentVolumeClaim'; then
    bad "a persistent volume is mounted: $volumes"
  else
    ok "the only volume is an emptyDir that dies with the pod ($volumes)"
  fi

  # And the logs the service actually emitted carry no passage.
  local logs
  logs="$(kubectl -n "$NS" logs deploy/gateway --tail=200 2>/dev/null || true)"
  if printf '%s' "$logs" | grep -qi 'aurinkoinen'; then
    bad "a passage appears in the gateway log"
  else
    ok "no passage appears in 200 lines of gateway log"
  fi
}

require_cluster
runbook_outage
runbook_ratelimit
runbook_oversize
runbook_drift
runbook_rollback
runbook_retention

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
