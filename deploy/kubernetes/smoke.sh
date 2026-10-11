#!/usr/bin/env bash
# C34-AC3: readiness, termination, secret rotation and rollback, exercised
# against a real cluster rather than described.
#
# Four drills, each of which can fail, and one of which found something.
#
#   isolation  a pod that is not the gateway cannot reach the detector
#   drain      a rollout drops no request
#   rotation   a changed Secret takes effect, and only after a roll
#   rollback   the previous revision comes back and serves
#
# Usage:
#   deploy/kubernetes/smoke.sh up      create the cluster and deploy
#   deploy/kubernetes/smoke.sh drills  run the four drills
#   deploy/kubernetes/smoke.sh down    delete the cluster
#   deploy/kubernetes/smoke.sh all     all three, in order
#
# Needs docker, kind and kubectl. Touches nothing outside the kind cluster
# named below and contacts no provider: the detector runs in fake mode.
set -euo pipefail

# Pinned. A CNI that silently changes behaviour between runs would make the
# isolation drill meaningless.
CALICO="${CALICO:-https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

up() {
  step "Building images"
  note "a cold Docker cache takes a minute or two; a warm one is seconds"
  timed "gateway " docker build -q -t avoid-pp/gateway:local "$ROOT/gateway"
  timed "detector" docker build -q -t avoid-pp/detector:local "$ROOT/detector"

  step "Creating cluster (no default CNI)"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  timed "kind create" sh -c "kind create cluster --config \"$HERE/kind-cluster.yaml\" >/dev/null 2>&1"

  step "Installing Calico"
  # kindnet accepts NetworkPolicy and enforces none of it, which would make
  # the isolation drill report a pass it did not earn.
  note "pinned to $(basename "$(dirname "$CALICO")")"
  timed "applying manifest" sh -c "kubectl apply -f \"$CALICO\" >/dev/null"
  timed "waiting for calico-node" \
    sh -c "kubectl -n kube-system rollout status ds/calico-node --timeout=300s >/dev/null"
  timed "waiting for the node" \
    sh -c "kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null"

  step "Deploying"
  timed "loading images into the cluster" \
    sh -c "kind load docker-image avoid-pp/gateway:local avoid-pp/detector:local --name \"$CLUSTER\" >/dev/null 2>&1"
  timed "applying manifests" sh -c "kubectl apply -f \"$HERE/00-namespace.yaml\" -f \"$HERE/20-detector.yaml\" -f \"$HERE/30-gateway.yaml\" -f \"$HERE/40-networkpolicy.yaml\" >/dev/null"

  # The Secret is created here rather than committed. The gateway refuses to
  # start without it, which is C19 behaving correctly and is why the
  # deployment above is briefly in CreateContainerConfigError.
  KEY1="$(openssl rand -hex 24)"
  echo "$KEY1" > "$HERE/.key-current"
  kubectl -n "$NS" delete secret avoidpp-gateway --ignore-not-found >/dev/null
  kubectl -n "$NS" create secret generic avoidpp-gateway \
    --from-literal=AVOIDPP_API_KEYS="pilot:translate_fi_en_v1:${KEY1}" >/dev/null

  kubectl -n "$NS" rollout restart deploy/gateway >/dev/null
  timed "waiting for the detector" \
    sh -c "kubectl -n \"$NS\" rollout status deploy/detector --timeout=180s >/dev/null"
  timed "waiting for the gateway " \
    sh -c "kubectl -n \"$NS\" rollout status deploy/gateway --timeout=180s >/dev/null"
  echo
  kubectl -n "$NS" get pods
}

drill_isolation() {
  step "Drill 1 - the detector accepts only the gateway"
  local code
  code="$(run_pod netpol-probe \
    "curl -s -o /dev/null -w %{http_code} --max-time 5 $DETECTOR_URL/healthz || true" \
    | tail -1)"

  if [ "$code" = "200" ]; then
    bad "a pod that is not the gateway reached the detector (HTTP $code)"
    echo "       NetworkPolicy is present and not enforced. Check the CNI:"
    echo "       kindnet accepts these objects and ignores them."
  else
    ok "a pod that is not the gateway cannot reach the detector (got $code)"
  fi

  if [ "$(scan_status "$(cat "$HERE/.key-current")")" = "200" ]; then
    ok "the gateway still reaches the detector"
  else
    bad "the policy also blocked the gateway"
  fi
}

# The drain hammer runs as a pod for the same reason the one-shot probes do,
# and because it has to survive the very rollout it is measuring.
HAMMER=drain-hammer

hammer_start() { # $1 = key, $2 = how many requests
  kubectl -n "$NS" delete pod "$HAMMER" --ignore-not-found --wait=true >/dev/null 2>&1
  kubectl -n "$NS" run "$HAMMER" --restart=Never --image="$CURL_IMAGE" \
    --overrides="$(hardened "$HAMMER" "t=0; f=0; r=0; while [ \$t -lt $2 ]; do t=\$((t+1)); c=\$(curl -s -o /dev/null -w %{http_code} --max-time 10 -X POST $GATEWAY_URL/v1/scans -H 'Content-Type: application/json' -H 'Authorization: Bearer $1' -d '$PASSAGE' || true); if [ \\\"\$c\\\" = 429 ]; then r=\$((r+1)); elif [ \\\"\$c\\\" != 200 ]; then f=\$((f+1)); fi; sleep 1; done; echo \\\"\$t \$f \$r\\\"")" \
    >/dev/null
}

hammer_result() {
  kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$HAMMER" \
    --timeout=300s >/dev/null 2>&1 || true
  kubectl -n "$NS" logs "$HAMMER" 2>/dev/null | tail -1
  kubectl -n "$NS" delete pod "$HAMMER" --ignore-not-found --wait=false >/dev/null 2>&1
}

drill_drain() {
  step "Drill 2 - a rollout drops no request"
  # 40 seconds of traffic at the rate the service actually permits, with the
  # rollout in the middle of it.
  hammer_start "$(cat "$HERE/.key-current")" 40
  sleep 8
  kubectl -n "$NS" rollout restart deploy/gateway >/dev/null
  kubectl -n "$NS" rollout status deploy/gateway --timeout=180s >/dev/null

  local total failed limited
  read -r total failed limited <<<"$(hammer_result)"
  if [ "${failed:-1}" = "0" ]; then
    ok "${total} requests across a rolling restart, ${failed} dropped (${limited} rate limited)"
  else
    bad "${failed:-?} of ${total:-?} requests were dropped during the rollout"
    echo "       A 429 is the service working; this counts only refused"
    echo "       connections and 5xx, which is what a drain should prevent."
  fi
}

drill_rotation() {
  step "Drill 3 - secret rotation"
  local old new_key
  old="$(cat "$HERE/.key-current")"
  new_key="$(openssl rand -hex 24)"

  # delete+create rather than apply: the Secret was created imperatively, and
  # `kubectl apply` over it warns about a missing last-applied annotation.
  kubectl -n "$NS" delete secret avoidpp-gateway --ignore-not-found >/dev/null
  kubectl -n "$NS" create secret generic avoidpp-gateway \
    --from-literal=AVOIDPP_API_KEYS="pilot:translate_fi_en_v1:${new_key}" >/dev/null

  # The part worth proving, because it is the part people assume away: the
  # Secret has changed and the running process has not noticed. Env vars are
  # read once at startup, and both services validate credentials there.
  sleep 5
  local with_old with_new
  with_old="$(scan_status "$old")"
  with_new="$(scan_status "$new_key")"
  if [ "$with_old" = "200" ] && [ "$with_new" = "401" ]; then
    ok "a changed Secret alone does nothing: old key $with_old, new key $with_new"
  else
    bad "expected old=200 new=401 before a roll, got old=$with_old new=$with_new"
  fi

  kubectl -n "$NS" rollout restart deploy/gateway >/dev/null
  kubectl -n "$NS" rollout status deploy/gateway --timeout=180s >/dev/null
  echo "$new_key" > "$HERE/.key-current"

  with_old="$(scan_status "$old")"
  with_new="$(scan_status "$new_key")"
  if [ "$with_new" = "200" ] && [ "$with_old" = "401" ]; then
    ok "after the roll the new key works and the old one is refused"
  else
    bad "expected old=401 new=200 after the roll, got old=$with_old new=$with_new"
  fi
}

drill_rollback() {
  step "Drill 4 - rollback"
  local before after
  before="$(kubectl -n "$NS" get deploy/gateway -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"

  # A change that is visibly wrong, so the rollback has something to undo.
  kubectl -n "$NS" set env deploy/gateway AVOIDPP_POLICY_MODE=enforcement >/dev/null
  kubectl -n "$NS" rollout status deploy/gateway --timeout=180s >/dev/null
  local mode
  mode="$(kubectl -n "$NS" get deploy/gateway -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="AVOIDPP_POLICY_MODE")].value}')"
  [ "$mode" = "enforcement" ] && ok "a configuration change rolled out (mode=$mode)" \
                              || bad "the change did not apply"

  kubectl -n "$NS" rollout undo deploy/gateway >/dev/null
  kubectl -n "$NS" rollout status deploy/gateway --timeout=180s >/dev/null
  mode="$(kubectl -n "$NS" get deploy/gateway -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="AVOIDPP_POLICY_MODE")].value}')"
  after="$(kubectl -n "$NS" get deploy/gateway -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"

  if [ "$mode" = "monitoring" ]; then
    ok "rollout undo restored mode=$mode (revision $before -> $after)"
  else
    bad "after undo the mode is $mode"
  fi
  [ "$(scan_status "$(cat "$HERE/.key-current")")" = "200" ] \
    && ok "the rolled-back revision serves" || bad "the rolled-back revision does not serve"
}

drills() {
  drill_isolation
  drill_drain
  drill_rotation
  drill_rollback

  printf '\n\033[1m%d passed, %d failed\033[0m\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

down() {
  step "Deleting cluster"
  kind delete cluster --name "$CLUSTER"
  rm -f "$HERE/.key-current"
}

case "${1:-all}" in
  up)     up ;;
  drills) drills ;;
  down)   down ;;
  all)    up; drills; down ;;
  *)      echo "usage: $0 {up|drills|down|all}" >&2; exit 2 ;;
esac
