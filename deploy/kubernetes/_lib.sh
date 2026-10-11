#!/usr/bin/env bash
# Shared plumbing for the drill scripts.
#
# smoke.sh proves the deployment behaves (C34); runbooks.sh proves the
# documented operating procedures work (C35). They need the same four
# things - a pass/fail tally, timed steps, a way to run a hardened pod, and
# a way to make one scan - so those live here rather than in whichever
# script was written first.
#
# Not executable on its own. Source it.

CLUSTER="${CLUSTER:-avoid-pp}"
NS=avoid-pp
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LIB_DIR/../.." && pwd)"

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
note() { printf '  %s\n' "$1"; }

# Every long step says what it is doing and how long it took. The first
# version printed "Building images" and then nothing for a minute on a cold
# Docker cache, which is indistinguishable from a hang - and the only
# reasonable response to a hang is Ctrl-C.
timed() { # $1 = description, rest = command
  local description="$1"; shift
  local started; started=$SECONDS
  printf '  %s ... ' "$description"
  if "$@"; then
    printf 'done (%ss)\n' "$((SECONDS - started))"
  else
    printf '\033[31mfailed\033[0m\n'; return 1
  fi
}

# Ctrl-C at any point is safe; say so rather than leaving someone guessing.
on_interrupt() {
  printf '\n\033[1minterrupted\033[0m\n'
  printf '  Nothing is left running unless the cluster was already created.\n'
  printf '  To be sure:  %s down\n' "$0"
  exit 130
}
trap on_interrupt INT

# ## Why every request below is made from inside the cluster
#
# The obvious harness is `kubectl port-forward` and a local curl, and it is
# wrong here. port-forward binds to a *pod*, not to the Service, so the first
# rollout kills it - measured: 200 before a rolling restart and 000 after.
# Three of the four drills restart something, so a port-forwarded harness
# reports failures that are entirely its own.
#
# Running the client in-cluster also makes the drain drill mean what it says.
# It exercises the Service, endpoints and kube-proxy, which is the path a real
# caller takes and the path a rollout actually disturbs.
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.5.0}"

# restricted Pod Security is enforced on the namespace, so every helper pod
# has to satisfy it too. Kept in one place rather than repeated.
hardened() { # $1 = container name, $2 = shell command
  cat <<JSON
{"spec":{"automountServiceAccountToken":false,
 "restartPolicy":"Never",
 "securityContext":{"runAsNonRoot":true,"runAsUser":65532,
                    "seccompProfile":{"type":"RuntimeDefault"}},
 "containers":[{"name":"$1","image":"$CURL_IMAGE",
   "command":["sh","-c","$2"],
   "securityContext":{"allowPrivilegeEscalation":false,
     "readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}
JSON
}

run_pod() { # $1 = name, $2 = command; echoes the pod's stdout
  kubectl -n "$NS" delete pod "$1" --ignore-not-found --wait=true >/dev/null 2>&1
  kubectl -n "$NS" run "$1" --restart=Never --image="$CURL_IMAGE" \
    --overrides="$(hardened "$1" "$2")" >/dev/null
  kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$1" \
    --timeout=180s >/dev/null 2>&1 || true
  kubectl -n "$NS" logs "$1" 2>/dev/null | tr -d '\r'
  kubectl -n "$NS" delete pod "$1" --ignore-not-found --wait=false >/dev/null 2>&1
}

GATEWAY_URL="http://gateway.$NS.svc.cluster.local:8080"
DETECTOR_URL="http://detector.$NS.svc.cluster.local:9000"
PASSAGE='{\"task_id\":\"translate_fi_en_v1\",\"content\":{\"id\":\"smoke\",\"source_type\":\"translation_input\",\"language_hint\":\"fi\",\"text\":\"Saa on tanaan aurinkoinen.\"}}'

scan_status() { # $1 = key; echoes an HTTP status, or 000
  run_pod "scan-probe" \
    "curl -s -o /dev/null -w %{http_code} --max-time 10 -X POST $GATEWAY_URL/v1/scans -H 'Content-Type: application/json' -H 'Authorization: Bearer $1' -d '$PASSAGE' || true" \
    | tail -1
}

