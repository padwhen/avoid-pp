#!/usr/bin/env bash
# Prove that contracts/validate.py actually rejects bad contract data.
#
# A validator that accepts everything passes every fixture and protects
# nothing. This copies contracts/ to a scratch directory, introduces one
# deliberate defect at a time, and requires the validator to FAIL each time.
# C04-AC2.
#
# Usage: contracts/selftest.sh [python-command...]
#   defaults to: uv run --project detector --locked --no-sync python

set -euo pipefail

CONTRACTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$CONTRACTS_DIR")"
cd "$REPO_ROOT"

if [ "$#" -gt 0 ]; then
    PY=("$@")
else
    PY=(uv run --project detector --locked --no-sync python)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0

# Run the validator against a fresh copy after applying a mutation.
# $1 = description, $2 = shell snippet mutating files under $WORK/contracts
expect_failure() {
    local description="$1" mutation="$2" output status
    rm -rf "$WORK/contracts"
    cp -R "$CONTRACTS_DIR" "$WORK/contracts"
    ( cd "$WORK" && eval "$mutation" )

    set +e
    output="$("${PY[@]}" "$WORK/contracts/validate.py" 2>&1)"
    status=$?
    set -e

    if [ "$status" -eq 0 ]; then
        printf 'selftest: NOT CAUGHT  %s\n' "$description"
        failures=$((failures + 1))
    else
        printf 'selftest: caught       %s\n' "$description"
        printf '                       %s\n' "$(printf '%s' "$output" | sed -n '2p' | sed 's/^ *//')"
    fi
}

# Sanity: an unmutated copy must pass, or every result below is meaningless.
rm -rf "$WORK/contracts"
cp -R "$CONTRACTS_DIR" "$WORK/contracts"
if ! "${PY[@]}" "$WORK/contracts/validate.py" >/dev/null 2>&1; then
    echo 'selftest: FAILED - unmutated copy does not pass; fix the fixtures first' >&2
    exit 1
fi
echo 'selftest: baseline copy passes'

expect_failure 'a suspicious assessment allowed through' \
  'cp contracts/fixtures/invalid/scan-response.suspicious-but-allow.json contracts/fixtures/valid/'

expect_failure 'an error envelope carrying a clean assessment' \
  'cp contracts/fixtures/invalid/error.carries-assessment.json contracts/fixtures/valid/'

expect_failure 'a caller-supplied policy override accepted' \
  'cp contracts/fixtures/invalid/scan-request.caller-policy-override.json contracts/fixtures/valid/'

expect_failure 'the embedded Dutch span deleted from the passage' \
  'python3 -c "
import io, json
p = \"contracts/fixtures/valid/scan-request.finnish-with-embedded-dutch.json\"
d = json.load(io.open(p, encoding=\"utf-8\"))
d[\"content\"][\"text\"] = \"Alku suomeksi. Loppu suomeksi.\"
json.dump(d, io.open(p, \"w\", encoding=\"utf-8\"), ensure_ascii=False, indent=2)
"'

expect_failure 'a partial scan reported as complete coverage' \
  'python3 -c "
import io, json
p = \"contracts/fixtures/valid/scan-response.allow.json\"
d = json.load(io.open(p, encoding=\"utf-8\"))
d[\"coverage\"][\"scanned_utf8_bytes\"] = 10
json.dump(d, io.open(p, \"w\", encoding=\"utf-8\"), ensure_ascii=False, indent=2)
"'

if [ "$failures" -ne 0 ]; then
    printf '\nselftest: %d mutation(s) went undetected\n' "$failures" >&2
    exit 1
fi

echo 'selftest: all mutations detected'
