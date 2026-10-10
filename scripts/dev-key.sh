#!/usr/bin/env bash
# Generate a development API key and write it into the gitignored .env.
#
# C19 requires the gateway to be configured with callers before it will serve
# scans, and it refuses to start without them. Rather than ship a default key
# in the repository — a committed credential is a public one, however it is
# labelled — this generates a fresh one per machine.
#
# Usage: scripts/dev-key.sh [caller-name]

set -euo pipefail

CALLER="${1:-local-dev}"
TASKS="translate_fi_en_v1"
ENV_FILE=".env"
VAR="AVOIDPP_API_KEYS"

if [ -f "$ENV_FILE" ] && grep -q "^${VAR}=" "$ENV_FILE"; then
    printf '%s is already set in %s. Nothing changed.\n' "$VAR" "$ENV_FILE"
    printf 'To rotate, add a second entry for the same caller with a new key,\n'
    printf 'move callers across, then remove the old entry. See docs/c19-auth.md.\n'
    exit 0
fi

# 32 bytes of CSPRNG output as base64url without padding: 43 characters, well
# past the configured floor, and free of the separators the format reserves.
#
# Not `tr -dc ... </dev/urandom | head -c`: head closes the pipe once it has
# enough, tr dies of SIGPIPE, and `set -o pipefail` then fails the whole
# script. The failure is silent precisely when the key was generated fine.
KEY="$(openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"

if [ "${#KEY}" -lt 32 ]; then
    echo "dev-key: generated key is too short; openssl rand failed?" >&2
    exit 1
fi

printf '%s=%s:%s:%s\n' "$VAR" "$CALLER" "$TASKS" "$KEY" >> "$ENV_FILE"

printf 'Wrote %s to %s for caller %q.\n' "$VAR" "$ENV_FILE" "$CALLER"
printf '%s is gitignored. The key is not printed here; read it from the file\n' "$ENV_FILE"
printf 'if you need it for a manual request.\n'
