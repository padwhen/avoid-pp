# Contracts

The frozen shape of the public scan API and the private detector API. The Go
gateway (C07) and the Python detector (C08) are both written against this, so
it is defined before either exists.

```text
openapi.yaml          Endpoints, HTTP status semantics, error codes
schemas/              JSON Schema (draft 2020-12), the normative definitions
fixtures/valid/       Must validate
fixtures/invalid/     Must be rejected
validate.py           Runs both directions plus the cross-field invariants
```

Run it:

```sh
make check-contracts
```

## What the schemas enforce

Three properties are structural rather than documented, so a future
implementation cannot quietly violate them:

1. **A caller cannot weaken its own scan.** `scan-request` sets
   `additionalProperties: false` and has no field for policy, mode,
   instructions, thresholds or trust level. A request carrying `policy` or
   `mode` is rejected, not ignored.
2. **A non-clean assessment can never emerge as `allow`.** `scan-response`
   constrains the label/action pairing directly: `suspicious` and `uncertain`
   accept only `flag` or `block`.
3. **A failure cannot impersonate a clean scan.** `scan_status` has exactly one
   legal value (`complete`), so an unavailable, timed-out or truncated outcome
   cannot be expressed in the response shape at all. Those are error envelopes,
   and `error.schema.json` forbids an `assessment` field.

`validate.py` adds what JSON Schema cannot express: scanned bytes must equal
original bytes on a completed scan, no error envelope may also validate as a
scan response, and the Finnish/Dutch passage must survive parsing byte for byte.

## Enum stability

Enum values are append-only: once emitted, never renamed or removed. To make
that safe, the contract requires clients to treat **any unrecognised
`decision.action` as `block`** — fail closed. The value `verify` is reserved for
a future output-verification action and is never emitted today. See
[../docs/threat-model.md](../docs/threat-model.md) section 7.

## Deliberately absent

- **A confidence number.** An LLM-invented probability is not calibrated and
  must not be rendered as though it were.
- **Batch scanning.** `content` is an object, not an array, so a two-passage
  request cannot be expressed rather than being silently truncated to the first.
- **Signed receipts and caching.** The initial integration is synchronous. Note
  that an application with its own translation cache must scan *before* its
  cache lookup, or cached entries bypass scanning entirely.
