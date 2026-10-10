# C11 — monitoring and enforcement decisions

Scope: a pure Go policy evaluator driven by server configuration and a
validated assessment. Replaces the placeholder that C09 shipped.

```sh
make run-gateway                                    # monitoring, the default
cd gateway && AVOIDPP_POLICY_MODE=enforcement \
  AVOIDPP_ADDR=:8099 AVOIDPP_DETECTOR_URL=http://localhost:9000 go run ./cmd/server
```

## The matrix

| Mode | Label | Action | Reason |
| --- | --- | --- | --- |
| monitoring | `no_injection_detected` | `allow` | nothing was found |
| monitoring | `suspicious` | `flag` | continue, with telemetry |
| monitoring | `uncertain` | `flag` | continue, with telemetry |
| enforcement | `no_injection_detected` | `allow` | nothing was found |
| enforcement | `suspicious` | `block` | stop continuation |
| enforcement | `uncertain` | `block` | an unresolved answer is not a clean one |

No row produces `allow` from a non-clean label, in either mode.

Monitoring is the default, and the only mode intended before the quality gates
at C30 are met. Enforcement has to be chosen deliberately.

## Acceptance criteria

1. Every combination in the documented policy matrix has an explicit expected
   decision.
2. Monitoring flags suspicious and uncertain results; enforcement blocks them;
   neither mode treats errors as clean.
3. A client cannot choose a policy or change the task configuration through
   extra request fields.

## Verification

```sh
cd gateway && go test -race ./internal/policy/ ./internal/api/ ./internal/config/
```

### AC1 — the matrix is a table, written out in full

`Evaluate` is pure: configuration in, decision out, no I/O and no clock. That
is what makes all six rows testable directly.

The table in `TestPolicyMatrix` is written out rather than generated, so a
changed row shows up as a visible diff in review instead of a silent change in
behaviour. A second loop then asserts every mode and label combination is
actually present, so a deleted row fails rather than quietly shrinking
coverage.

### AC2 — observed against the running services

```
monitoring:  {"action":"flag",  "reason":"suspicious_monitoring", "policy":"monitoring-1"}
enforcement: {"action":"block", "reason":"suspicious_enforced",   "policy":"enforcement-1"}
```

Same passage, same detector, same assessment. Only the server's configured
mode differs, and the response records which policy produced the decision.

A block returns **200**, not an error: it is a completed scan with an
unwelcome answer.

Operational failures never reach the evaluator. An unavailable detector, an
expired deadline or an untrustworthy response is an error envelope decided by
the handler, because a failure is not an assessment and must not be handed to
something whose only job is to produce actions.

### Two ways this fails closed

**An unknown label errors rather than falling through.** A `switch` with a
default branch would turn a label this build does not define into whatever that
branch does. Instead `Evaluate` returns `ErrUnknownLabel`, and the handler
converts that to a 503 carrying no assessment.

**An unconfigured mode refuses.** An empty or unrecognised mode does not relax
to monitoring, which is the permissive branch. `TestScanRefusesWithoutAConfiguredMode`
asserts the handler returns a non-200 containing no verdict, and startup
rejects a bad value outright:

```
$ AVOIDPP_POLICY_MODE=enforce go run ./cmd/server
gateway: invalid configuration: AVOIDPP_POLICY_MODE: must be monitoring or enforcement
exit status 1
```

A misconfigured gateway stops scanning. It does not start allowing.

### AC3 — the caller cannot pick its own rules

The policy comes from server configuration and is never read from a request.
`TestClientCannotChooseThePolicy` runs the gateway in enforcement, sends
passages carrying `policy` and `mode` fields at both the top level and inside
content, and requires each to be rejected before reaching the detector. A
caller cannot downgrade enforcement to monitoring by asking.

### Evidence does not steer the outcome

`TestEvidenceDoesNotChangeTheDecision` compares a bare assessment against one
carrying two categories and two quotations, and requires an identical decision.
Only the label matters, so a detector cannot push toward an outcome by
attaching more findings.

## Configuration

| Variable | Default | Values |
| --- | --- | --- |
| `AVOIDPP_POLICY_MODE` | `monitoring` | monitoring, enforcement |

The response's `versions.policy` field reports the mode and policy version, so
a result in an evaluation report can be attributed to the rules in force when
it was produced.

## Not yet

`uncertain` blocks under enforcement. The intended future resolution is output
verification — see threat model section 7 — which needs a commit the original
plan does not have. The contract reserves `verify` for it, and clients already
have to treat an unrecognised action as a block, so adding it later breaks
nobody.
