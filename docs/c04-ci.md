# C04 — fast offline checks

Scope: run the repository's documented check commands in CI, on a machine that
is not the author's, without any LLM provider credential.

CI calls the same Make targets the README documents. There is no separate CI
script to drift out of sync with local development.

## Acceptance criteria

1. Go formatting/vet/tests and Python Ruff/mypy/tests run through documented
   local commands and the same CI entry points.
2. Contract fixture checks fail when an intentionally invalid fixture is
   admitted.
3. Default checks make no network calls to an LLM provider and do not require
   production credentials.

## Verification

### AC1 — same entry points

`.github/workflows/checks.yml` runs, in order:

```sh
make bootstrap
git diff --exit-code     # bootstrap must not rewrite manifests or the lockfile
make check-go
make check-python
make check-contracts
make check-contracts-selftest
```

Every one of those is a documented local command. Running `make check` locally
covers the last four.

This also gives C01-AC1 its first honest test. Until now "a clean checkout
installs locked dependencies" had only been observed on one macOS machine with
hand-installed tooling. The runner starts from nothing, pins Go from
`.go-version` and uv to `0.12.15`, and lets uv provision the interpreter named
in `detector/.python-version`.

### AC2 — the validator is proven to reject

`make check-contracts-selftest` runs `contracts/selftest.sh`, which copies
`contracts/` to a scratch directory, applies one deliberate defect at a time,
and requires the validator to fail each time:

| Mutation | Expected rejection |
| --- | --- |
| A suspicious assessment allowed through | `'allow' is not one of ['flag', 'block']` |
| An error envelope carrying a clean assessment | `Additional properties are not allowed ('assessment' ...)` |
| A caller-supplied policy override accepted | `Additional properties are not allowed ('policy' ...)` |
| The embedded Dutch span deleted | `text was altered in transit` |
| A partial scan reported as complete | `scan_status=complete but scanned 10 of 82 bytes` |

The script first confirms an unmutated copy passes; without that, every
"rejection" below it could be an unrelated error. If any mutation goes
undetected the build fails and names it.

Run it locally:

```sh
make check-contracts-selftest
```

### AC3 — no credentials, no provider calls

The workflow references no secret, and the final step enforces that rather than
asserting it in prose:

```sh
grep -rnE '\$\{\{ *secrets\.' .github/workflows && exit 1
```

Adding a secret to any workflow in this directory fails the build. Live-model
runs arrive later (C13+) as a separate, opt-in workflow with its own
credentials and an explicit cost ceiling; they are never part of the default
pull-request path.

`permissions: contents: read` limits the token to reading the repository.

## Notes

- Go caching is disabled: `gateway` has no external modules, so there is no
  `go.sum` to key a cache on. Re-enable `cache-dependency-path` when one exists.
- uv caching is keyed on `detector/uv.lock`.
- `concurrency` cancels superseded runs on the same ref.
