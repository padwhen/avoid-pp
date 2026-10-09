# C01 — initialize Go and Python workspace

Scope: reproducible manifests, a minimal importable/compilable package in each
language, local checks, configuration template and repository hygiene. This
commit makes no detector-quality or security-enforcement claims.

## Acceptance criteria

1. A clean checkout resolves Go modules and installs locked Python dependencies
   using `make bootstrap` with the tool versions in the root README.
2. `make check-go` and `make check-python` complete without an LLM provider key.
   Go has no external modules or behavioral tests yet; Python has no model SDK.
3. Generated artifacts, local configuration, credential files and private
   datasets are excluded from version control.

## Verification

After creating the commit, check a fresh local clone with no copied `.venv` or
working-tree files:

```sh
git clone --no-hardlinks /absolute/path/to/avoid-pp /tmp/avoid-pp-c01-check
cd /tmp/avoid-pp-c01-check
make bootstrap
make check
git status --porcelain
```

Choose an unused temporary checkout path. The final status must be empty; the
bootstrap must not rewrite manifests or the lockfile. A shared download cache is
acceptable, but the project virtual environment must be newly created.

Check representative ignored paths without creating sensitive files:

```sh
git check-ignore .env detector/.env.local detector/.venv/example \
  credentials.json secrets.json private.pem private.key \
  gateway/bin/server detector/dist/package.whl \
  evals/reports/run.json evals/datasets/private/cases.jsonl
git ls-files
```

Every path supplied to `git check-ignore` above must be ignored.
`.env.example`, both dependency manifests and `detector/uv.lock` must be tracked.
Review staged contents before committing; ignore patterns cannot identify every
possible secret or confidential passage.
