# avoid-pp

A Go/Python workspace for a prompt-injection detection API, initially evaluated
around Finnish-to-English LLM translation.

**Status: C01 — repository bootstrap only.** There is no HTTP server, detector,
translation service or security protection implemented yet.

Go will own the API, authentication, request limits and policy decisions. Python
will own model integration, assessment validation and evaluation logic. The
application must distinguish translating an instruction from obeying it.

Language detection is routing metadata. A Finnish passage can contain an
instruction in another language, so future scanning must preserve the entire
original passage. Mixed-language detection quality is a later evaluation goal.

## Prerequisites

Install these pinned tools:

| Tool | Version | Pin |
| --- | --- | --- |
| Go | 1.27.2 | `.go-version`, `gateway/go.mod` |
| Python | 3.13.14 | `detector/.python-version` |
| uv | 0.12.15 | `detector/pyproject.toml` |
| Make | A POSIX-compatible Make implementation | Used for local commands |

Go installation: <https://go.dev/doc/install>.
uv installation: <https://docs.astral.sh/uv/getting-started/installation/>.
To select this uv release, use the installer's versioned installation instructions
or install `uv==0.12.15` through your package manager.

With uv installed, provision Python if needed:

```sh
uv python install 3.13.14
```

Put `go`, its matching `gofmt`, `uv` and `make` on `PATH`. Python is selected by uv
from the detector workspace's pin. `GO`, `GOFMT` and `UV` can also be overridden
when invoking Make, for example `make check-go GO=/path/to/go GOFMT=/path/to/gofmt`.

## Bootstrap and check

From the repository root:

```sh
make bootstrap
make check
```

The first bootstrap needs network access for Python packages and, if absent, the
pinned Python interpreter. It installs the Python package in editable mode and
its locked developer dependencies. No LLM provider key, `.env`, database, Docker,
or paid API call is required.

Go currently uses only the standard library. `go mod download` therefore reports
that there are no module dependencies, and no `go.sum` is needed yet. Go checks
formatting, vets and compiles the package using `go test ./...`; there are no
behavioral tests at this scaffolding stage. Python checks formatting, lint, strict
types and that the installed package imports successfully. `make check` does not
rewrite source files.

Individual checks:

```sh
make check-go
make check-python
```

Dependency installation uses `uv sync --locked` so a stale lockfile fails rather
than silently changing dependency versions. Commit `detector/uv.lock` whenever
dependencies intentionally change. Runtime dependencies and provider SDKs will
be added with the code that needs them.

## Layout

```text
gateway/                     Go module for the future API and policy layer
detector/                    Installable Python package and locked developer tools
contracts/                   Future public/private API schemas and shared fixtures
evals/                       Future reviewed datasets, runners and generated reports
examples/                    Future protected-translator integration example
docs/                        Implementation notes and acceptance evidence
```

Service subpackages will be created as their behavior is introduced; this commit
does not create empty HTTP routes or fake protection behavior. CI wiring is C04,
and runnable Go/Python HTTP services begin at C07/C08.

## Configuration and data hygiene

`.env.example` documents planned local fake/monitor defaults. It is a template,
not runtime configuration in C01, and the bootstrap never loads it. Local `.env`
files, credential/key files, caches, build outputs and private evaluation data
are ignored. Put private datasets only in `data/private/` or
`evals/datasets/private/`; generated evaluation reports go in `evals/reports/`.
Ignore rules are a safeguard, not a substitute for reviewing staged files.

See [C01 acceptance criteria](docs/c01-bootstrap.md) for verification details.
