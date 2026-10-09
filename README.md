# avoid-pp

[![checks](https://github.com/padwhen/avoid-pp/actions/workflows/checks.yml/badge.svg)](https://github.com/padwhen/avoid-pp/actions/workflows/checks.yml)

A Go/Python workspace for a prompt-injection detection API, initially evaluated
around Finnish-to-English LLM translation.

**Status: C03 — bootstrap, threat model and API contract only.** There is no
HTTP server, detector, translation service or security protection implemented
yet; the contract is frozen before the services that implement it.

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
make check-contracts
make check-contracts-selftest
```

Every pull request runs exactly these commands on a clean Linux checkout; see
[C04 acceptance criteria](docs/c04-ci.md). No LLM provider credential is used
or required.

Dependency installation uses `uv sync --locked` so a stale lockfile fails rather
than silently changing dependency versions. Commit `detector/uv.lock` whenever
dependencies intentionally change. Runtime dependencies and provider SDKs will
be added with the code that needs them.

## Layout

```text
gateway/                     Go module for the future API and policy layer
detector/                    Installable Python package and locked developer tools
contracts/                   Public/private API schemas, OpenAPI and shared fixtures
evals/                       Future reviewed datasets, runners and generated reports
examples/                    Future protected-translator integration example
docs/                        Implementation notes and acceptance evidence
```

Service subpackages will be created as their behavior is introduced; the
bootstrap commit did not create empty HTTP routes or fake protection behavior.
Runnable Go/Python HTTP services begin at C07/C08.

## Configuration and data hygiene

`.env.example` documents planned local fake/monitor defaults. It is a template,
not runtime configuration in C01, and the bootstrap never loads it. Local `.env`
files, credential/key files, caches, build outputs and private evaluation data
are ignored. Put private datasets only in `data/private/` or
`evals/datasets/private/`; generated evaluation reports go in `evals/reports/`.
Ignore rules are a safeguard, not a substitute for reviewing staged files.

See [C01 acceptance criteria](docs/c01-bootstrap.md) for verification details.

## API contract

[contracts/](contracts/) holds the frozen public scan and private assessment
schemas, the OpenAPI document and the positive/negative fixtures. `make
check-contracts` validates both directions. Three properties are structural
rather than documented: a caller cannot supply policy, a non-clean assessment
cannot emerge as `allow`, and a failure cannot be expressed in the success
shape. See [C03 acceptance criteria](docs/c03-contracts.md).

## Threat model

[docs/threat-model.md](docs/threat-model.md) defines the supported scope, trust
boundaries, failure behavior and policy modes for the Finnish-to-English task.
Read it before adding any scanning, policy or translation behavior; it records
what this service deliberately does not protect, and which capabilities remain
unverified.
