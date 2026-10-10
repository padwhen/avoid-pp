# avoid-pp

[![checks](https://github.com/padwhen/avoid-pp/actions/workflows/checks.yml/badge.svg)](https://github.com/padwhen/avoid-pp/actions/workflows/checks.yml)

A Go/Python workspace for a prompt-injection detection API, initially evaluated
around Finnish-to-English LLM translation.

**Status: C06 — contract, Finnish seed corpus and evaluation runner.** There is
no HTTP server, detector, translation service or security protection
implemented yet. The contract is frozen and the evaluation harness runs against
fake detectors, both before the services that will implement them.

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

## Evaluation

### Nothing here is trained

No model is trained or fine-tuned in this project. The detector will be a
hosted LLM called with a prompt, so its behaviour changes by editing text, not
by adjusting weights.

That makes [evals/](evals/) a **measuring instrument**, not training data:

| | What it is | Plain version |
| --- | --- | --- |
| **C05** `datasets/seed-fi.yaml` | 73 Finnish passages, each with the label a correct detector should produce | The exam questions, plus the answer key |
| **C06** `runner.py` | Runs a detector over those passages and scores it | The marking scheme |
| C13–C14 | The real LLM detector | The student. Does not exist yet. |

Because the corpus is a test set, the prompt must not be tuned against all of
it. C26 splits off a frozen holdout that stays unread until the end; scoring
against data you tuned on produces numbers that do not survive contact with
reality.

### Tested versus measured

Two different things live here, and conflating them causes confusion:

```sh
make check-evals-runner    # a TEST.   Pass/fail. Subject: the scorer.
make check-evals           # a TEST.   Pass/fail. Subject: the dataset.

uv run --project detector python evals/runner.py --adapter keyword
                           # a MEASUREMENT. No pass/fail. Subject: the detector.
```

A unit test asserts one exact output from deterministic code. A probabilistic
system has no single right answer per run, so the runner reports where it sits
instead of claiming it passed. There is deliberately no failing threshold: that
threshold is the release gate at C30, and at 73 cases it would not be
measurable anyway.

The runner's own arithmetic *is* pinned by a test, against a fixture small
enough to check by hand. That way, when a real model is wired in and a number
looks wrong, the scorer is not a suspect.

### Reading the numbers

Running the naive `keyword` detector over the corpus:

```text
TP 5   FN 18   FP 8   TN 37
conditional : recall 0.2174   fpr 0.1778   precision 0.3846
```

The four counts are one tally of what the detector said against what was true:

| | it said "attack" | it said "clean" |
| --- | --- | --- |
| **really an attack** (23) | TP 5 — caught | FN 18 — missed |
| **really harmless** (45) | FP 8 — false alarm | TN 37 — passed |

The three ratios each divide by a *different* denominator, which is the part
worth slowing down for:

- **recall** `= TP/(TP+FN) = 5/23 = 0.22` — of all real attacks, how many were
  caught? It missed 18 of 23.
- **false positive rate** `= FP/(FP+TN) = 8/45 = 0.18` — of all harmless text,
  how much was wrongly blocked? Eight users' ordinary Finnish refused.
- **precision** `= TP/(TP+FP) = 5/13 = 0.38` — when the alarm went off, was it
  right? It raised 13 alarms; 8 were wrong.

So a keyword matcher misses four of every five attacks *and* blocks nearly one
in five innocent passages. Not a badly tuned tradeoff — bad on both axes at
once, which is what keyword matching looks like on a task that needs context.

**Never read one of these alone.** The `always_suspicious` adapter scores a
perfect `recall 1.0` by blocking everything; its false positive rate is also
1.0. Recall without false positive rate says nothing.

### Abstaining is not success

Results are reported in two views, because they can disagree completely:

| View | Measured over | Answers |
| --- | --- | --- |
| `conditional` | cases that produced a definite label | How accurate is it *given that it answered*? |
| `operational` | every scored case | What does the application actually experience? |

A detector that answers "uncertain" to everything has a flawless conditional
record — it never commits, so it is never wrong. Its operational view shows
`attack_caught_rate 0.0`. Abstentions and errors are never counted as correct
benign answers.

See [C05](docs/c05-dataset.md) and [C06](docs/c06-runner.md) for acceptance
criteria and known limitations.

## Threat model

[docs/threat-model.md](docs/threat-model.md) defines the supported scope, trust
boundaries, failure behavior and policy modes for the Finnish-to-English task.
Read it before adding any scanning, policy or translation behavior; it records
what this service deliberately does not protect, and which capabilities remain
unverified.
