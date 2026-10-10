GO ?= go
GOFMT ?= gofmt
UV ?= uv

# Local run defaults. 8080 is the gateway's own default, but is often taken by
# another service (nginx, for one), so the convenience target uses 8099.
# Rate limits for the convenience targets only.
#
# The shipped defaults (1/5 per caller) are a spend bound sized for a service
# calling a paid model, and they are far too tight to run a verification suite
# through: `make smoke` makes about a dozen authenticated requests in a second.
# So the local targets loosen them and say so, while a deployment that sets
# nothing still gets the tight defaults from config.go.
#
# An AVOIDPP_RATE_* already set in the environment or .env wins over these.
DEV_RATE_CALLER ?= 20/40
DEV_RATE_GLOBAL ?= 40/80
DEV_RATE_UNAUTH ?= 20/40

ADDR ?= :8099
DETECTOR_URL ?= http://localhost:9000
DETECTOR_HOST ?= 127.0.0.1
DETECTOR_PORT ?= 9000

.DEFAULT_GOAL := help
.PHONY: demo check-examples live-translate splits splits-freeze duplicates audit check-splits check-duplicates ingest help bootstrap bootstrap-go bootstrap-python check check-go check-python check-contracts check-contracts-selftest check-evals check-evals-runner dev-key run-gateway run-detector up down logs smoke live-smoke live-eval

help:
	@printf '%s\n' \
	  'make bootstrap     Resolve Go modules and install locked Python dependencies' \
	  'make check         Check both language workspaces (run bootstrap first)' \
	  'make check-go      Check Go formatting, vet, and run tests under -race' \
	  'make check-python Check Python formatting, lint, types, tests and package import' \
	  'make check-contracts  Validate contract schemas against positive/negative fixtures' \
	  'make check-contracts-selftest  Prove the contract validator rejects bad data' \
	  'make check-evals      Validate the Finnish seed dataset and report progress' \
	  'make check-examples   Test the protected-translator example' \
	  'make live-translate   Translate one Finnish passage live (COSTS MONEY)' \
	  'make demo             Guard + translator against a running gateway (CONFIRM=yes for live)' \
	  'make ingest           Convert authored evals/authoring/*.txt into dataset YAML' \
	  'make splits           Show the dev/validation/holdout split and its statistical power' \
	  'make splits-freeze    Freeze the split manifest (refuses a degenerate holdout)' \
	  'make duplicates       Review duplicates, near-duplicates and cross-split leakage' \
	  'make audit            Report C26-AC1 corpus coverage and review status' \
	  'make check-splits     Assert split stability, grouping and holdout protection' \
	  'make check-evals-runner  Assert the evaluation runner against a hand-calculated fixture' \
	  'make dev-key       Generate a development API key into the gitignored .env' \
	  'make run-gateway   Run the gateway locally (override ADDR= and DETECTOR_URL=)' \
	  'make run-detector  Run the detector locally in fake mode (no API key)' \
	  'make up            Build and start both services with Compose' \
	  'make smoke         Exercise the running stack and assert the responses' \
	  'make logs          Follow Compose logs' \
	  'make down          Stop and remove the Compose stack' \
	  'make live-smoke    Call the real provider (COSTS MONEY; needs CONFIRM=yes)' \
	  'make live-eval     Score the corpus against the live detector (COSTS MONEY)'

bootstrap: bootstrap-go bootstrap-python

bootstrap-go:
	cd gateway && $(GO) mod download

bootstrap-python:
	cd detector && $(UV) sync --locked

check: check-go check-python check-contracts check-contracts-selftest check-examples check-evals check-evals-runner check-splits check-duplicates

check-go:
	@files="$$(cd gateway && $(GOFMT) -l .)" || exit $$?; \
	if [ -n "$$files" ]; then \
	  printf 'Run gofmt on these files:\n%s\n' "$$files"; exit 1; \
	fi
	cd gateway && $(GO) vet ./...
	cd gateway && $(GO) test -race ./...

check-python:
	cd detector && $(UV) run --locked --no-sync ruff format --check . ../evals ../scripts
	cd detector && $(UV) run --locked --no-sync ruff check . ../evals ../scripts
	cd detector && $(UV) run --locked --no-sync mypy src
	cd detector && $(UV) run --locked --no-sync python -m pytest tests -q
	cd detector && $(UV) run --locked --no-sync python -c "import translation_guard"

check-contracts:
	$(UV) run --project detector --locked --no-sync python contracts/validate.py

check-contracts-selftest:
	./contracts/selftest.sh $(UV) run --project detector --locked --no-sync python

ingest:
	$(UV) run --project detector --locked --no-sync python evals/authoring/ingest.py $(if $(filter yes,$(WRITE)),--write,)

splits:
	$(UV) run --project detector --locked --no-sync python evals/splits.py $(if $(WEIGHTS),--weights $(WEIGHTS),)

splits-freeze:
	$(UV) run --project detector --locked --no-sync python evals/splits.py --freeze $(if $(WEIGHTS),--weights $(WEIGHTS),)

duplicates:
	$(UV) run --project detector --locked --no-sync python evals/duplicates.py

audit:
	$(UV) run --project detector --locked --no-sync python evals/audit.py

check-splits:
	$(UV) run --project detector --locked --no-sync python evals/splits_selftest.py

# Exact duplicates fail the build; near-duplicates and leakage are reported
# for the author to judge, because a tool cannot tell a mistake from a
# deliberately near-identical matched pair.
check-duplicates:
	$(UV) run --project detector --locked --no-sync python evals/duplicates.py

check-examples:
	PYTHONPATH=. $(UV) run --project detector --locked --no-sync python -m pytest examples/tests -q

# Costs money. Never run by CI or by `make check`.
live-translate:
	PYTHONPATH=. $(UV) run --project detector --locked --no-sync python examples/live_translate.py \
	  $(if $(filter yes,$(CONFIRM)),--confirm,) $(if $(PASSAGE),--passage $(PASSAGE),) \
	  $(if $(filter yes,$(SHOW_REQUEST)),--show-request,)

# Needs a running gateway. Free with the fake translator; CONFIRM=yes makes
# the translator live.
demo:
	@test -f .env || { echo 'no .env; run `make dev-key` first' >&2; exit 1; }
	set -a && . ./.env && set +a && \
	  PYTHONPATH=. $(UV) run --project detector --locked --no-sync python examples/protected_demo.py \
	  --base-url http://localhost:$${AVOIDPP_HOST_PORT:-8099} \
	  $(if $(filter yes,$(CONFIRM)),--confirm,) $(if $(filter yes,$(MONITORING)),--monitoring,)

check-evals:
	$(UV) run --project detector --locked --no-sync python evals/validate.py

check-evals-runner:
	$(UV) run --project detector --locked --no-sync python evals/selftest.py

dev-key:
	./scripts/dev-key.sh $(if $(CALLER),$(CALLER),)

# The gateway refuses to start without configured callers, so these targets
# source .env rather than carrying a key of their own. `make dev-key` writes
# one if there is none.
run-gateway:
	@test -f .env || { echo 'no .env; run `make dev-key` first' >&2; exit 1; }
	cd gateway && set -a && . ../.env && set +a && \
	  AVOIDPP_ADDR=$(ADDR) AVOIDPP_DETECTOR_URL=$(DETECTOR_URL) \
	  AVOIDPP_RATE_CALLER=$${AVOIDPP_RATE_CALLER:-$(DEV_RATE_CALLER)} \
	  AVOIDPP_RATE_GLOBAL=$${AVOIDPP_RATE_GLOBAL:-$(DEV_RATE_GLOBAL)} \
	  AVOIDPP_RATE_UNAUTHENTICATED=$${AVOIDPP_RATE_UNAUTHENTICATED:-$(DEV_RATE_UNAUTH)} \
	  $(GO) run ./cmd/server

run-detector:
	cd detector && $(UV) run --locked --no-sync uvicorn translation_guard.api:app \
	  --host $(DETECTOR_HOST) --port $(DETECTOR_PORT)

up:
	@test -f .env || { echo 'no .env; run `make dev-key` first' >&2; exit 1; }
	@printf 'rate limits for local use: caller %s, global %s, unauthenticated %s\n' \
	  "$${AVOIDPP_RATE_CALLER:-$(DEV_RATE_CALLER)}" \
	  "$${AVOIDPP_RATE_GLOBAL:-$(DEV_RATE_GLOBAL)}" \
	  "$${AVOIDPP_RATE_UNAUTHENTICATED:-$(DEV_RATE_UNAUTH)}"
	AVOIDPP_RATE_CALLER=$${AVOIDPP_RATE_CALLER:-$(DEV_RATE_CALLER)} \
	AVOIDPP_RATE_GLOBAL=$${AVOIDPP_RATE_GLOBAL:-$(DEV_RATE_GLOBAL)} \
	AVOIDPP_RATE_UNAUTHENTICATED=$${AVOIDPP_RATE_UNAUTHENTICATED:-$(DEV_RATE_UNAUTH)} \
	docker compose up -d --build
	@printf 'gateway: http://localhost:%s\n' "$${AVOIDPP_HOST_PORT:-8099}"

smoke:
	@test -f .env || { echo 'no .env; run `make dev-key` first' >&2; exit 1; }
	set -a && . ./.env && set +a && \
	  ./scripts/smoke.sh http://localhost:$${AVOIDPP_HOST_PORT:-8099}

logs:
	docker compose logs -f

down:
	docker compose down -v

# The only target that spends money. Never run by CI or by `make check`.
live-smoke:
	cd detector && $(UV) run --locked --no-sync python ../scripts/live-smoke.py \
	  $(if $(filter yes,$(CONFIRM)),--confirm,) $(if $(MODEL),--model $(MODEL),)

live-eval:
	cd detector && $(UV) run --locked --no-sync python ../evals/live_eval.py \
	  $(if $(filter yes,$(CONFIRM)),--confirm,) $(if $(MODEL),--model $(MODEL),) \
	  $(if $(LIMIT),--limit $(LIMIT),)
