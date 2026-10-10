GO ?= go
GOFMT ?= gofmt
UV ?= uv

# Local run defaults. 8080 is the gateway's own default, but is often taken by
# another service (nginx, for one), so the convenience target uses 8099.
ADDR ?= :8099
DETECTOR_URL ?= http://localhost:9000

.DEFAULT_GOAL := help
.PHONY: help bootstrap bootstrap-go bootstrap-python check check-go check-python check-contracts check-contracts-selftest check-evals check-evals-runner run-gateway

help:
	@printf '%s\n' \
	  'make bootstrap     Resolve Go modules and install locked Python dependencies' \
	  'make check         Check both language workspaces (run bootstrap first)' \
	  'make check-go      Check Go formatting, vet, and run tests under -race' \
	  'make check-python Check Python formatting, lint, types and package import' \
	  'make check-contracts  Validate contract schemas against positive/negative fixtures' \
	  'make check-contracts-selftest  Prove the contract validator rejects bad data' \
	  'make check-evals      Validate the Finnish seed dataset and report progress' \
	  'make check-evals-runner  Assert the evaluation runner against a hand-calculated fixture' \
	  'make run-gateway   Run the gateway locally (override ADDR= and DETECTOR_URL=)'

bootstrap: bootstrap-go bootstrap-python

bootstrap-go:
	cd gateway && $(GO) mod download

bootstrap-python:
	cd detector && $(UV) sync --locked

check: check-go check-python check-contracts check-contracts-selftest check-evals check-evals-runner

check-go:
	@files="$$(cd gateway && $(GOFMT) -l .)" || exit $$?; \
	if [ -n "$$files" ]; then \
	  printf 'Run gofmt on these files:\n%s\n' "$$files"; exit 1; \
	fi
	cd gateway && $(GO) vet ./...
	cd gateway && $(GO) test -race ./...

check-python:
	cd detector && $(UV) run --locked --no-sync ruff format --check .
	cd detector && $(UV) run --locked --no-sync ruff check .
	cd detector && $(UV) run --locked --no-sync mypy src
	cd detector && $(UV) run --locked --no-sync python -c "import translation_guard"

check-contracts:
	$(UV) run --project detector --locked --no-sync python contracts/validate.py

check-contracts-selftest:
	./contracts/selftest.sh $(UV) run --project detector --locked --no-sync python

check-evals:
	$(UV) run --project detector --locked --no-sync python evals/validate.py

check-evals-runner:
	$(UV) run --project detector --locked --no-sync python evals/selftest.py

run-gateway:
	cd gateway && AVOIDPP_ADDR=$(ADDR) AVOIDPP_DETECTOR_URL=$(DETECTOR_URL) $(GO) run ./cmd/server
