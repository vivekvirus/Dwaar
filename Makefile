# Dwaar developer commands. `make help` lists them.
# Python tooling runs through `uv run --no-sync`: it never touches uv.lock or the venv, so many
# agents/CI jobs can run make targets at once. Only `make setup` (flock-guarded) syncs.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

UV_LOCK  ?= /tmp/dwaar-uv.lock
PNPM_LOCK ?= /tmp/dwaar-pnpm.lock
UV_RUN   := uv run --no-sync
JS_PROJECTS := $(wildcard apps/*/package.json packages/contracts/package.json packages/i18n/package.json)
API_PORT ?= $(or $(DWAAR_API_PORT),8000)
MILESTONE ?=

.PHONY: help setup db-up db-down db-reset migrate seed api lint format typecheck test acceptance trace

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sed -E 's/:.*##/\t/' | sort

setup: ## install Python (uv) and JS (pnpm) dependencies, create .env with local keys
	flock $(UV_LOCK) uv sync
	$(UV_RUN) python tools/dev/devenv.py init
	@if [ -n "$(JS_PROJECTS)" ]; then flock $(PNPM_LOCK) pnpm install; else echo "no JS projects yet: skipping pnpm install"; fi

db-up: ## start the local dev PostgreSQL (.local/pg), create roles and database
	tools/dev/pg.sh up

db-down: ## stop the local dev PostgreSQL
	tools/dev/pg.sh down

db-reset: ## drop and recreate the empty dev database (then run: make migrate)
	tools/dev/pg.sh reset

migrate: ## apply SQL migrations as dwaar_owner (dwaar_api.core.migrate)
	$(UV_RUN) python -m tools.dev.migrate

seed: ## load synthetic demo data (DWAAR_ENV=local); says so if not implemented yet
	$(UV_RUN) python -m tools.dev.seed

api: ## run the API with reload on $(API_PORT) (foreground; Ctrl-C to stop)
	$(UV_RUN) python tools/dev/devenv.py exec -- uvicorn dwaar_api.main:app --reload --host 127.0.0.1 --port $(API_PORT)

lint: ## ruff check + format check
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .

format: ## apply ruff fixes and formatting
	$(UV_RUN) ruff check --fix .
	$(UV_RUN) ruff format .

typecheck: ## mypy (strict)
	$(UV_RUN) mypy

test: ## all tests (starts a private ephemeral PostgreSQL unless DWAAR_TEST_PG_ADMIN_URL is set)
	$(UV_RUN) pytest $(PYTEST_ARGS)

acceptance: ## acceptance tests with evidence: make acceptance MILESTONE=M0|M1 (cumulative)
	@case "$(MILESTONE)" in M0|M1|M2|M3|M4) ;; *) echo "usage: make acceptance MILESTONE=M0|M1" >&2; exit 2;; esac
	$(UV_RUN) pytest --evidence --milestone $(MILESTONE) -m "at" $(PYTEST_ARGS)

trace: ## requirement traceability report (tools/trace_check.py)
	@if [ -f tools/trace_check.py ]; then $(UV_RUN) python tools/trace_check.py; \
	else echo "make trace: tools/trace_check.py does not exist yet (added by the traceability step); nothing checked"; fi
