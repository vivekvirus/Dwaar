# ADR-0001: Monorepo layout and technology stack

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team
- Related: PRD 19.1, decisions D-05 to D-12, B-003

## Context

PRD 19.1 prescribes a monorepo with `apps/`, `services/`, `packages/`, `infra/`, `tests/` and `docs/`. Several agents and
engineers build in parallel, so the repository needs one place for shared Python code, one workspace per language, and
commands that never fight over shared state.

## Decision

1. **Layout** follows PRD 19.1, plus `packages/dwaar-common` (shared Python library), `packages/dwaar-packs` (legal and tax
   pack loader) and `tools/` (developer scripts, `trace_check.py`). `.github/` holds CI.
2. **Python 3.12 with a uv workspace.** The root `pyproject.toml` is virtual (`package = false`); members are
   `packages/dwaar-*` and `services/*`. The root `dev` dependency group lists every member plus the toolchain (pytest,
   hypothesis, ruff, mypy). A new member adds one line to that group and one `[tool.uv.sources]` entry.
3. **Services** `api`, `worker`, `edge`, `ai-gateway` are separate installable packages (`dwaar_api`, ...). They may
   depend on `dwaar-common` but never on each other's internals.
4. **JS/TS with pnpm workspaces** for `apps/*`, `packages/contracts`, `packages/i18n`. Android (`apps/guard-android`) is a
   Gradle project outside both workspaces.
5. **Runtime stack** is the decision register default: FastAPI + Pydantic v2, SQLAlchemy 2 (sync) on psycopg 3, PostgreSQL
   16, Redis for job brokering, Next.js for the console, Expo for the resident app, Kotlin for the guard terminal.
6. **Tooling:** ruff (lint and format), mypy (strict), pytest + hypothesis. Shared Python rules are in the root
   `pyproject.toml`, the single source of truth.
7. **Shared-state discipline:** `make` targets run `uv run --no-sync`, so only `make setup` (and CI) touches `uv.lock` or
   the virtualenv; package-manager writes are wrapped in `flock` (`/tmp/dwaar-uv.lock`, `/tmp/dwaar-pnpm.lock`).

## Consequences

- One lockfile (`uv.lock`) and one set of tool versions for every Python package; a dependency bump is one reviewed change.
- `dwaar-common` is deliberately small and dependency-light (pydantic, cryptography, tzdata). Business rules never go in it.
- Anything outside PRD 19.1 needs a recorded reason (B-003) and, if it changes a decision-register default, an ADR first.

## Alternatives considered

- Per-service virtualenvs and lockfiles: more isolation, but version drift and slower cross-package work.
- Poetry/pip-tools: no workspace support comparable to uv for this layout.
- Putting shared code into `services/api`: would force the worker and edge to import the API, breaking the modular boundary.
