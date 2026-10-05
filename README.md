# Dwaar

Ad-free, offline-first community operating platform for Indian gated communities. Monorepo layout follows PRD 19.1.
Read [`docs/BUILD_BRIEF.md`](docs/BUILD_BRIEF.md) first, then [`DECISIONS.md`](DECISIONS.md) and [`docs/adr/`](docs/adr/).

```
apps/        admin-web (Next.js), resident-mobile (Expo), guard-android (Kotlin)   [added by later steps]
services/    api (FastAPI), worker, edge, ai-gateway
packages/    dwaar-common (shared Python), contracts, i18n, legal-packs, tax-packs, prompts
infra/       db/ (role + database bootstrap SQL), docker-compose.yml
tests/       _harness (pytest plugin), harness (its self-tests), integration, acceptance, security ...
tools/       dev/ (pg.sh, devenv, migrate, seed), trace_check.py
docs/        PRD (local only), ADRs, evidence, reports, traceability
```

## Prerequisites

Python 3.12 and [uv](https://docs.astral.sh/uv/), PostgreSQL 16 server binaries (`initdb`, `postgres`, `psql`), `make`,
`flock`. Node 22 and pnpm only once JS projects exist. Redis 7 is needed only for worker work. Docker is optional.

## Local startup

```bash
make setup      # uv sync (flock-guarded), create .env with freshly generated local keys, pnpm install if JS projects exist
make db-up      # persistent dev PostgreSQL under .local/pg on port 55432 (roles, database, extensions)
make migrate    # apply SQL migrations as dwaar_owner (says so if the migration runner is not built yet)
make seed       # synthetic demo data, DWAAR_ENV=local only (says so if not implemented yet)
make api        # FastAPI on http://127.0.0.1:8000 (foreground, Ctrl-C to stop)
make db-down    # stop the dev database
```

* `make db-reset` drops and recreates the empty dev database; follow it with `make migrate`.
* Running as root is supported: PostgreSQL then runs as the `postgres` OS user through `runuser`.
* No local PostgreSQL binaries but Docker available: `docker compose -f infra/docker-compose.yml up -d` gives the same
  roles, database, ports and Redis (see `.env.example`; `docker-init` runs the same SQL files).
* `.env` is git-ignored and created once by `make setup`; the process environment overrides `.env`, which overrides
  `.env.example`. Add every new variable to `.env.example` with a comment.

## Quality gates

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy (strict) over source packages, tools and the harness
make test        # everything under tests/, services/, packages/, tools/
make trace       # requirement traceability (tools/trace_check.py)
make acceptance MILESTONE=M0   # AT tests tagged up to M0 with --evidence (cumulative); MILESTONE=M1 includes M0
make format      # apply ruff fixes and formatting
```

`make` targets use `uv run --no-sync`, so they never modify `uv.lock` or the virtualenv; run `make setup` after pulling
dependency changes. Use `PYTEST_ARGS="-k name -x"` to pass arguments to pytest.

### Tests and the database

`make test` needs no database setup. The harness starts a private ephemeral PostgreSQL per pytest session and removes it
afterwards; set `DWAAR_TEST_PG_ADMIN_URL=postgresql://postgres:...@host:5432/postgres` to use an existing server instead
(CI does). DB tests receive a clone of a migrated template through the `db` fixture, connect as the real restricted roles
and set request context exactly like the API:

```python
def test_isolation(db):
    with db.app_conn(society_id=a, person_id=p, actor_role="committee") as conn:
        ...
```

Until `dwaar_api.core.migrate` exists, tests using `db` are skipped with an explanatory message. See
[ADR-0003](docs/adr/0003-test-harness-and-evidence.md). Tag tests with `@pytest.mark.req("GATE-03")` and
`@pytest.mark.at("AT-04")`; evidence appears under `docs/evidence/` after `make acceptance`.

## Conventions in one place

Money is integer paise (`dwaar_common.money`), time is UTC (present IST), identifiers are UUIDv7 (`dwaar_common.ids`),
errors use the PRD 12.2 codes (`dwaar_common.errors`), logs go through the scrubber (`dwaar_common.logging`), user-visible
strings come from i18n keys (`dwaar_common.i18n`, catalogs in `packages/i18n/locales/<lang>/<namespace>.json`). Legal and
tax values are never hard-coded: they come from versioned, approved packs. No ad or tracking SDKs. Simulators are labelled
`simulation=true`; demo logins exist only with `DWAAR_ENV=local`.
