# Dwaar

Ad-free, offline-first community operating platform for Indian gated communities. Monorepo layout follows PRD 19.1.
Read [`docs/BUILD_BRIEF.md`](docs/BUILD_BRIEF.md) first, then [`DECISIONS.md`](DECISIONS.md) and [`docs/adr/`](docs/adr/).

```
apps/        admin-web (Next.js), resident-mobile (Expo), guard-android (Kotlin)   [added by later steps]
services/    api (FastAPI), worker, edge, ai-gateway
packages/    dwaar-common (shared Python), dwaar-packs (law-as-configuration evaluators), contracts, i18n, legal-packs, tax-packs
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
make migrate    # apply SQL migrations as dwaar_owner (dwaar_api.core.migrate; checksummed, one transaction per file)
make seed       # synthetic demo data, DWAAR_ENV=local only (see "Local demo"); safe to run again
make api        # FastAPI on http://127.0.0.1:8000 (foreground, Ctrl-C to stop; uvicorn's own access log is dropped; the JSON access log of the app records the route template, never the raw path or query)
make db-down    # stop the dev database
```

* `make db-reset` drops and recreates the empty dev database; follow it with `make migrate`.
* Running as root is supported: PostgreSQL then runs as the `postgres` OS user through `runuser`.
* No local PostgreSQL binaries but Docker available: `docker compose -f infra/docker-compose.yml up -d` gives the same
  roles, database, ports and Redis (see `.env.example`; `docker-init` runs the same SQL files).
* `.env` is git-ignored and created once by `make setup`; the process environment overrides `.env`, which overrides
  `.env.example`. Add every new variable to `.env.example` with a comment.

## Edge gateway and worker (local simulation)

`make seed` also enrols a society **gateway** per demo society (simulation, a key derived from a public label) and publishes a first signed policy snapshot; `DWAAR_SEED_EDGE=0` skips it.
The on-site gateway (`services/edge`, `python -m dwaar_edge`) is commissioned like this: a guard requests the enrolment with the gateway's PUBLIC key, a different supervisor approves it, then
`python -m dwaar_edge.provision` (device-signed `GET /v1/edge/keys`) prints the issuer and guest-pass keys to pin as `DWAAR_EDGE_ISSUER_KEYS` / `DWAAR_EDGE_PASS_KEYS`. See ADR-0018 and ADR-0019.
Background jobs (policy publisher, visits expiry and overstay sweep): `make worker` (Dramatiq on `DWAAR_REDIS_URL`, needs Redis) and `make scheduler`; the job functions themselves need no Redis.
The edge and cloud have run against each other only in simulation (`tests/integration/edge_e2e`, `docs/reports/slice-3.md`).

## Local demo

`make seed` fills the dev database with a synthetic dataset (PRD 8.3, slice 1 part). It refuses to run unless
`DWAAR_ENV=local`, writes through the real service functions as the restricted `dwaar_app` role (so every row has its audit
and outbox record), is deterministic (fixed UUIDv7 time, ids derived from stable keys) and idempotent (run it again: nothing
changes; `make db-reset && make migrate && make seed` starts over).

| What | Content |
|---|---|
| Sahyadri Residency CHS (demo), Pune, Maharashtra | 3 blocks (A 100, B 80, C 60 units = 240); legal pack `maharashtra-chs`, **unapproved**, so binding governance is off |
| Nandana Apartments Owners Association (demo), Bengaluru, Karnataka | 2 blocks (Tower 1 100, Tower 2 80 = 180); legal pack `karnataka-aoa-1972`, unapproved |
| Staff and committee | secretary, treasurer, committee, estate manager, guards, guard supervisor, time-bound auditor per society; elevated roles have a confirmed synthetic TOTP factor |
| People scenarios | unit labels repeated across blocks; owners with several memberships; a non-resident owner and her tenant; an active tenant whose owner is absent; a disputed move-out; family approvals (2 approved, 1 pending, 1 rejected); a mover who left Society A for B; a committee hold; 64 generated owner-occupiers |

Not seeded yet (their slices add them as `services/api/dwaar_api/seed/steps/sNNN_*.py`): guard shifts, visits, invoices,
receipts, bank lines, settlements.

Everything is invented. Phone numbers are the reserved fictional range `+91 99999 0nnnn`. **Demo logins exist only through
the labelled local identity simulator** (`simulation=true`, mounted only when `DWAAR_ENV` is `local` or `test`); there is no
password and no other way in. `uv run --no-sync python tools/dev/devenv.py exec -- python -m dwaar_api.seed demo-logins` prints every seeded person with the role and scenario (the `devenv exec` wrapper loads `.env` so `DWAAR_ENV=local` is set).

```bash
make api &                                    # the API on http://127.0.0.1:8000
P=+919999901001                               # Anita Kulkarni, secretary of Sahyadri (MH)
curl -s -X POST localhost:8000/v1/auth/otp/request -H 'Content-Type: application/json' -d "{\"phone\":\"$P\"}"
OTP=$(curl -s "localhost:8000/v1/dev/otp?phone=%2B919999901001" | python -c 'import json,sys; print(json.load(sys.stdin)["otp"])')
TOKEN=$(curl -s -X POST localhost:8000/v1/auth/otp/verify -H 'Content-Type: application/json' \
  -d "{\"phone\":\"$P\",\"code\":\"$OTP\",\"device\":{\"device_id\":\"demo\",\"label\":\"curl\"}}" \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
# elevated roles (secretary, treasurer, committee, estate manager, guard supervisor, auditor) must step up with TOTP,
# otherwise society routes answer 403 not_authorised; the seeded secret is derived from the number:
CODE=$(uv run --no-sync python tools/dev/devenv.py exec -- python -m dwaar_api.seed totp $P)
curl -s -X POST localhost:8000/v1/auth/mfa/verify -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\"}"
curl -s localhost:8000/v1/me -H "Authorization: Bearer $TOKEN"          # who the server says you are, per society
```

Useful personas: `+91 99999 01101` Meera Joshi (secretary of Nandana **and** non-resident owner in Sahyadri: AT-01/AT-02),
`01212` Vikram Nair (moved from Sahyadri to Nandana), `01213` Farhan Sheikh (Nandana only), `01205` Imran Qureshi (tenant,
owner absent), `01204` Dev Rane (tenant, move-out disputed). Residents have no second factor. The TOTP secrets protect nothing:
the people, the numbers and the database are synthetic, and the seed will not run anywhere but local.

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

See [ADR-0003](docs/adr/0003-test-harness-and-evidence.md). Tag tests with `@pytest.mark.req("GATE-03")` and
`@pytest.mark.at("AT-04")`; evidence appears under `docs/evidence/` after `make acceptance`.

## Conventions in one place

Money is integer paise (`dwaar_common.money`), time is UTC (present IST), identifiers are UUIDv7 (`dwaar_common.ids`),
errors use the PRD 12.2 codes (`dwaar_common.errors`), logs go through the scrubber (`dwaar_common.logging`), user-visible
strings come from i18n keys (`dwaar_common.i18n`, catalogs in `packages/i18n/locales/<lang>/<namespace>.json`). Legal and
tax values are never hard-coded: they come from versioned, approved packs. No ad or tracking SDKs. Simulators are labelled
`simulation=true`; demo logins exist only with `DWAAR_ENV=local`.
