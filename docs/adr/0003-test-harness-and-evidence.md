# ADR-0003: Test harness and acceptance evidence

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team
- Related: PRD 4.3, 16, 19.2 rule 5, INV-12; B-007

## Context

Acceptance tests (AT-01..AT-48) are the contract, and "done" must be backed by recorded evidence, not by assertion.
Database behaviour (roles, RLS, constraints) can only be tested against a real PostgreSQL with the real roles. Many builders
run tests concurrently on one machine, and nothing may leak processes or databases.

## Decision

1. **One pytest plugin, `tests._harness.plugin`**, registered via `-p` in the root `addopts` so it works from any test
   directory without conftest boilerplate. Strict markers: `req(*ids)`, `at(id, dataset=None)`, `milestone(name)`,
   `simulation`, `slow`.
2. **PostgreSQL for tests.** Session fixture `pg_server` either uses `DWAAR_TEST_PG_ADMIN_URL` (CI service container) or
   starts a private ephemeral cluster: random free port, trust auth on 127.0.0.1, data under a private temp directory, run as
   the `postgres` OS user through `runuser` when the tests run as root. It is stopped by the fixture finalizer, `atexit`, a
   SIGTERM handler, and a startup sweep that removes clusters whose owner process died (pidfile based). Durability is turned
   off (`fsync=off`): the cluster is disposable.
3. **Production-parity roles.** The harness bootstraps the same `dwaar_owner` / `dwaar_app` / `dwaar_worker` roles as
   production (`infra/db/bootstrap_roles.sql`) and tests connect as those roles. Test credentials are fixed, documented,
   test-only constants.
4. **Fast isolated databases.** `template_db` (session) creates a database through `infra/db/create_database.sql` and runs
   `dwaar_api.core.migrate.run_migrations(owner_dsn)` (imported lazily; DB-backed tests skip with a clear message while the
   module does not exist yet). `db` (function) is a `CREATE DATABASE ... TEMPLATE` clone dropped with `FORCE` afterwards. The
   handle exposes `admin_dsn`, `owner_dsn`, `app_dsn`, `worker_dsn` and connection helpers; `app_conn(society_id, person_id,
   actor_role)` applies transaction-local `set_config` exactly as the API does.
5. **Evidence.** With `--evidence`, each acceptance test that ran produces `docs/evidence/<AT-ID>.json` (id, milestone,
   scenario, expected, observed outcome and failure message, commit, environment, dataset, trace, tester, date), plus
   `docs/evidence/INDEX.md` and a machine-readable `docs/evidence/_run.json` of every `req`/`at` test. Tests that did not run
   produce nothing and appear in the index as "no evidence yet"; skipped tests are reported as skipped, never as passed.
   Simulated, staging and field results are different evidence classes: simulator-backed tests carry `@pytest.mark.simulation`
   and the evidence records `simulation: true`.
6. **Marker validation** aborts collection on malformed IDs, unknown ATs, bad milestones, or a milestone that contradicts
   `docs/traceability/acceptance_matrix.yaml`.
7. **`make acceptance MILESTONE=Mx`** runs `pytest --evidence --milestone Mx -m at`; selection is cumulative.
8. The harness is itself tested (`tests/harness/`): cluster lifecycle with no leaked processes, role attributes and RLS
   behaviour, clone isolation, evidence writer in a temp directory, marker validation.

## Consequences

- Tests exercise the same permission model as production; an RLS or grant mistake fails a test instead of passing as superuser.
- A pytest session pays one PostgreSQL start (about a second measured on the build machine, including teardown); each `db` is a template copy, which stays cheap while the schema is small.
- Tests must not rely on collation order beyond `C`, nor on a particular port or data directory.
- Evidence files are generated artefacts; committing them is the orchestrator's decision per milestone.
