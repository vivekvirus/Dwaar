# ADR-0004: Row-level security context, roles and the SQL helpers

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team
- Related: PRD INV-01, ARCH-01, ARCH-03, ARCH-04, DB-02; ADR-0002, ADR-0003; code: `services/api/migrations/0001-0007`,
  `dwaar_api.core.db`, `dwaar_api.core.migrate`; tests: `tests/security/test_core_rls_isolation.py`

## Context

ADR-0002 fixed the shape (three roles, society policy on `app.society_id`, context set per transaction, missing context
gives zero rows). This ADR records how the platform core makes that the default for every later migration, and what it
deliberately does not protect against.

## Decision

1. **Context.** `dwaar_api.core.db.transaction()` opens one transaction and sets `app.society_id`, `app.person_id`,
   `app.actor_role`, `app.request_id` with `set_config(name, value, true)` (transaction-local). Nothing survives COMMIT or
   ROLLBACK, so a pooled connection never carries a previous request's society. `RequestContext` is a frozen dataclass whose
   ids must be `uuid.UUID` and whose role must match `^[a-z][a-z0-9_]{0,63}$`; the values come only from the server-derived
   authorisation scope (ADR-0006), never from the request.
2. **Engines.** `Database` holds an engine for `dwaar_app` and optionally `dwaar_worker`. There is no owner engine at
   runtime. Settings refuse an application URL whose user is `dwaar_owner`, `postgres` or `root`, and the application
   lifespan refuses to start when the connected role is a superuser or has BYPASSRLS. Engines use `hide_parameters=True` so bound
   values (names, phones) never reach exception text or logs, and set `statement_timeout` and `idle_in_transaction_session_timeout`.
3. **`dwaar_enable_society_rls(tbl [, app_privileges, worker_privileges])`** (migration 0003) is called by every migration
   right after `CREATE TABLE`. It requires a `uuid` column `society_id`, makes it `NOT NULL`, runs `ENABLE` + `FORCE ROW LEVEL
   SECURITY`, creates the policy `dwaar_society_isolation` (`USING` and `WITH CHECK` on
   `society_id = nullif(current_setting('app.society_id', true), '')::uuid`), resets grants and then grants the requested
   privileges to `dwaar_app` / `dwaar_worker` (default full CRUD for both; pass narrower lists when a table needs them), including
   `USAGE` on owned sequences. The `nullif` makes an empty or never-set context a NULL predicate: zero rows, failed writes. A
   garbage context value (not a uuid) raises instead of matching anything. The policy applies to PUBLIC, so the owner needs a
   context too (FORCE); migrations that seed data set one.
4. **`dwaar_make_append_only(tbl)`** adds row triggers rejecting UPDATE and DELETE and a statement trigger rejecting TRUNCATE
   for every role including superusers (SQLSTATE `DW001`), and revokes UPDATE/DELETE/TRUNCATE from `dwaar_app` and
   `dwaar_worker`. Call order relative to the RLS helper does not matter: the RLS helper re-strips those privileges when it
   sees the trigger (DB-02).
5. **Purge path.** `dwaar_purge_append_only(tbl, ids, reason, society, id_column)` is `SECURITY DEFINER`, owner-only
   (`REVOKE ... FROM PUBLIC`), sets a transaction-local flag holding the table OID, deletes by id only, restores the previous
   `app.society_id`, and writes `purge_log` (itself append-only, no purge path). The triggers accept the flag only for a
   DELETE issued by the table owner, so a role that merely forges the flag (the GUC is settable by anyone) is still stopped
   by the missing DELETE privilege and by the owner check. The privacy engine (migrations 0700+) is the intended caller.
6. **Migration runner.** Plain SQL in `services/api/migrations/NNNN_name.sql`, ledger `schema_migrations` with sha256
   checksums, a session-level advisory lock (concurrent runners serialise; the second finds nothing to do), one transaction
   per file together with its ledger row, hard error on an edited or missing applied file, files may not contain their own
   BEGIN/COMMIT. A late-arriving lower version (another area's range merged later) is applied in version order; the ledger is
   not required to be a prefix. CLI: `python -m dwaar_api.core.migrate up|status`.
7. **Guard for the future.** `tests/security/test_core_rls_isolation.py::test_every_society_table_has_force_rls_and_a_society_policy`
   inspects the catalog: every table in `public` with a `society_id` column must have RLS enabled and FORCEd, a NOT NULL column
   (two documented exceptions below), at least one policy referencing `app.society_id`, no policy for PUBLIC that is
   `USING (true)`, and no grants to PUBLIC. The guard itself is tested against deliberately broken tables.

## Decisions on edge cases

- **`audit_log.society_id` and `purge_log.society_id` are nullable.** Platform-level events (sign-in failures, society
  creation) have no society. The application may insert such rows but no society context can read them. Both tables have
  hand-written policies and are the only entries in the catalog test's allow-list.
- **The outbox relay sees all societies.** It must claim pending events across tenants, so `outbox` has extra policies
  `TO dwaar_worker` (`USING (true)`), limited by a column-level grant (`published_at, attempts, next_attempt_at,
  last_error`) and by a guard trigger. The API role never gets them. Likewise `dwaar_worker` can see and delete only
  expired `idempotency_keys`.
- **Migration 0001-0007 were edited before first use.** Nothing had been applied outside throw-away test databases;
  from now on applied files are immutable (checksums enforce it).

## Fix round 1 additions (B-009)

- `RequestContext.all_settings()` writes all four GUCs on every transaction (empty when unset, also for `app_tx(None)`) and the
  pool resets sessions with `RESET ALL` on check-in, so a stray session-level `SET app.society_id` cannot scope a later
  society-less transaction.
- The generic society policy of `idempotency_keys` applies to `dwaar_app` and `dwaar_owner` only (migration 0008): the worker
  keeps just its two expired-rows-only policies and cannot delete live keys even with a society context.
- The catalog guard is deny-by-default and semantic (see `find_rls_violations`): every relation a runtime role can use needs
  `society_id` + FORCE RLS or a reviewed allowlist entry; matviews and foreign tables are banned; views owned by a role that
  bypasses RLS are flagged; policies are evaluated against a foreign society; cross-society worker/owner policies are allowlisted
  by (table, policy name). The database cannot refuse a `GRANT` on a matview (event triggers need a superuser), so CI is the control.

## Accepted risks (documented, not hidden)

- The application role can call `set_config('app.society_id', ...)` itself: RLS defends against forgotten filters and cross-
  tenant bugs, not against SQL injection in the API process. The primary gate stays the permission service plus
  parameterised SQL.
- The table owner can forge the purge flag. The owner is the migration role and can drop triggers anyway; it is never used at runtime.
- A **global** unique index is an existence oracle across societies (the unique-violation error reveals the foreign row).
  Unique constraints on society-owned tables must include `society_id`; the security test demonstrates both forms.
- Pooled connections reading `current_setting` after COMMIT see `''`, not NULL. Policies use `nullif`, and any code reading
  the setting directly must too.

## Consequences

- A forgotten `set_config` fails closed. A forgotten helper call fails the catalog test, not production.
- `docs/BUILD_BRIEF.md` module authors: call `dwaar_enable_society_rls` once per table, put extra grants after it, scope unique
  indexes by `society_id`, never re-run an applied migration with edits.

## Alternatives considered

- Superuser or BYPASSRLS for workers: rejected; the relay gets targeted policies instead.
- Session-level `SET` plus reset on checkout: rejected; transaction-local `set_config` cannot leak by construction.
- Trigger-only append-only enforcement without privilege revocation: rejected; two independent layers are cheaper than one bug.
