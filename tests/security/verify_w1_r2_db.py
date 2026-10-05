"""W1 verification round 2 (lens INVARIANTS + SECURITY): attacks against a real ephemeral PostgreSQL.

Not collected by ``make test`` (the file name does not start with ``test_``). Run explicitly:

    uv run --no-sync pytest tests/security/verify_w1_r2_db.py -p no:cacheprovider

A test that FAILS here is a confirmed defect: it asserts the SECURE behaviour. A test that passes is an
attack that was tried and did not succeed (regression evidence). Nothing here changes production code.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator

import psycopg
import pytest
from psycopg import errors
from sqlalchemy import text

from dwaar_api.core.db import Database, RequestContext
from dwaar_api.core.migrate import ADVISORY_LOCK_KEY
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    SOCIETY_A,
    SOCIETY_B,
    CoreHarness,
    core_harness,
    create_probe_table,
)
from tests.security.test_core_rls_isolation import find_rls_violations

pytestmark = pytest.mark.req("INV-01", "ARCH-01", "ARCH-03", "DB-02", "INV-02")

HASH = "sha256:" + "0" * 64


def _seed(db: DbHandle, society: uuid.UUID, *names: str) -> None:
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
        for name in names:
            conn.execute(
                "INSERT INTO probe_things (society_id, name) VALUES (%s, %s)", (society, name)
            )


@pytest.fixture
def two(db: DbHandle) -> DbHandle:
    create_probe_table(db)
    _seed(db, SOCIETY_A, "a-1", "a-2")
    _seed(db, SOCIETY_B, "b-1", "b-2", "b-3")
    return db


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


# ------------------------------------------------------------------------------------------------
# (1) the CI catalog guard is the ONLY control for future tables; attack its blind spots
# ------------------------------------------------------------------------------------------------
def test_guard_flags_a_policy_with_a_guc_controlled_escape_hatch(db: DbHandle) -> None:
    """``USING (society_id = <ctx> OR current_setting('app.admin_mode', true) = 'on')``. ANY SQL running as
    ``dwaar_app`` can ``set_config('app.admin_mode', 'on', true)`` and read every society (shown below). The
    guard probes the expression with the GUC unset, so the escape hatch evaluates to false and the table is
    reported clean."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE gucbypass (id int, society_id uuid NOT NULL, secret text)")
        conn.execute("ALTER TABLE gucbypass ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE gucbypass FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY p ON gucbypass USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid"
            " OR current_setting('app.admin_mode', true) = 'on')"
        )
        conn.execute("GRANT SELECT ON gucbypass TO dwaar_app")
        conn.execute("SELECT set_config('app.admin_mode', 'on', true)")
        conn.execute("INSERT INTO gucbypass VALUES (1, %s, 'B only')", (SOCIETY_B,))
    with db.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute("SELECT set_config('app.admin_mode', 'on', true)")
        stolen = conn.execute("SELECT secret FROM gucbypass").fetchall()
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert stolen == [("B only",)]  # the bypass is real
    assert any(p.startswith("gucbypass") for p in problems), (
        "guard is green on a GUC-bypassable policy"
    )


def test_guard_flags_a_policy_that_exempts_the_api_role_by_name(db: DbHandle) -> None:
    """``... OR current_user = 'dwaar_app'`` is evaluated by the guard as the superuser connection, so it is
    false there and true for the role that matters."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE rolebypass (id int, society_id uuid NOT NULL, secret text)")
        conn.execute("ALTER TABLE rolebypass ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE rolebypass FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY p ON rolebypass USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid"
            " OR current_user = 'dwaar_app')"
        )
        conn.execute("GRANT SELECT ON rolebypass TO dwaar_app")
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_B),))
        conn.execute("INSERT INTO rolebypass VALUES (1, %s, 'B only')", (SOCIETY_B,))
    with db.app_conn(society_id=SOCIETY_A) as conn:
        stolen = conn.execute("SELECT secret FROM rolebypass").fetchall()
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert stolen == [("B only",)]
    assert any(p.startswith("rolebypass") for p in problems), "guard is green on a role-name bypass"


def test_guard_sees_tables_outside_the_public_schema(db: DbHandle) -> None:
    """``find_rls_violations`` only enumerates ``nspname = 'public'``. A migration that creates a society
    table in another schema and grants USAGE + SELECT is invisible to the CI guard, and RLS-less (shown)."""
    with db.owner_conn() as conn:
        conn.execute("CREATE SCHEMA reporting")
        conn.execute("CREATE TABLE reporting.docs (id int, society_id uuid NOT NULL, body text)")
        conn.execute(
            "INSERT INTO reporting.docs VALUES (1, %s, 'A only'), (2, %s, 'B only')",
            (SOCIETY_A, SOCIETY_B),
        )
        conn.execute("GRANT USAGE ON SCHEMA reporting TO dwaar_app")
        conn.execute("GRANT SELECT ON reporting.docs TO dwaar_app")
    with db.app_conn(society_id=SOCIETY_A) as conn:
        visible = {r[0] for r in conn.execute("SELECT body FROM reporting.docs")}
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert visible == {"A only", "B only"}  # real cross-tenant read
    assert any("docs" in p for p in problems), "guard blind to non-public schemas"


# ------------------------------------------------------------------------------------------------
# (1e) worker over-grant
# ------------------------------------------------------------------------------------------------
def test_worker_cannot_read_response_bodies_of_other_societies_expired_keys(two: DbHandle) -> None:
    """The worker's expired-key policies exist for cleanup, but the grant is table-level ``SELECT`` so with NO
    society context the worker reads ``response_body`` (stored API responses: ids, names, amounts) of every
    society's expired keys. Cleanup only needs ``id`` / ``expires_at`` (column-level SELECT)."""
    with two.app_conn(society_id=SOCIETY_B) as conn:
        conn.execute(
            "INSERT INTO idempotency_keys (society_id, actor_id, key, endpoint, request_hash, state,"
            " response_status, response_body, completed_at, expires_at)"
            " VALUES (%s, %s, 'expired-key-0001', 'POST /x', %s, 'completed', 201,"
            " '{\"resident\": \"B private response\"}'::jsonb, now(), now() - interval '1 day')",
            (SOCIETY_B, uuid.uuid4(), HASH),
        )
    try:
        with two.worker_conn() as conn:  # no society context at all
            rows = conn.execute("SELECT response_body FROM idempotency_keys").fetchall()
    except errors.InsufficientPrivilege:
        rows = []
    assert rows == [], f"worker read another society's stored response: {rows}"


def test_outbox_refuses_two_events_for_the_same_aggregate_version(two: DbHandle) -> None:
    """PRD 12.4 orders events per aggregate version. ``outbox_aggregate_idx`` is not UNIQUE, so two concurrent
    writers that both read version N both emit version N+1 and the relay delivers two different events with
    the same (aggregate, version): consumers cannot order or deduplicate them."""
    aggregate = uuid.uuid4()
    for _ in range(2):
        try:
            with two.app_conn(society_id=SOCIETY_A) as conn:
                conn.execute(
                    "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id,"
                    " aggregate_version, event_type, occurred_at, actor_ref, correlation_id, payload, payload_hash)"
                    " VALUES (%s, 1, %s, 'probe_thing', %s, 5, 'ThingChanged', now(), 'system', %s, '{}'::jsonb, %s)",
                    (uuid.uuid4(), SOCIETY_A, aggregate, uuid.uuid4(), HASH),
                )
        except errors.UniqueViolation:
            return
    pytest.fail(
        "two outbox events share (society, aggregate_type, aggregate_id, aggregate_version)"
    )


# ------------------------------------------------------------------------------------------------
# (1b) pooled connections: what survives the pool reset
# ------------------------------------------------------------------------------------------------
def test_pool_reset_releases_session_level_advisory_locks(two: DbHandle) -> None:
    """``_reset_session`` runs ``ROLLBACK`` + ``RESET ALL``. Neither releases session-level advisory locks (or
    LISTEN registrations), so a lock taken in one request stays held by the pooled connection. The migration
    runner serialises on the constant ``ADVISORY_LOCK_KEY`` which is public in the source: one statement from
    any ``dwaar_app`` SQL blocks every future migration/deploy until the process restarts."""
    database = Database(two.app_dsn, pool_size=1, max_overflow=0)
    try:
        with database.app_engine.connect() as conn:
            conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": ADVISORY_LOCK_KEY})
            conn.commit()
        # connection returned to the pool: the next borrower must not inherit the lock
        with psycopg.connect(two.owner_dsn, autocommit=True) as other:
            got = other.execute("SELECT pg_try_advisory_lock(%s)", (ADVISORY_LOCK_KEY,)).fetchone()
            if got and got[0]:
                other.execute("SELECT pg_advisory_unlock(%s)", (ADVISORY_LOCK_KEY,))
        assert got == (True,), "advisory lock survived the pool reset and blocks the migrator"
    finally:
        database.dispose()


def test_runtime_roles_cannot_take_the_migration_advisory_lock(two: DbHandle) -> None:
    """Even if the pool is fixed, the lock key is a shared global namespace: dwaar_app may take ANY advisory
    lock. Reported with the test above; here the direct attack from a fresh connection."""
    with psycopg.connect(two.app_dsn, autocommit=True) as attacker:
        taken = attacker.execute("SELECT pg_try_advisory_lock(%s)", (ADVISORY_LOCK_KEY,)).fetchone()
        assert taken is not None
        with psycopg.connect(two.owner_dsn, autocommit=True) as migrator:
            free = migrator.execute(
                "SELECT pg_try_advisory_lock(%s)", (ADVISORY_LOCK_KEY,)
            ).fetchone()
            if free and free[0]:
                migrator.execute("SELECT pg_advisory_unlock(%s)", (ADVISORY_LOCK_KEY,))
        assert free == (True,) or taken == (False,), (
            "dwaar_app can block migrations with one statement"
        )


# ------------------------------------------------------------------------------------------------
# attacks that were tried and did NOT work (regression evidence)
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["app", "worker"])
@pytest.mark.parametrize(
    "statement",
    [
        "SET session_replication_role = replica",
        "ALTER TABLE audit_log DISABLE TRIGGER ALL",
        "ALTER TABLE outbox DISABLE TRIGGER dwaar_history_guard",
        "DROP TRIGGER dwaar_append_only_row ON audit_log",
        "ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY",
        "DROP POLICY audit_log_read ON audit_log",
        "CREATE POLICY evil ON audit_log USING (true)",
        "TRUNCATE audit_log",
        "TRUNCATE outbox",
        "DELETE FROM audit_log",
        "UPDATE audit_log SET reason = 'x'",
        "UPDATE outbox SET payload = '{}'::jsonb",
        "SELECT * FROM audit_log FOR SHARE",
        "COPY audit_log TO STDOUT",
        "COPY (SELECT 1) TO PROGRAM 'id'",
        "SELECT dwaar_purge_append_only('audit_log'::regclass, ARRAY[gen_random_uuid()], 'attack reason')",
        "SELECT dwaar_enable_society_rls('audit_log')",
        "SELECT set_config('dwaar.purge_table', 'audit_log'::regclass::oid::text, true); DELETE FROM audit_log",
        "ALTER ROLE dwaar_app BYPASSRLS",
        "SET row_security = off; SELECT 1 FROM probe_things",
    ],
)
def test_runtime_roles_cannot_defeat_history_protection(
    two: DbHandle, role: str, statement: str
) -> None:
    opener = two.app_conn if role == "app" else two.worker_conn
    with pytest.raises(psycopg.Error):
        with opener(society_id=SOCIETY_A) as conn:
            conn.execute(statement)  # type: ignore[call-overload]
            # `SET row_security = off` is only an error for roles that would have to bypass; reading must
            # still come back empty rather than succeed with rows
            if statement.startswith("SET row_security"):
                rows = conn.execute("SELECT 1 FROM probe_things").fetchall()
                assert rows == [], "row_security=off exposed rows"
                raise psycopg.Error("rows hidden")


def test_grant_attempts_by_runtime_roles_change_nothing(two: DbHandle) -> None:
    """GRANT without grant option is only a WARNING in PostgreSQL, so check the privilege itself."""
    for opener in (two.app_conn, two.worker_conn):
        with opener(society_id=SOCIETY_A) as conn:
            conn.execute("GRANT UPDATE, DELETE ON audit_log TO dwaar_app, dwaar_worker, PUBLIC")
    with two.admin_conn() as conn:
        row = conn.execute(
            "SELECT has_table_privilege('dwaar_app', 'audit_log', 'UPDATE'),"
            " has_table_privilege('dwaar_worker', 'audit_log', 'DELETE'),"
            " has_table_privilege('public', 'audit_log', 'UPDATE')"
        ).fetchone()
    assert row == (False, False, False)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("row_security", "off"),
        ("default_transaction_read_only", "on"),
        ("lock_timeout", "1"),
    ],
)
def test_runtime_role_cannot_persistently_poison_its_own_session_defaults(
    two: DbHandle, setting: str, value: str
) -> None:
    """Any role may ``ALTER ROLE <itself> SET ...`` (role-level defaults are cluster state and survive
    restarts). One injected statement as ``dwaar_app`` such as ``ALTER ROLE dwaar_app SET row_security = off``
    makes EVERY later query on an RLS table fail with 42501 (which the API maps to 404 not_found), or
    ``default_transaction_read_only = on`` turns every write into an error: a persistent outage that only a
    superuser can clear. ``RESET ALL`` in the pool reset returns to the poisoned default. Startup ``options``
    (``-c``) outrank role defaults, so the engine should PIN row_security / read-only / lock_timeout there."""
    planted = False
    try:
        with psycopg.connect(two.app_dsn, autocommit=True) as conn:
            try:
                conn.execute(f"ALTER ROLE dwaar_app SET {setting} = '{value}'")  # type: ignore[call-overload]
                planted = True
            except errors.InsufficientPrivilege:
                return  # denied: secure
        database = Database(two.app_dsn, pool_size=1, max_overflow=0)
        try:
            ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.uuid4())
            with database.app_tx(ctx) as conn:
                conn.execute(
                    text("INSERT INTO probe_things (society_id, name) VALUES (:s, 'after-poison')"),
                    {"s": SOCIETY_A},
                )
                count = conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one()
            assert count >= 1
        finally:
            database.dispose()
    finally:
        if planted:
            with two.admin_conn() as admin:
                admin.execute(f"ALTER ROLE dwaar_app RESET {setting}")  # type: ignore[call-overload]


def test_worker_cannot_park_published_events_or_rewrite_content(two: DbHandle) -> None:
    with two.app_conn(society_id=SOCIETY_A) as conn:
        event_id = uuid.uuid4()
        conn.execute(
            "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id,"
            " aggregate_version, event_type, occurred_at, actor_ref, correlation_id, payload, payload_hash)"
            " VALUES (%s, 1, %s, 'probe_thing', %s, 1, 'ThingCreated', now(), 'system', %s, '{}'::jsonb, %s)",
            (event_id, SOCIETY_A, uuid.uuid4(), uuid.uuid4(), HASH),
        )
    with two.worker_conn() as conn:
        conn.execute("UPDATE outbox SET published_at = now() WHERE event_id = %s", (event_id,))
    with pytest.raises(psycopg.Error):
        with two.worker_conn() as conn:
            conn.execute("UPDATE outbox SET published_at = NULL WHERE event_id = %s", (event_id,))
    with pytest.raises(psycopg.Error):
        with two.worker_conn() as conn:
            conn.execute(
                "UPDATE outbox SET society_id = %s WHERE event_id = %s", (SOCIETY_B, event_id)
            )
    with pytest.raises(psycopg.Error):
        with two.worker_conn() as conn:
            conn.execute(
                "UPDATE outbox SET attempts = attempts - 5 WHERE event_id = %s", (event_id,)
            )


def test_forged_audit_rows_cannot_name_another_society(two: DbHandle) -> None:
    with pytest.raises(errors.InsufficientPrivilege):
        with two.app_conn(society_id=SOCIETY_A) as conn:
            conn.execute(
                "INSERT INTO audit_log (society_id, actor_id, effective_role, operation, object_type)"
                " VALUES (%s, %s, 'committee', 'forge.op', 'x')",
                (SOCIETY_B, COMMITTEE_A),
            )


# ------------------------------------------------------------------------------------------------
# (6) HTTP: unhandled 500s
# ------------------------------------------------------------------------------------------------
def test_unhandled_500_carries_the_same_safe_headers_as_every_other_response(
    core: CoreHarness,
) -> None:
    """``RequestContextMiddleware`` adds ``Cache-Control: no-store`` and ``X-Content-Type-Options: nosniff`` in
    its ``send`` wrapper, but the generic ``Exception`` handler runs in Starlette's outer
    ServerErrorMiddleware, outside that wrapper: a 500 body is cacheable and sniffable."""
    resp = core.client().post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "crash-key-000001"},
        json={"name": "__crash__"},
    )
    assert resp.status_code == 500
    assert resp.json()["code"] == "internal_error"
    assert resp.headers.get("cache-control") == "no-store", dict(resp.headers)
    assert resp.headers.get("x-content-type-options") == "nosniff", dict(resp.headers)


def test_error_responses_never_contain_the_sql_or_the_exception_text(core: CoreHarness) -> None:
    resp = core.client().post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "crash-key-000002"},
        json={"name": "__crash__"},
    )
    body = resp.text
    for needle in ("boom", "Traceback", "INSERT", "probe_things", "psycopg", "sqlalchemy"):
        assert needle not in body, needle


def test_request_context_actor_role_with_newline_cannot_reach_a_guc(two: DbHandle) -> None:
    """Regression check for the trailing-newline validator gap: the GUC value is stored verbatim, so a
    role string with a newline would break any ``current_setting('app.actor_role') = 'committee'`` policy
    in the OPPOSITE direction (fails closed here), proving the value is not normalised."""
    ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee\n", uuid.uuid4())
    database = Database(two.app_dsn, pool_size=1, max_overflow=0)
    try:
        with database.app_tx(ctx) as conn:
            value = conn.execute(text("SELECT current_setting('app.actor_role')")).scalar_one()
        assert value == "committee", repr(value)
    finally:
        database.dispose()


def test_clock_is_not_trusted_for_expiry_reclaim_across_actors(two: DbHandle) -> None:
    """Sanity: an expired key of ANOTHER actor in the same society is not reclaimable by a different actor
    through the unique index (scope includes actor_id)."""
    key = "shared-key-00001"
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    with two.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute(
            "INSERT INTO idempotency_keys (society_id, actor_id, key, endpoint, request_hash, expires_at)"
            " VALUES (%s, %s, %s, 'POST /x', %s, %s)",
            (SOCIETY_A, uuid.uuid4(), key, HASH, past),
        )
    with two.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute(
            "INSERT INTO idempotency_keys (society_id, actor_id, key, endpoint, request_hash, expires_at)"
            " VALUES (%s, %s, %s, 'POST /x', %s, now() + interval '1 day')",
            (SOCIETY_A, uuid.uuid4(), key, HASH),
        )


def test_runtime_role_cannot_change_its_own_password(two: DbHandle) -> None:
    """``ALTER ROLE <self> PASSWORD`` is allowed for any role. One injected statement locks the API out of
    its own database (new connections fail under scram auth) until a superuser resets it. The harness cluster
    uses trust auth, so the lock-out itself cannot be shown here; the privilege is. The password is restored
    afterwards so other tests keep working."""
    changed = False
    try:
        try:
            with psycopg.connect(two.app_dsn, autocommit=True) as conn:
                conn.execute("ALTER ROLE dwaar_app PASSWORD 'attacker-chosen-pw'")
                changed = True
        except errors.InsufficientPrivilege:
            return
        pytest.fail("dwaar_app can change its own password (persistent lock-out of the API)")
    finally:
        if changed:
            with two.admin_conn() as admin:
                admin.execute("ALTER ROLE dwaar_app PASSWORD 'test-only-app-pw'")


def test_large_money_amounts_survive_the_outbox_and_audit_path(core: CoreHarness) -> None:
    """End to end through ``mutation()``: an event payload ``{"settled": 250_000_000}`` is stored as
    ``"[REDACTED]"`` because nine digits look like a phone number (see the pure-function test)."""
    from dwaar_api.core.audit import MutationResult, mutation

    ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.uuid4())

    def apply(c: object) -> MutationResult:
        return MutationResult(
            uuid.uuid4(), 1, after={"credit": 250_000_000}, event_payload={"settled": 250_000_000}
        )

    with core.database.app_tx(ctx) as conn:
        mutation(
            conn, ctx, operation="probe.settle", object_type="probe_thing",
            event_type="SettlementMatched", apply=apply,
        )  # fmt: skip
    with core.database.app_tx(ctx) as conn:
        payload = conn.execute(text("SELECT payload FROM outbox")).scalar_one()
        diff = conn.execute(text("SELECT diff_masked FROM audit_log")).scalar_one()
    assert payload == {"settled": 250_000_000}, payload
    assert diff["changed"]["credit"]["after"] == 250_000_000, diff


def test_a_superuser_database_role_with_an_innocent_name_never_serves_traffic(db: DbHandle) -> None:
    """ARCH-03: the API must never run as a superuser / BYPASSRLS role. Two gaps:

    * ``Settings`` only blocks four role NAMES (dwaar_owner, postgres, postgresql, root); any other
      superuser (``platform_admin``, ``rdsadmin``, ``supabase_admin`` ...) passes configuration.
    * The real check (``assert_restricted_role``) runs once in the lifespan and is SKIPPED, with only a
      warning, when the database is unreachable at boot. Nothing ever re-runs it, ``/readyz`` does not
      look at it, so an API that boots while the database is briefly down serves every request as a
      superuser with RLS bypassed.
    """
    from fastapi.testclient import TestClient

    from dwaar_api.core.config import Settings
    from dwaar_api.main import create_app
    from tests._harness.pgfixtures import make_dsn

    with db.admin_conn() as admin:
        admin.execute("CREATE ROLE platform_admin LOGIN SUPERUSER")
    try:
        dsn = make_dsn(db.admin_dsn, user="platform_admin")
        settings = Settings.model_validate(
            {"env": "test", "database_url": dsn, "cursor_signing_key": "k" * 40}
        )  # accepted: the role name is not on the blocklist

        class FlakyAtBoot(Database):
            calls = 0

            def assert_restricted_role(self) -> None:
                FlakyAtBoot.calls += 1
                if FlakyAtBoot.calls == 1:  # the database is "down" exactly while the lifespan runs
                    raise psycopg.OperationalError("connection refused (simulated)")
                super().assert_restricted_role()

        database = FlakyAtBoot(dsn)
        app = create_app(settings, database=database, modules_package=None)
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                ready = client.get("/readyz")
                with database.app_engine.connect() as conn:
                    is_super = conn.execute(
                        text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                    ).scalar_one()
            assert is_super is True  # the premise: this API process runs as a superuser
            assert ready.status_code != 200, (
                "API reports ready while connected as a superuser (RLS bypassed)"
            )
        finally:
            database.dispose()
    finally:
        with db.admin_conn() as admin:
            admin.execute("DROP ROLE platform_admin")
