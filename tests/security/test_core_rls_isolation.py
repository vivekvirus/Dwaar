"""Tenant isolation and database hardening of the platform core (INV-01, ARCH-01, ARCH-03, DB-02).

Every check uses the REAL restricted roles (``dwaar_app`` / ``dwaar_worker``: NOSUPERUSER NOBYPASSRLS),
never the superuser. The catalog test at the bottom guards every FUTURE migration: a society-owned table
without FORCE RLS and a society policy turns the build red.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import psycopg
import pytest
from psycopg import errors

from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import COMMITTEE_A, SOCIETY_A, SOCIETY_B, create_probe_table

pytestmark = pytest.mark.req("INV-01", "ARCH-01", "ARCH-03")

AUDIT_COLS = "(society_id, actor_id, effective_role, operation, object_type, object_id)"


def _with_society(conn: psycopg.Connection[Any], society: uuid.UUID) -> None:
    conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))


def seed_things(db: DbHandle, society: uuid.UUID, *names: str) -> list[uuid.UUID]:
    """Insert probe rows through the OWNER role (FORCE RLS applies to it too, so it sets a context)."""
    ids: list[uuid.UUID] = []
    with db.owner_conn() as conn:
        _with_society(conn, society)
        for name in names:
            row = conn.execute(
                "INSERT INTO probe_things (society_id, name) VALUES (%s, %s) RETURNING id",
                (society, name),
            ).fetchone()
            assert row is not None
            ids.append(row[0])
    return ids


def seed_audit(db: DbHandle, society: uuid.UUID | None, operation: str = "probe.seed") -> uuid.UUID:
    audit_id = uuid.uuid4()
    with db.app_conn(society_id=society) as conn:
        conn.execute(
            "INSERT INTO audit_log (id, society_id, actor_id, effective_role, operation, object_type, object_id)"
            " VALUES (%s, %s, %s, 'committee', %s, 'probe_thing', %s)",
            (audit_id, society, COMMITTEE_A, operation, uuid.uuid4()),
        )
    return audit_id


def seed_outbox(db: DbHandle, society: uuid.UUID, event_type: str = "ThingCreated") -> uuid.UUID:
    event_id = uuid.uuid4()
    with db.app_conn(society_id=society) as conn:
        conn.execute(
            "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id,"
            " aggregate_version, event_type, occurred_at, actor_ref, correlation_id, payload, payload_hash)"
            " VALUES (%s, 1, %s, 'probe_thing', %s, 1, %s, now(), 'system', %s, '{\"k\": 1}'::jsonb, %s)",
            (event_id, society, uuid.uuid4(), event_type, uuid.uuid4(), "sha256:" + "0" * 64),
        )
    return event_id


def run_sql(
    opener: Any, statement: str, *, society: uuid.UUID | None = SOCIETY_A, setup: str | None = None
) -> None:
    """Run ``statement`` in its own transaction with the given connection factory (one statement for raises())."""
    with opener(society_id=society) as conn:
        if setup is not None:
            conn.execute(setup)
        conn.execute(statement)


def run_as_owner(db: DbHandle, statement: str, society: uuid.UUID = SOCIETY_A) -> None:
    with db.owner_conn() as conn:
        _with_society(conn, society)
        conn.execute(statement)  # type: ignore[call-overload]


@pytest.fixture
def two_societies(db: DbHandle) -> DbHandle:
    create_probe_table(db)
    seed_things(db, SOCIETY_A, "a-1", "a-2")
    seed_things(db, SOCIETY_B, "b-1", "b-2", "b-3")
    return db


# ============================================================================== missing context
def test_missing_context_returns_zero_rows_everywhere(two_societies: DbHandle) -> None:
    db = two_societies
    seed_audit(db, SOCIETY_A)
    seed_outbox(db, SOCIETY_A)
    with db.app_conn() as conn:  # no set_config at all
        for table in ("probe_things", "audit_log", "outbox", "idempotency_keys", "purge_log"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # noqa: S608


def test_empty_string_context_left_on_a_pooled_connection_returns_zero_rows(
    two_societies: DbHandle,
) -> None:
    """After COMMIT a custom GUC reads as '' on that connection: it must mean 'nobody', not 'everybody'."""
    with psycopg.connect(two_societies.app_dsn) as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        assert conn.execute("SELECT count(*) FROM probe_things").fetchone() == (2,)
        conn.commit()
        assert conn.execute("SELECT current_setting('app.society_id', true)").fetchone() == ("",)
        assert conn.execute("SELECT count(*) FROM probe_things").fetchone() == (0,)


def test_write_without_context_fails(two_societies: DbHandle) -> None:
    with pytest.raises(errors.InsufficientPrivilege), two_societies.app_conn() as conn:
        conn.execute("INSERT INTO probe_things (society_id, name) VALUES (%s, 'x')", (SOCIETY_A,))


def test_update_and_delete_without_context_touch_nothing(two_societies: DbHandle) -> None:
    with two_societies.app_conn() as conn:
        assert conn.execute("UPDATE probe_things SET name = 'hijack'").rowcount == 0
        assert conn.execute("DELETE FROM probe_things").rowcount == 0
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        assert conn.execute(
            "SELECT count(*) FROM probe_things WHERE name = 'hijack'"
        ).fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM probe_things").fetchone() == (2,)


def test_garbage_context_fails_closed(two_societies: DbHandle) -> None:
    with (
        pytest.raises(errors.InvalidTextRepresentation),
        two_societies.app_conn(society_id="not-a-uuid") as conn,
    ):
        conn.execute("SELECT count(*) FROM probe_things")


# ============================================================================== society A vs B
def test_society_a_cannot_read_b(two_societies: DbHandle) -> None:
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        names = sorted(r[0] for r in conn.execute("SELECT name FROM probe_things"))
        assert names == ["a-1", "a-2"]
        assert conn.execute(
            "SELECT count(*) FROM probe_things WHERE society_id = %s", (SOCIETY_B,)
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM probe_things WHERE name LIKE 'b-%%'"
        ).fetchone() == (0,)


def test_society_a_cannot_write_into_b(two_societies: DbHandle) -> None:
    with (
        pytest.raises(errors.InsufficientPrivilege),
        two_societies.app_conn(society_id=SOCIETY_A) as conn,
    ):
        conn.execute(
            "INSERT INTO probe_things (society_id, name) VALUES (%s, 'smuggled')", (SOCIETY_B,)
        )


def test_society_a_cannot_update_delete_or_move_rows_of_b(two_societies: DbHandle) -> None:
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        assert (
            conn.execute(
                "UPDATE probe_things SET name = 'owned' WHERE society_id = %s", (SOCIETY_B,)
            ).rowcount
            == 0
        )
        assert (
            conn.execute("DELETE FROM probe_things WHERE society_id = %s", (SOCIETY_B,)).rowcount
            == 0
        )
        assert conn.execute("UPDATE probe_things SET name = 'x' WHERE name = 'b-1'").rowcount == 0
    with (
        pytest.raises(errors.InsufficientPrivilege),
        two_societies.app_conn(society_id=SOCIETY_A) as conn,
    ):
        conn.execute(
            "UPDATE probe_things SET society_id = %s WHERE name = 'a-1'", (SOCIETY_B,)
        )  # donate a row
    with two_societies.app_conn(society_id=SOCIETY_B) as conn:
        assert sorted(r[0] for r in conn.execute("SELECT name FROM probe_things")) == [
            "b-1",
            "b-2",
            "b-3",
        ]


def test_joins_and_subqueries_cannot_reach_other_society(two_societies: DbHandle) -> None:
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        joined = conn.execute(
            "SELECT count(*) FROM probe_things a JOIN probe_things b ON b.society_id <> a.society_id"
        ).fetchone()
        assert joined == (0,)
        cross = conn.execute(
            "SELECT count(*) FROM probe_things WHERE society_id IN (SELECT society_id FROM probe_things)"
        ).fetchone()
        assert cross == (2,)
        assert conn.execute("SELECT count(DISTINCT society_id) FROM probe_things").fetchone() == (
            1,
        )
        # aggregates, CTEs and set operations are all filtered at the table scan
        assert conn.execute(
            "WITH x AS (SELECT * FROM probe_things) SELECT count(*) FROM x UNION ALL SELECT count(*) FROM probe_things"
        ).fetchall() == [(2,), (2,)]


INSERT_DUPLICATE_NAME = "INSERT INTO probe_things (society_id, name) VALUES ('0192f300-0000-7000-8000-00000000000a', 'b-1')"


def test_unique_constraints_must_include_society_id(two_societies: DbHandle) -> None:
    """A GLOBAL unique index is an existence oracle across societies (the error reveals the foreign row);
    a society-scoped one is not. Module authors must use (society_id, ...) keys (ADR-0004)."""
    with two_societies.owner_conn() as conn:
        conn.execute("CREATE UNIQUE INDEX probe_name_global ON probe_things (name)")
    with pytest.raises(errors.UniqueViolation):
        run_sql(
            two_societies.app_conn,
            INSERT_DUPLICATE_NAME,
        )
    with two_societies.owner_conn() as conn:
        conn.execute("DROP INDEX probe_name_global")
        conn.execute("CREATE UNIQUE INDEX probe_name_scoped ON probe_things (society_id, name)")
    run_sql(
        two_societies.app_conn,
        INSERT_DUPLICATE_NAME,
    )  # same name in another society is simply allowed: nothing to probe


# ============================================================================== role hardening
def test_runtime_roles_are_not_privileged(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        rows = conn.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolinherit"
            " FROM pg_roles WHERE rolname IN ('dwaar_app', 'dwaar_worker')"
        ).fetchall()
        assert {r[0] for r in rows} == {"dwaar_app", "dwaar_worker"}
        for name, superuser, bypass, createrole, createdb, replication, _inherit in rows:
            assert not superuser, name
            assert not bypass, name
            assert not createrole, name
            assert not createdb, name
            assert not replication, name
        member_of_owner = conn.execute(
            "SELECT pg_has_role('dwaar_app', 'dwaar_owner', 'MEMBER'), pg_has_role('dwaar_worker', 'dwaar_owner', 'MEMBER')"
        ).fetchone()
        assert member_of_owner == (False, False)
        owner_tables = conn.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner <> 'dwaar_owner'"
        ).fetchone()
        assert owner_tables == (0,)  # nothing is owned by a runtime role


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE probe_things DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE probe_things NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY dwaar_society_isolation ON probe_things",
        "ALTER POLICY dwaar_society_isolation ON probe_things USING (true)",
        "CREATE POLICY open_door ON probe_things USING (true)",
        "ALTER TABLE probe_things ADD COLUMN sneaky int",
        "DROP TABLE probe_things",
        "TRUNCATE probe_things",
        "ALTER TABLE audit_log DISABLE TRIGGER dwaar_append_only_row",
        "DROP TRIGGER dwaar_append_only_row ON audit_log",
        "ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY",
        "DROP TABLE audit_log",
        "ALTER TABLE outbox DISABLE ROW LEVEL SECURITY",
        "CREATE TABLE public.rogue (id int)",
        "SET ROLE dwaar_owner",
        "SET SESSION AUTHORIZATION dwaar_owner",
        "ALTER ROLE dwaar_app BYPASSRLS",
        "ALTER ROLE dwaar_app SUPERUSER",
        "SET session_replication_role = replica",
        "CREATE EXTENSION IF NOT EXISTS dblink",
        "SELECT dwaar_enable_society_rls('probe_things')",
        "SELECT dwaar_make_append_only('probe_things')",
        "SELECT dwaar_purge_append_only('audit_log', ARRAY[gen_random_uuid()], 'abusing the purge path')",
        "ALTER FUNCTION dwaar_reject_mutation() RENAME TO harmless",
        "CREATE OR REPLACE FUNCTION dwaar_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    ],
)
@pytest.mark.parametrize("role", ["app", "worker"])
def test_runtime_roles_cannot_alter_or_escalate(
    two_societies: DbHandle, role: str, statement: str
) -> None:
    opener = two_societies.app_conn if role == "app" else two_societies.worker_conn
    with (
        pytest.raises((errors.InsufficientPrivilege, errors.FeatureNotSupported)),
        opener(society_id=SOCIETY_A) as conn,
    ):
        conn.execute(statement)  # type: ignore[call-overload]


def test_a_grant_attempt_by_the_app_role_changes_nothing(two_societies: DbHandle) -> None:
    """GRANT without grant option is only a WARNING in PostgreSQL: assert the privilege really did not appear."""
    run_sql(two_societies.app_conn, "GRANT UPDATE, DELETE ON audit_log TO dwaar_app")
    run_sql(two_societies.worker_conn, "GRANT UPDATE ON outbox TO dwaar_worker, dwaar_app")
    with two_societies.admin_conn() as conn:
        row = conn.execute(
            "SELECT has_table_privilege('dwaar_app', 'audit_log', 'UPDATE'),"
            " has_table_privilege('dwaar_app', 'audit_log', 'DELETE'),"
            " has_table_privilege('dwaar_app', 'outbox', 'UPDATE'),"
            " has_table_privilege('dwaar_worker', 'audit_log', 'UPDATE')"
        ).fetchone()
    assert row == (False, False, False, False)


def test_row_security_off_cannot_be_used_to_read_everything(two_societies: DbHandle) -> None:
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute("SET LOCAL row_security = off")
        with pytest.raises(
            errors.InsufficientPrivilege
        ):  # PostgreSQL refuses rather than silently bypassing
            conn.execute("SELECT count(*) FROM probe_things")


# ============================================================================== append-only history
def test_app_and_worker_cannot_update_or_delete_audit_log(two_societies: DbHandle) -> None:
    seed_audit(two_societies, SOCIETY_A)
    for opener in (two_societies.app_conn, two_societies.worker_conn):
        for statement in (
            "UPDATE audit_log SET reason = 'edited'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                run_sql(opener, statement)


def _history_counts(db: DbHandle) -> tuple[int, int]:
    with db.admin_conn() as conn:  # superuser bypasses RLS: counts ALL rows
        a = conn.execute("SELECT count(*) FROM audit_log").fetchone()
        o = conn.execute("SELECT count(*) FROM outbox").fetchone()
    assert a is not None
    assert o is not None
    return int(a[0]), int(o[0])


HISTORY_STATEMENTS = (
    "UPDATE audit_log SET reason = 'edited'",
    "DELETE FROM audit_log",
    "TRUNCATE audit_log",
    "DELETE FROM outbox",
    "UPDATE outbox SET payload = '{}'::jsonb",
    "UPDATE outbox SET society_id = gen_random_uuid()",
    "TRUNCATE outbox",
    "DELETE FROM purge_log",
)


def test_owner_cannot_rewrite_history_either(two_societies: DbHandle) -> None:
    """DB-02 holds for the table OWNER too: RLS hides rows from DELETE, triggers reject the rest."""
    seed_audit(two_societies, SOCIETY_A)
    seed_outbox(two_societies, SOCIETY_A)
    with (
        two_societies.owner_conn() as conn
    ):  # make sure purge_log has a row, so DELETE has something to reject
        conn.execute(
            "SELECT dwaar_purge_append_only('audit_log', ARRAY[%s], 'seed a purge_log row', %s)",
            (seed_audit(two_societies, SOCIETY_A, "probe.tmp"), SOCIETY_A),
        )
    before = _history_counts(two_societies)
    for statement in HISTORY_STATEMENTS:
        sqlstate: str | None = None
        changed = 0
        try:
            with two_societies.owner_conn() as conn:
                _with_society(conn, SOCIETY_A)
                changed = conn.execute(statement).rowcount  # type: ignore[call-overload]
        except psycopg.Error as exc:
            sqlstate = exc.sqlstate
        # either the trigger/privilege rejected it, or RLS left nothing for it to change
        assert sqlstate in {None, "DW001", "42501"}, (statement, sqlstate)
        assert sqlstate is not None or changed in (0, -1), (statement, changed)
    assert _history_counts(two_societies) == before


def test_even_a_superuser_cannot_rewrite_history_without_the_purge_path(
    two_societies: DbHandle,
) -> None:
    """The triggers reject the superuser too (RLS does not apply to it): the guard is not just a privilege."""
    seed_audit(two_societies, SOCIETY_A)
    seed_outbox(two_societies, SOCIETY_A)
    before = _history_counts(two_societies)
    for statement in HISTORY_STATEMENTS:
        if statement.startswith("DELETE FROM purge_log"):
            continue  # purge_log is empty here
        with pytest.raises(psycopg.Error) as exc, two_societies.admin_conn() as conn:
            conn.execute(statement)  # type: ignore[call-overload]
        assert exc.value.sqlstate == "DW001", statement
    assert _history_counts(two_societies) == before


def test_audit_insert_rules(two_societies: DbHandle) -> None:
    seed_audit(two_societies, SOCIETY_A, "probe.a")
    seed_audit(
        two_societies, None, "auth.sign_in_failed"
    )  # platform-level event: allowed, society NULL
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        ops = [r[0] for r in conn.execute("SELECT operation FROM audit_log")]
        assert ops == ["probe.a"]  # platform rows are invisible to every society context
    with pytest.raises(errors.InsufficientPrivilege):
        seed_audit_as(
            two_societies, context=SOCIETY_A, row_society=SOCIETY_B
        )  # cannot write another society's trail
    with two_societies.app_conn(society_id=SOCIETY_B) as conn:
        assert conn.execute("SELECT count(*) FROM audit_log").fetchone() == (0,)


def seed_audit_as(db: DbHandle, *, context: uuid.UUID, row_society: uuid.UUID) -> None:
    with db.app_conn(society_id=context) as conn:
        conn.execute(
            "INSERT INTO audit_log (society_id, effective_role, operation, object_type)"
            " VALUES (%s, 'committee', 'probe.forged', 'probe_thing')",
            (row_society,),
        )


def test_purge_path_is_owner_only_logged_and_restores_context(two_societies: DbHandle) -> None:
    audit_id = seed_audit(two_societies, SOCIETY_A)
    keep_id = seed_audit(two_societies, SOCIETY_A, "probe.keep")
    platform_id = seed_audit(two_societies, None, "auth.platform_row")
    with two_societies.owner_conn() as conn:
        _with_society(conn, SOCIETY_B)  # a DIFFERENT ambient context: must be restored afterwards
        purged = conn.execute(
            "SELECT dwaar_purge_append_only('audit_log', ARRAY[%s, %s], 'privacy erasure test', %s)",
            (audit_id, platform_id, SOCIETY_A),
        ).fetchone()
        assert purged == (2,)
        assert conn.execute("SELECT current_setting('app.society_id', true)").fetchone() == (
            str(SOCIETY_B),
        )
        assert conn.execute("SELECT current_setting('dwaar.purge_table', true)").fetchone() == ("",)
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        remaining = [r[0] for r in conn.execute("SELECT id FROM audit_log")]
        assert remaining == [keep_id]
        log = conn.execute("SELECT table_name, row_count, reason FROM purge_log").fetchall()
        assert log == [("audit_log", 2, "privacy erasure test")]
    with two_societies.app_conn(society_id=SOCIETY_B) as conn:
        assert conn.execute("SELECT count(*) FROM purge_log").fetchone() == (
            0,
        )  # logs are society-scoped too


def test_purge_function_refuses_bad_use(two_societies: DbHandle) -> None:
    for statement in (
        "SELECT dwaar_purge_append_only('probe_things', ARRAY[gen_random_uuid()], 'not a history table')",
        "SELECT dwaar_purge_append_only('purge_log', ARRAY[gen_random_uuid()], 'purging the purge log')",
        "SELECT dwaar_purge_append_only('audit_log', ARRAY[gen_random_uuid()], 'x')",
    ):
        with pytest.raises(psycopg.Error), two_societies.owner_conn() as conn:
            conn.execute(statement)  # type: ignore[call-overload]


def test_forging_the_purge_flag_does_not_help_the_app_role(two_societies: DbHandle) -> None:
    audit_id = seed_audit(two_societies, SOCIETY_A)
    oid_row = None
    with two_societies.admin_conn() as conn:
        oid_row = conn.execute("SELECT 'audit_log'::regclass::oid::text").fetchone()
    assert oid_row is not None
    for opener in (two_societies.app_conn, two_societies.worker_conn):
        with pytest.raises(errors.InsufficientPrivilege):
            run_sql(
                opener,
                f"DELETE FROM audit_log WHERE id = '{audit_id}'",  # noqa: S608
                setup=f"SELECT set_config('dwaar.purge_table', '{oid_row[0]}', true)",
            )


# ============================================================================== outbox relay (worker)
def test_worker_relay_claims_across_societies_and_updates_delivery_fields_only(
    two_societies: DbHandle,
) -> None:
    a = seed_outbox(two_societies, SOCIETY_A)
    b = seed_outbox(two_societies, SOCIETY_B)
    with two_societies.app_conn() as conn:
        assert conn.execute("SELECT count(*) FROM outbox").fetchone() == (
            0,
        )  # the API role never sees the relay view
    with two_societies.worker_conn() as conn:  # NO society context: platform relay job
        claimed = conn.execute(
            "SELECT event_id FROM outbox WHERE published_at IS NULL AND next_attempt_at <= now()"
            " ORDER BY next_attempt_at, event_id FOR UPDATE SKIP LOCKED LIMIT 10"
        ).fetchall()
        assert {r[0] for r in claimed} == {a, b}
        assert (
            conn.execute(
                "UPDATE outbox SET published_at = now(), attempts = attempts + 1, last_error = NULL WHERE event_id = %s",
                (a,),
            ).rowcount
            == 1
        )
    for statement in (
        "UPDATE outbox SET payload = '{\"tampered\": true}'::jsonb",
        "UPDATE outbox SET society_id = gen_random_uuid()",
        "UPDATE outbox SET event_type = 'Forged'",
        "DELETE FROM outbox",
        "INSERT INTO outbox (schema_version, society_id, aggregate_type, aggregate_id, aggregate_version, event_type,"
        " occurred_at, actor_ref, correlation_id, payload_hash) VALUES (1, gen_random_uuid(), 'x', gen_random_uuid(), 1,"
        " 'X', now(), 's', gen_random_uuid(), 'sha256:" + "0" * 64 + "')",
    ):
        with pytest.raises(errors.InsufficientPrivilege):
            run_sql(two_societies.worker_conn, statement, society=None)


def test_outbox_guard_blocks_unpublish_and_attempt_rollback_even_for_owner(
    two_societies: DbHandle,
) -> None:
    event = seed_outbox(two_societies, SOCIETY_A)
    with two_societies.owner_conn() as conn:
        _with_society(conn, SOCIETY_A)
        conn.execute(
            "UPDATE outbox SET published_at = now(), attempts = 3 WHERE event_id = %s", (event,)
        )
    for statement in (
        "UPDATE outbox SET published_at = NULL",
        "UPDATE outbox SET published_at = now() + interval '1 day'",
        "UPDATE outbox SET attempts = 1",
    ):
        with pytest.raises(psycopg.Error) as exc:
            run_as_owner(two_societies, statement)
        assert exc.value.sqlstate == "DW001", statement


def test_worker_can_only_clean_up_expired_idempotency_keys(two_societies: DbHandle) -> None:
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        for key, expiry in (
            ("fresh-key-0001", "now() + interval '1 hour'"),
            ("stale-key-0001", "now() - interval '1 hour'"),
        ):
            conn.execute(
                "INSERT INTO idempotency_keys (society_id, actor_id, key, endpoint, request_hash, expires_at)"  # noqa: S608
                f" VALUES (%s, %s, %s, 'POST /x', %s, {expiry})",
                (SOCIETY_A, COMMITTEE_A, key, "sha256:" + "a" * 64),
            )
    with two_societies.worker_conn() as conn:
        assert conn.execute("SELECT key FROM idempotency_keys").fetchall() == [("stale-key-0001",)]
        assert conn.execute("DELETE FROM idempotency_keys").rowcount == 1
    with two_societies.app_conn(society_id=SOCIETY_A) as conn:
        assert conn.execute("SELECT key FROM idempotency_keys").fetchall() == [("fresh-key-0001",)]
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("DELETE FROM idempotency_keys")  # the API role never deletes keys


# ============================================================================== the catalog guard
# DENY BY DEFAULT: every relation in `public` that a runtime role (dwaar_app / dwaar_worker, or PUBLIC)
# can touch must be FORCE-RLS protected and society scoped, or be named below after a security review.
RUNTIME_ROLES = ("dwaar_app", "dwaar_worker")
#: society_id is deliberately nullable here (platform-level rows); both tables have hand-written policies.
NULLABLE_SOCIETY_ALLOWED = frozenset({"audit_log", "purge_log"})
#: platform-level tables with no tenant data that runtime roles may use without RLS (review each addition).
PLATFORM_TABLE_ALLOWLIST = frozenset({"rate_limit_buckets", "schema_migrations"})
#: materialised views are never RLS-protected, so none may be readable by a runtime role (ban for tenant data).
MATVIEW_ALLOWLIST: frozenset[str] = frozenset()
#: reviewed policies that intentionally let a background role see more than one society (table, policy).
CROSS_SOCIETY_POLICY_ALLOWLIST = frozenset(
    {
        ("outbox", "outbox_relay_select"),  # the relay claims pending events of all societies
        ("outbox", "outbox_relay_update"),  # ... and updates delivery columns only (column grants)
        ("idempotency_keys", "idempotency_keys_expired_select"),  # expired-key cleanup job
        ("idempotency_keys", "idempotency_keys_expired_delete"),  # expired rows only
        ("purge_log", "purge_log_insert_owner"),  # owner-only logged purge path
    }
)
_PROBE_SOCIETY = "0192f300-0000-7000-8000-0000000000aa"
_OTHER_SOCIETY = "0192f300-0000-7000-8000-0000000000bb"
_PRIV_ANY = "SELECT, INSERT, UPDATE, REFERENCES"


def _policy_leaks(conn: psycopg.Connection[Any], expression: str) -> str | None:
    """Evaluate a policy expression for a row of society P while the session is society Q (and unset).

    Returns ``"leak"`` when it is TRUE for a foreign society or for no society, ``"unverifiable"``
    when it cannot be evaluated with society_id substituted (it depends on other columns/functions
    and must use the standard society expression), else None. Semantic, not a substring match.
    """
    probe = re.sub(r"(?<![\w.'])society_id(?![\w'])", f"'{_PROBE_SOCIETY}'::uuid", expression)
    for context in (_OTHER_SOCIETY, ""):
        try:
            with conn.transaction():
                conn.execute("SELECT set_config('app.society_id', %s, true)", (context,))
                row = conn.execute(f"SELECT ({probe}) IS TRUE").fetchone()  # type: ignore[call-overload]  # noqa: S608
        except psycopg.Error:
            return "unverifiable"
        if row is not None and row[0]:
            return "leak"
    return None


def find_rls_violations(conn: psycopg.Connection[Any]) -> list[str]:
    """Report every way a runtime role could read or write across societies. Empty list = guard is green."""
    problems: list[str] = []
    relations = conn.execute(
        """
        SELECT c.oid, c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity,
               a.attnotnull IS TRUE, a.attname IS NOT NULL,
               (SELECT r.rolsuper OR r.rolbypassrls FROM pg_roles r WHERE r.oid = c.relowner),
               EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = ANY (%s) AND (
                   has_any_column_privilege(r.oid, c.oid, %s)
                   OR has_table_privilege(r.oid, c.oid, 'DELETE, TRUNCATE, TRIGGER')))
               OR EXISTS (SELECT 1 FROM aclexplode(c.relacl) x WHERE x.grantee = 0)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'society_id' AND NOT a.attisdropped
        WHERE c.relkind IN ('r', 'p', 'm', 'v', 'f')
        ORDER BY c.relname
        """,
        (list(RUNTIME_ROLES), _PRIV_ANY),
    ).fetchall()
    for (
        oid,
        name,
        kind,
        enabled,
        forced,
        notnull,
        has_society,
        owner_bypasses,
        reachable,
    ) in relations:
        if kind == "m" and reachable and name not in MATVIEW_ALLOWLIST:
            problems.append(
                f"{name}: materialised view readable by a runtime role (RLS does not apply to matviews)"
            )
            continue
        if kind == "f" and reachable:
            problems.append(f"{name}: foreign table readable by a runtime role")
            continue
        if kind == "v":
            if reachable and owner_bypasses:
                problems.append(f"{name}: view owner bypasses RLS (superuser/BYPASSRLS)")
            continue
        if kind == "m":
            continue
        if not has_society:
            if reachable and name not in PLATFORM_TABLE_ALLOWLIST:
                problems.append(
                    f"{name}: table reachable by a runtime role has no society_id column and is not an "
                    "allowlisted platform table (tenant scoping must be society_id + RLS)"
                )
            continue
        if not enabled:
            problems.append(f"{name}: ROW LEVEL SECURITY is not enabled")
        if not forced:
            problems.append(f"{name}: ROW LEVEL SECURITY is not FORCED (the owner would bypass it)")
        if not notnull and name not in NULLABLE_SOCIETY_ALLOWED:
            problems.append(f"{name}: society_id is nullable")
        policies = conn.execute(
            "SELECT p.polname, p.polcmd, pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid),"
            " ARRAY(SELECT rolname FROM pg_roles r WHERE r.oid = ANY (p.polroles)), p.polroles = '{0}',"
            " p.polpermissive"
            " FROM pg_policy p WHERE p.polrelid = %s",
            (oid,),
        ).fetchall()
        if not policies:
            problems.append(f"{name}: no row level security policy")
        for polname, _cmd, qual, check, roles, to_public, permissive in policies:
            expression = f"{qual or ''} {check or ''}"
            scoped_away = bool(roles) and not (set(roles) & set(RUNTIME_ROLES)) and not to_public
            reviewed = (name, polname) in CROSS_SOCIETY_POLICY_ALLOWLIST
            if not scoped_away and not reviewed and "app.society_id" not in expression:
                problems.append(
                    f"{name}.{polname}: policy for the API role does not use app.society_id"
                )
            if to_public and (qual or "").strip() == "true":
                problems.append(f"{name}.{polname}: policy for PUBLIC is USING (true)")
            if permissive and not reviewed:
                for part in (qual, check):
                    if not part:
                        continue
                    verdict = _policy_leaks(conn, part)
                    if verdict == "leak":
                        problems.append(
                            f"{name}.{polname}: policy is TRUE for another society or for none "
                            "(always-true or not society-scoped); review it into "
                            "CROSS_SOCIETY_POLICY_ALLOWLIST only if the cross-society access is intended"
                        )
                    elif verdict == "unverifiable" and not scoped_away:
                        problems.append(
                            f"{name}.{polname}: policy cannot be probed with society_id substituted; "
                            "use the standard society expression"
                        )
        has_society_policy = any(
            "app.society_id" in f"{q or ''} {c or ''}" for _n, _m, q, c, _r, _p, _perm in policies
        )
        if policies and not has_society_policy:
            problems.append(f"{name}: no policy references app.society_id")
        grants = conn.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants"
            " WHERE table_schema = 'public' AND table_name = %s AND grantee = 'PUBLIC'",
            (name,),
        ).fetchall()
        if grants:
            problems.append(f"{name}: privileges granted to PUBLIC")
    return problems


@pytest.mark.req("ARCH-01", "ARCH-03", "DB-02")
def test_every_society_table_has_force_rls_and_a_society_policy(db: DbHandle) -> None:
    """GUARD for all future migrations: add a society-owned table without dwaar_enable_society_rls and this fails."""
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
        covered = {
            r[0]
            for r in conn.execute(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'"
                " JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'society_id' AND NOT a.attisdropped"
                " WHERE c.relkind IN ('r', 'p')"
            )
        }
    assert problems == [], "\n".join(problems)
    assert {
        "audit_log",
        "outbox",
        "idempotency_keys",
        "purge_log",
    } <= covered  # the checker really sees the core tables


def test_catalog_guard_detects_each_kind_of_violation(db: DbHandle) -> None:
    """The guard itself is tested: deliberately broken tables must be reported."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE bad_no_rls (id int, society_id uuid NOT NULL)")
        conn.execute("CREATE TABLE bad_no_force (id int, society_id uuid NOT NULL)")
        conn.execute("ALTER TABLE bad_no_force ENABLE ROW LEVEL SECURITY")
        conn.execute("CREATE TABLE bad_no_policy (id int, society_id uuid NOT NULL)")
        conn.execute("ALTER TABLE bad_no_policy ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE bad_no_policy FORCE ROW LEVEL SECURITY")
        conn.execute("CREATE TABLE bad_open_policy (id int, society_id uuid NOT NULL)")
        conn.execute("ALTER TABLE bad_open_policy ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE bad_open_policy FORCE ROW LEVEL SECURITY")
        conn.execute("CREATE POLICY wide_open ON bad_open_policy USING (true)")
        conn.execute("CREATE TABLE bad_nullable (id int, society_id uuid)")
        conn.execute("SELECT dwaar_enable_society_rls('bad_nullable')")  # helper fixes NOT NULL
        conn.execute("ALTER TABLE bad_nullable ALTER COLUMN society_id DROP NOT NULL")
        conn.execute("CREATE TABLE bad_grant (id int, society_id uuid NOT NULL)")
        conn.execute("SELECT dwaar_enable_society_rls('bad_grant')")
        conn.execute("GRANT SELECT ON bad_grant TO PUBLIC")
        conn.execute("CREATE TABLE fine_table (id int, society_id uuid NOT NULL)")
        conn.execute("SELECT dwaar_enable_society_rls('fine_table')")
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    text = "\n".join(problems)
    assert "bad_no_rls: ROW LEVEL SECURITY is not enabled" in text
    assert "bad_no_force: ROW LEVEL SECURITY is not FORCED" in text
    assert "bad_no_policy: no row level security policy" in text
    assert "bad_open_policy.wide_open: policy for the API role does not use app.society_id" in text
    assert "bad_open_policy.wide_open: policy for PUBLIC is USING (true)" in text
    assert "bad_nullable: society_id is nullable" in text
    assert "bad_grant: privileges granted to PUBLIC" in text
    assert "fine_table" not in text


def test_helper_functions_are_not_executable_by_public(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        for signature in (
            "dwaar_enable_society_rls(regclass, text, text)",
            "dwaar_make_append_only(regclass)",
            "dwaar_purge_append_only(regclass, uuid[], text, uuid, name)",
        ):
            row = conn.execute(
                "SELECT has_function_privilege('dwaar_app', %s::regprocedure, 'EXECUTE'),"
                " has_function_privilege('dwaar_worker', %s::regprocedure, 'EXECUTE'),"
                " has_function_privilege('dwaar_owner', %s::regprocedure, 'EXECUTE')",
                (signature, signature, signature),
            ).fetchone()
            assert row == (False, False, True), signature
