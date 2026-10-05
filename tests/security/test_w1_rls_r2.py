"""W1 fix round 2: regression tests for RLS, roles and the catalog guard (INV-01, ARCH-01/03).

These started life as failing repros in ``verify_w1_rls.py`` (open findings of verification round 1) and were moved
here when their root causes were fixed; each asserts the SECURE behaviour. Tests that already passed in the
repro file (attacks that were tried and did not work) are kept as regression evidence.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from psycopg import errors

from dwaar_api.core.db import Database
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import SOCIETY_A, SOCIETY_B, create_probe_table

pytestmark = pytest.mark.req("INV-01", "ARCH-01", "ARCH-03", "DB-02")


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


# ------------------------------------------------------------------------------------------------
# (1a) unset / blank / garbage app.society_id
# ------------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------------
# (1b) session-level state leaking across pooled connections
# ------------------------------------------------------------------------------------------------
@pytest.fixture
def one_connection_database(two: DbHandle) -> Iterator[Database]:
    database = Database(two.app_dsn, pool_size=1, max_overflow=0)
    try:
        yield database
    finally:
        database.dispose()


# ------------------------------------------------------------------------------------------------
# (1c) SECURITY DEFINER functions / views / materialised views
# ------------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------------
# (1d) dwaar_app privilege probes
# ------------------------------------------------------------------------------------------------


def test_app_role_cannot_lock_tables_it_can_update(two: DbHandle) -> None:
    """LOCK TABLE ... ACCESS EXCLUSIVE needs only UPDATE/DELETE/TRUNCATE. idempotency_keys and
    rate_limit_buckets grant UPDATE to the API role, so one statement from a compromised handler (or a
    stuck transaction) blocks every idempotent write of every society."""
    for table in ("idempotency_keys", "rate_limit_buckets"):
        try:
            with two.app_conn(society_id=SOCIETY_A) as conn:
                conn.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE NOWAIT")  # type: ignore[call-overload]
        except errors.InsufficientPrivilege:
            continue
        pytest.fail(f"dwaar_app can take ACCESS EXCLUSIVE on {table} (global DoS)")


# ------------------------------------------------------------------------------------------------
# (1e) worker over-grant
# ------------------------------------------------------------------------------------------------
def _live_key(db: DbHandle, society: uuid.UUID, key: str = "live-key-0001") -> None:
    with db.app_conn(society_id=society) as conn:
        conn.execute(
            "INSERT INTO idempotency_keys (society_id, actor_id, key, endpoint, request_hash, state,"
            " response_status, response_body, completed_at, expires_at)"
            " VALUES (%s, %s, %s, 'POST /x', %s, 'completed', 201, '{}'::jsonb, now(), now() + interval '1 day')",
            (society, uuid.uuid4(), key, "sha256:" + "a" * 64),
        )


def test_worker_rate_limit_table_access_is_not_cross_tenant_writable(two: DbHandle) -> None:
    """rate_limit_buckets is platform-level: any app/worker SQL can reset or delete ANY bucket (e.g. wipe
    another phone's OTP throttle). Documented as accepted? The grant is full CRUD."""
    with two.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute("SELECT * FROM dwaar_rate_limit_take('otp:phone:victim', 3, 0.001, 1)")
    with two.worker_conn() as conn:
        deleted = conn.execute(
            "DELETE FROM rate_limit_buckets WHERE key = 'otp:phone:victim'"
        ).rowcount
    assert deleted == 0, "worker can delete another actor's throttle bucket"


# ------------------------------------------------------------------------------------------------
# more (1): header-borne selectors over real HTTP, role-scoped policy exemption, worker INSERT rights
# ------------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------------
# fix round 2: rate_limit_buckets is reached only through the SECURITY DEFINER function (migration 0009)
# ------------------------------------------------------------------------------------------------
def test_runtime_roles_hold_no_table_privileges_on_rate_limit_buckets(two: DbHandle) -> None:
    with two.admin_conn() as conn:
        app_any = conn.execute(
            "SELECT has_table_privilege('dwaar_app', 'rate_limit_buckets', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE'),"
            " has_any_column_privilege('dwaar_app', 'rate_limit_buckets', 'SELECT, INSERT, UPDATE')"
        ).fetchone()
        worker = conn.execute(
            "SELECT has_table_privilege('dwaar_worker', 'rate_limit_buckets', 'SELECT, INSERT, UPDATE, TRUNCATE'),"
            " has_column_privilege('dwaar_worker', 'rate_limit_buckets', 'tokens', 'SELECT'),"
            " has_column_privilege('dwaar_worker', 'rate_limit_buckets', 'key', 'SELECT'),"
            " has_table_privilege('dwaar_worker', 'rate_limit_buckets', 'DELETE')"
        ).fetchone()
    assert app_any == (False, False)
    assert worker == (False, False, True, True)  # housekeeping only: read key/updated_at, delete


def test_the_api_role_still_gets_rate_decisions_through_the_function(two: DbHandle) -> None:
    with two.app_conn() as conn:
        first = conn.execute(
            "SELECT allowed FROM dwaar_rate_limit_take('k-fn', 1, 0.001, 1)"
        ).fetchone()
    with two.app_conn() as conn:
        second = conn.execute(
            "SELECT allowed FROM dwaar_rate_limit_take('k-fn', 1, 0.001, 1)"
        ).fetchone()
    assert (first, second) == ((True,), (False,))
    for statement in (
        "SELECT * FROM rate_limit_buckets",
        "UPDATE rate_limit_buckets SET tokens = 1000000",
        "DELETE FROM rate_limit_buckets",
        "INSERT INTO rate_limit_buckets (key, tokens, updated_at) VALUES ('x', 1, now())",
    ):
        with pytest.raises(errors.InsufficientPrivilege):
            with two.app_conn() as conn:
                conn.execute(statement)  # type: ignore[call-overload]


def test_worker_housekeeping_removes_only_stale_buckets(two: DbHandle) -> None:
    with two.owner_conn() as conn:
        conn.execute(
            "INSERT INTO rate_limit_buckets (key, tokens, updated_at) VALUES"
            " ('stale-bucket', 1, now() - interval '3 days'), ('fresh-bucket', 1, now())"
        )
    with two.worker_conn() as conn:
        assert conn.execute("SELECT key FROM rate_limit_buckets").fetchall() == [("stale-bucket",)]
        assert conn.execute("DELETE FROM rate_limit_buckets").rowcount == 1
    with two.owner_conn() as conn:
        assert conn.execute("SELECT key FROM rate_limit_buckets").fetchall() == [("fresh-bucket",)]


def test_idempotency_keys_grants_are_column_level_so_no_lock_table_is_possible(
    two: DbHandle,
) -> None:
    with two.admin_conn() as conn:
        row = conn.execute(
            "SELECT has_table_privilege('dwaar_app', 'idempotency_keys', 'UPDATE, DELETE, TRUNCATE'),"
            " has_column_privilege('dwaar_app', 'idempotency_keys', 'response_body', 'UPDATE'),"
            " has_column_privilege('dwaar_app', 'idempotency_keys', 'society_id', 'UPDATE'),"
            " has_column_privilege('dwaar_app', 'idempotency_keys', 'actor_id', 'UPDATE'),"
            " has_column_privilege('dwaar_worker', 'idempotency_keys', 'response_body', 'SELECT')"
        ).fetchone()
    # the API role may rewrite a response and nothing that scopes the key (society, actor, key); the worker cannot read bodies
    assert row == (False, True, False, False, False)
