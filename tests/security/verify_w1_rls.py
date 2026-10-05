"""OPEN findings from W1 verification: RLS, roles, catalog guard (INV-01, ARCH-01/03).

Not collected by ``make test``; run explicitly with
``uv run --no-sync pytest tests/security/verify_w1_rls.py -p no:cacheprovider``.

A FAILING test asserts the secure behaviour and marks a defect that is NOT fixed yet (not part of fix round 1).
When one is fixed, move it to ``tests/security/test_w1_rls.py``. Tests for fixed findings live in
``tests/security/test_w1_*.py``.
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
