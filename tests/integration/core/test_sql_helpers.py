"""The SQL helpers every later migration relies on: uuid_generate_v7, RLS + append-only helpers, token bucket."""

from __future__ import annotations

import time

import psycopg
import pytest

from dwaar_common.ids import is_uuid7, uuid7_timestamp_ms
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import SOCIETY_A, SOCIETY_B

pytestmark = pytest.mark.req("ARCH-01", "DB-02")


def test_uuid_generate_v7_is_a_valid_time_ordered_uuid7(db: DbHandle) -> None:
    with db.owner_conn() as conn:
        before = int(time.time() * 1000)
        rows = [
            r[0] for r in conn.execute("SELECT uuid_generate_v7() FROM generate_series(1, 200)")
        ]
        after = int(time.time() * 1000)
        in_one_statement = conn.execute(
            "SELECT count(DISTINCT uuid_generate_v7()) FROM generate_series(1, 500)"
        ).fetchone()
    assert len(set(rows)) == 200
    assert in_one_statement == (500,)
    for value in rows:
        assert is_uuid7(value), value
        assert before - 5 <= uuid7_timestamp_ms(value) <= after + 5
    # milliseconds are non-decreasing across calls (clock_timestamp based)
    stamps = [uuid7_timestamp_ms(v) for v in rows]
    assert stamps == sorted(stamps)


def test_uuid_default_works_for_the_app_role(db: DbHandle) -> None:
    with db.app_conn(society_id=SOCIETY_A) as conn:
        value = conn.execute("SELECT uuid_generate_v7()").fetchone()
    assert value is not None
    assert is_uuid7(value[0])


def _owner_exec(db: DbHandle, *statements: str) -> None:
    with db.owner_conn() as conn:
        for statement in statements:
            conn.execute(statement)  # type: ignore[call-overload]


def test_enable_rls_rejects_tables_without_a_uuid_society_column(db: DbHandle) -> None:
    _owner_exec(
        db, "CREATE TABLE no_society (id int)", "CREATE TABLE text_society (society_id text)"
    )
    for table, message in (
        ("no_society", "no society_id column"),
        ("text_society", "must be uuid"),
    ):
        with pytest.raises(psycopg.errors.RaiseException, match=message), db.owner_conn() as conn:
            conn.execute(f"SELECT dwaar_enable_society_rls('{table}')")  # type: ignore[call-overload]


def test_enable_rls_makes_society_id_not_null_and_is_idempotent(db: DbHandle) -> None:
    _owner_exec(db, "CREATE TABLE nullable_soc (id int, society_id uuid)")
    _owner_exec(
        db,
        "SELECT dwaar_enable_society_rls('nullable_soc')",
        "SELECT dwaar_enable_society_rls('nullable_soc')",
    )
    with db.admin_conn() as conn:
        row = conn.execute(
            "SELECT a.attnotnull, c.relrowsecurity, c.relforcerowsecurity,"
            " (SELECT count(*) FROM pg_policy WHERE polrelid = c.oid)"
            " FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'society_id'"
            " WHERE c.relname = 'nullable_soc'"
        ).fetchone()
    assert row == (True, True, True, 1)  # re-running does not stack policies


def test_enable_rls_privilege_arguments(db: DbHandle) -> None:
    _owner_exec(
        db,
        "CREATE TABLE narrow (id int, society_id uuid)",
        "SELECT dwaar_enable_society_rls('narrow', 'SELECT, INSERT', 'SELECT')",
    )
    with db.admin_conn() as conn:

        def can(role: str, privilege: str) -> bool:
            row = conn.execute(
                "SELECT has_table_privilege(%s, 'narrow', %s)", (role, privilege)
            ).fetchone()
            assert row is not None
            return bool(row[0])

        assert [can("dwaar_app", p) for p in ("SELECT", "INSERT", "UPDATE", "DELETE")] == [
            True,
            True,
            False,
            False,
        ]
        assert [can("dwaar_worker", p) for p in ("SELECT", "INSERT", "UPDATE", "DELETE")] == [
            True,
            False,
            False,
            False,
        ]
    with pytest.raises(psycopg.errors.RaiseException, match="not allowed"), db.owner_conn() as conn:
        conn.execute("SELECT dwaar_enable_society_rls('narrow', 'SELECT, TRUNCATE')")


def test_standard_policy_gives_zero_rows_without_context_and_isolates(db: DbHandle) -> None:
    _owner_exec(
        db,
        "CREATE TABLE notes (id serial, society_id uuid, body text)",
        "SELECT dwaar_enable_society_rls('notes')",
    )
    for society in (SOCIETY_A, SOCIETY_B):
        with db.app_conn(society_id=society) as conn:
            conn.execute(
                "INSERT INTO notes (society_id, body) VALUES (%s, %s)",
                (society, f"note of {society}"),
            )
    with db.app_conn() as conn:
        assert conn.execute("SELECT count(*) FROM notes").fetchone() == (0,)
    with db.app_conn(society_id=SOCIETY_A) as conn:
        assert [r[0] for r in conn.execute("SELECT body FROM notes")] == [f"note of {SOCIETY_A}"]


INSERT_LEDGER = {
    "ledger_a": "INSERT INTO ledger_a (society_id, amount) VALUES (%s, 100)",
    "ledger_b": "INSERT INTO ledger_b (society_id, amount) VALUES (%s, 100)",
}


def test_append_only_helper_is_order_independent(db: DbHandle) -> None:
    _owner_exec(
        db,
        "CREATE TABLE ledger_a (id uuid PRIMARY KEY DEFAULT uuid_generate_v7(), society_id uuid, amount bigint)",
        "SELECT dwaar_enable_society_rls('ledger_a')",
        "SELECT dwaar_make_append_only('ledger_a')",
        "CREATE TABLE ledger_b (id uuid PRIMARY KEY DEFAULT uuid_generate_v7(), society_id uuid, amount bigint)",
        "SELECT dwaar_make_append_only('ledger_b')",
        "SELECT dwaar_enable_society_rls('ledger_b')",
    )
    for table in ("ledger_a", "ledger_b"):
        with db.app_conn(society_id=SOCIETY_A) as conn:
            conn.execute(INSERT_LEDGER[table], (SOCIETY_A,))
        with db.admin_conn() as conn:
            privileges = [
                conn.execute("SELECT has_table_privilege(%s, %s, %s)", (role, table, p)).fetchone()
                for role in ("dwaar_app", "dwaar_worker")
                for p in ("UPDATE", "DELETE", "TRUNCATE")
            ]
        assert privileges == [(False,)] * 6, table


def test_purge_path_works_for_a_helper_made_append_only_table(db: DbHandle) -> None:
    _owner_exec(
        db,
        "CREATE TABLE ledger (id uuid PRIMARY KEY DEFAULT uuid_generate_v7(), society_id uuid, amount bigint)",
        "SELECT dwaar_enable_society_rls('ledger')",
        "SELECT dwaar_make_append_only('ledger')",
    )
    with db.app_conn(society_id=SOCIETY_A) as conn:
        ids = [
            conn.execute(
                "INSERT INTO ledger (society_id, amount) VALUES (%s, %s) RETURNING id",
                (SOCIETY_A, n),
            ).fetchone()
            for n in (1, 2, 3)
        ]
    victim = [ids[0][0]]  # type: ignore[index]
    with db.owner_conn() as conn:
        assert conn.execute(
            "SELECT dwaar_purge_append_only('ledger', %s, 'erasure of a test row', %s)",
            (victim, SOCIETY_A),
        ).fetchone() == (1,)
    with db.app_conn(society_id=SOCIETY_A) as conn:
        assert conn.execute("SELECT count(*) FROM ledger").fetchone() == (2,)
    with pytest.raises(psycopg.Error) as exc, db.owner_conn() as conn:
        conn.execute("TRUNCATE ledger")
    assert exc.value.sqlstate == "DW001"


# ----------------------------------------------------------------------------------- token bucket
def _take(
    db: DbHandle, key: str, capacity: int = 3, refill: float = 1.0, cost: int = 1
) -> tuple[bool, float, int]:
    with db.app_conn() as conn:
        row = conn.execute(
            "SELECT allowed, remaining, retry_after_ms FROM dwaar_rate_limit_take(%s, %s, %s, %s)",
            (key, capacity, refill, cost),
        ).fetchone()
    assert row is not None
    return bool(row[0]), float(row[1]), int(row[2])


@pytest.mark.req("IAM-06")
def test_token_bucket_allows_capacity_then_denies_without_burning(db: DbHandle) -> None:
    results = [_take(db, "otp:phone:abc", capacity=3, refill=0.5) for _ in range(5)]
    assert [r[0] for r in results] == [True, True, True, False, False]
    assert results[2][1] == pytest.approx(0.0, abs=0.05)
    denied = results[3]
    assert 1 <= denied[2] <= 2100  # about 2 s until one token at 0.5 tokens/s
    # a denied attempt did not take anything: the retry hint does not grow with hammering
    assert results[4][2] <= denied[2]


def test_token_bucket_refills_over_time_and_keys_are_independent(db: DbHandle) -> None:
    assert [_take(db, "k1", capacity=1, refill=20.0)[0] for _ in range(2)] == [True, False]
    time.sleep(0.12)
    assert _take(db, "k1", capacity=1, refill=20.0)[0] is True
    assert _take(db, "k2", capacity=1, refill=20.0)[0] is True  # another key starts full


def test_token_bucket_rejects_nonsense_parameters(db: DbHandle) -> None:
    for capacity, refill, cost in ((0, 1.0, 1), (3, 0.0, 1), (3, 1.0, 0), (3, 1.0, 4)):
        with pytest.raises(psycopg.errors.RaiseException), db.app_conn() as conn:
            conn.execute(
                "SELECT * FROM dwaar_rate_limit_take('x', %s, %s, %s)", (capacity, refill, cost)
            )


def test_token_bucket_is_atomic_under_concurrency(db: DbHandle) -> None:
    import threading

    allowed: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        ok = _take(db, "race", capacity=3, refill=0.001)[0]
        with lock:
            allowed.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(allowed) == [False] * 5 + [True] * 3
