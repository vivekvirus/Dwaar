"""Migrations 0010, 0104, 0206, 0314: what ``dwaar_worker`` may write, and what it still may not (RLS context rules intact).

REQ: PRD 12.4 (a job's mutation commits with its audit and outbox row), INV-01, DB-02, ARCH-03.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg import errors as pg

from tests._harness.pgfixtures import DbHandle
from tests.integration.edge._support import EdgeWorld, ew  # noqa: F401

pytestmark = [pytest.mark.req("INV-01", "DB-02", "ARCH-03")]

EVENT = (
    "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id, aggregate_version, event_type,"
    " occurred_at, actor_ref, correlation_id, payload, payload_hash) VALUES (%s, 1, %s, 'probe', %s, 1, 'ProbeHappened',"
    " now(), 'system:worker', %s, '{}'::jsonb, %s)"
)
HASH = "sha256:" + "0" * 64


def insert_event(conn: psycopg.Connection, society: uuid.UUID) -> None:
    conn.execute(EVENT, (uuid.uuid4(), society, uuid.uuid4(), uuid.uuid4(), HASH))  # type: ignore[call-overload]


@pytest.fixture
def societies(ew: EdgeWorld) -> tuple[uuid.UUID, uuid.UUID]:
    return ew.soc.id, ew.idh.society("Beta Heights", units=("A-1",)).id


@pytest.fixture
def db(ew: EdgeWorld) -> DbHandle:
    return ew.idh.db


def worker_conn(db: DbHandle) -> psycopg.Connection:
    return psycopg.connect(db.worker_dsn, autocommit=False)


def test_worker_inserts_an_outbox_event_only_into_the_society_of_its_context(
    db: DbHandle, societies: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, b = societies
    with worker_conn(db) as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a),))
        insert_event(conn, a)  # its own society: fine
        conn.commit()
    with (
        worker_conn(db) as conn,
        pytest.raises(pg.InsufficientPrivilege),
    ):  # RLS WITH CHECK: row-level security policy violation
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a),))
        insert_event(conn, b)  # another society: refused
    with worker_conn(db) as conn, pytest.raises(pg.InsufficientPrivilege):
        insert_event(conn, a)  # no context at all: refused


def test_worker_cannot_set_delivery_columns_update_content_or_delete(
    db: DbHandle, societies: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, _b = societies
    with worker_conn(db) as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a),))
        insert_event(conn, a)
        conn.commit()
    for sql in (
        "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id, aggregate_version, event_type, occurred_at,"
        " actor_ref, correlation_id, payload, payload_hash, published_at) VALUES (gen_random_uuid(), 1, %(s)s, 'probe', gen_random_uuid(), 1,"
        " 'X', now(), 'w', gen_random_uuid(), '{}', %(h)s, now())",  # an event born 'published' would never be relayed
        "INSERT INTO outbox (event_id, schema_version, society_id, aggregate_type, aggregate_id, aggregate_version, event_type, occurred_at,"
        " actor_ref, correlation_id, payload, payload_hash, attempts) VALUES (gen_random_uuid(), 1, %(s)s, 'probe', gen_random_uuid(), 1,"
        " 'X', now(), 'w', gen_random_uuid(), '{}', %(h)s, 9)",
        "UPDATE outbox SET payload = '{\"x\": 1}'::jsonb",
        "UPDATE outbox SET event_type = 'Other'",
        "DELETE FROM outbox",
    ):
        with worker_conn(db) as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a),))
            with pytest.raises((pg.InsufficientPrivilege, pg.RaiseException)):
                conn.execute(sql, {"s": a, "h": HASH})  # type: ignore[call-overload]


def test_the_runtime_api_role_is_unchanged_and_the_worker_still_has_no_cross_society_read(
    db: DbHandle, societies: tuple[uuid.UUID, uuid.UUID]
) -> None:
    with worker_conn(db) as conn:
        assert conn.execute("SELECT count(*) FROM societies").fetchone() == (
            0,
        )  # FORCE RLS: no context, no row
        assert (
            conn.execute("SELECT count(*) FROM outbox").fetchone() is not None
        )  # (relay SELECT policy: not asserted here)
    with psycopg.connect(db.app_dsn) as app, pytest.raises(pg.InsufficientPrivilege):
        app.execute("SELECT dwaar_active_society_ids()")  # EXECUTE is the worker's alone


def test_active_society_ids_is_worker_only_ids_only_and_skips_inactive_societies(
    db: DbHandle, societies: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, b = societies
    with worker_conn(db) as conn:
        assert {r[0] for r in conn.execute("SELECT dwaar_active_society_ids()").fetchall()} == {
            a,
            b,
        }
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(b),))  # type: ignore[call-overload]
        conn.execute("UPDATE societies SET status = 'suspended' WHERE id = %s", (b,))  # type: ignore[call-overload]
    with worker_conn(db) as conn:
        assert [r[0] for r in conn.execute("SELECT dwaar_active_society_ids()").fetchall()] == [a]
        conn.execute("SELECT dwaar_active_society_ids()")
        # the flag that opens the owner policy is gone again after the call: a plain SELECT is still empty
        assert conn.execute("SELECT count(*) FROM societies").fetchone() == (0,)
    with (
        worker_conn(db) as conn
    ):  # forging the flag as the worker does not open the policy: it is scoped TO dwaar_owner
        conn.execute("SELECT set_config('dwaar.society_index', 'on', true)")
        assert conn.execute("SELECT count(*) FROM societies").fetchone() == (0,)


def test_worker_keeps_no_rights_the_jobs_do_not_need(
    db: DbHandle, societies: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, _b = societies
    with worker_conn(db) as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a),))
        for sql in (
            "UPDATE invitations SET uses = 3",  # the pass sweep may change state and version only
            "UPDATE invitations SET revoked_version = 9",
            "UPDATE policy_snapshots SET signature = 'x'",
            "DELETE FROM policy_snapshots",
            "UPDATE gate_policies SET approval_expiry_seconds = 3600",  # only the revocation counter
            "INSERT INTO visits (id) VALUES (gen_random_uuid())",
        ):
            with pytest.raises(pg.Error):
                conn.execute(sql)
            conn.rollback()
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a),))
