"""W1 adversarial verification: append-only history (audit_log / outbox) and mutation atomicity (DB-02, PRD 12.4).

Not collected by ``make test``; run explicitly:
    uv run --no-sync pytest tests/security/verify_w1_history.py -p no:cacheprovider

A FAILING test asserts the secure behaviour and therefore marks a confirmed defect.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg import errors
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from dwaar_api.core.audit import MutationResult, mutation
from dwaar_api.core.db import RequestContext
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    SOCIETY_A,
    SOCIETY_B,
    CoreHarness,
    core_harness,
)

pytestmark = pytest.mark.req("DB-02", "INV-01", "INV-02")

AUDIT_COLS = "(society_id, actor_id, effective_role, operation, object_type, object_id)"
HASH = "sha256:" + "0" * 64


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


def _audit(db: DbHandle, society: uuid.UUID | None = SOCIETY_A) -> uuid.UUID:
    audit_id = uuid.uuid4()
    with db.app_conn(society_id=society) as conn:
        conn.execute(
            "INSERT INTO audit_log (id, society_id, actor_id, effective_role, operation, object_type, object_id)"
            " VALUES (%s, %s, %s, 'committee', 'probe.seed', 'probe_thing', %s)",
            (audit_id, society, COMMITTEE_A, uuid.uuid4()),
        )
    return audit_id


def _outbox(db: DbHandle, society: uuid.UUID = SOCIETY_A, **cols: Any) -> uuid.UUID:
    event_id = uuid.uuid4()
    names = ["event_id", "schema_version", "society_id", "aggregate_type", "aggregate_id",
             "aggregate_version", "event_type", "occurred_at", "actor_ref", "correlation_id",
             "payload", "payload_hash", *cols]  # fmt: skip
    values: list[Any] = [event_id, 1, society, "probe_thing", uuid.uuid4(), 1, "ThingCreated",
                         dt.datetime.now(dt.UTC), "system", uuid.uuid4(), "{}", HASH, *cols.values()]  # fmt: skip
    marks = ", ".join("%s::jsonb" if n == "payload" else "%s" for n in names)
    with db.app_conn(society_id=society) as conn:
        conn.execute(f"INSERT INTO outbox ({', '.join(names)}) VALUES ({marks})", values)  # type: ignore[call-overload]
    return event_id


# ------------------------------------------------------------------------------------------------
# (2) append-only: UPDATE / DELETE / TRUNCATE / trigger tampering by runtime roles
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["app", "worker"])
@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO audit_log (id, society_id, effective_role, operation, object_type) SELECT id, society_id, 'x', 'a.b', 't' FROM audit_log ON CONFLICT (id) DO UPDATE SET operation = 'forged.op'",
        "MERGE INTO audit_log a USING (SELECT 1) s ON true WHEN MATCHED THEN UPDATE SET operation = 'forged.op'",
        "MERGE INTO audit_log a USING (SELECT 1) s ON true WHEN MATCHED THEN DELETE",
        "SELECT id FROM audit_log FOR UPDATE",
        "SELECT id FROM audit_log FOR NO KEY UPDATE",
        "TRUNCATE audit_log, outbox CASCADE",
        "ALTER TABLE audit_log DISABLE TRIGGER ALL",
        "ALTER TABLE outbox DISABLE TRIGGER dwaar_history_guard",
        "ALTER TABLE audit_log OWNER TO dwaar_app",
        "ALTER TABLE audit_log SET UNLOGGED",
        "CREATE RULE r AS ON DELETE TO audit_log DO INSTEAD NOTHING",
        "CREATE TRIGGER evil BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION dwaar_reject_mutation()",
        "DROP FUNCTION dwaar_outbox_guard() CASCADE",
        "DELETE FROM purge_log",
        "INSERT INTO purge_log (table_name, row_count, reason) VALUES ('audit_log', 0, 'forged purge entry')",
        "UPDATE outbox SET payload = '{\"x\": 1}'::jsonb",
        "UPDATE outbox SET society_id = society_id",
    ],
)
def test_history_cannot_be_rewritten_by_runtime_roles(
    db: DbHandle, role: str, statement: str
) -> None:
    _audit(db)
    _outbox(db)
    opener = db.app_conn if role == "app" else db.worker_conn
    with pytest.raises((errors.InsufficientPrivilege, errors.FeatureNotSupported)):
        with opener(society_id=SOCIETY_A) as conn:
            conn.execute(statement)  # type: ignore[call-overload]


def test_runtime_roles_hold_exactly_the_expected_privileges_on_history_tables(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        rows = conn.execute(
            """
            SELECT t, r, p, has_table_privilege(r, t, p)
            FROM unnest(ARRAY['audit_log', 'outbox', 'purge_log']) AS t,
                 unnest(ARRAY['dwaar_app', 'dwaar_worker', 'public']) AS r,
                 unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES']) AS p
            WHERE has_table_privilege(r, t, p)
            """
        ).fetchall()
        outbox_cols = conn.execute(
            "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = 'outbox'::regclass AND a.attnum > 0"
            " AND NOT a.attisdropped AND has_column_privilege('dwaar_worker', 'outbox', a.attname, 'UPDATE')"
        ).fetchall()
        app_outbox = conn.execute(
            "SELECT count(*) FROM pg_attribute a WHERE a.attrelid = 'outbox'::regclass AND a.attnum > 0"
            " AND NOT a.attisdropped AND has_column_privilege('dwaar_app', 'outbox', a.attname, 'UPDATE')"
        ).fetchone()
    unexpected = [
        r for r in rows if not (r[0] == "outbox" and r[1] == "dwaar_worker" and r[2] == "UPDATE")
    ]
    assert unexpected == [], unexpected
    assert sorted(c[0] for c in outbox_cols) == [
        "attempts",
        "last_error",
        "next_attempt_at",
        "published_at",
    ]
    assert app_outbox == (0,)


def test_audit_timestamp_cannot_be_backdated_by_the_runtime_role(db: DbHandle) -> None:
    """``at`` is a plain INSERT column with DEFAULT now(): the API role may write any value, so a buggy or
    compromised handler can place a forged row anywhere in the audit timeline (and reorder history)."""
    long_ago = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    forged = uuid.uuid4()
    try:
        with db.app_conn(society_id=SOCIETY_A) as conn:
            conn.execute(
                "INSERT INTO audit_log (id, society_id, effective_role, operation, object_type, at)"
                " VALUES (%s, %s, 'committee', 'forged.backdated', 'x', %s)",
                (forged, SOCIETY_A, long_ago),
            )
    except (errors.InsufficientPrivilege, errors.CheckViolation, errors.RaiseException):
        return
    with db.app_conn(society_id=SOCIETY_A) as conn:
        at = conn.execute("SELECT at FROM audit_log WHERE id = %s", (forged,)).fetchone()
    assert at is not None
    pytest.fail(
        f"audit row accepted with at={at[0]:%Y-%m-%d} (server time is {dt.datetime.now(dt.UTC):%Y-%m-%d})"
    )


def test_outbox_rows_cannot_be_inserted_already_published_or_parked(db: DbHandle) -> None:
    """The API role may INSERT every column. A row inserted with published_at set (or next_attempt_at in
    year 9999) is never relayed: a silent, permanent loss of a domain event."""
    for name, value in (
        ("published_at", dt.datetime.now(dt.UTC)),
        ("next_attempt_at", dt.datetime(9999, 1, 1, tzinfo=dt.UTC)),
        ("attempts", 10_000),
    ):
        try:
            _outbox(db, **{name: value})
        except (errors.InsufficientPrivilege, errors.CheckViolation, errors.RaiseException):
            continue
        pytest.fail(f"outbox accepted a client-supplied delivery field {name!r} on INSERT")


def test_worker_can_publish_but_never_unpublish_or_edit_events(db: DbHandle) -> None:
    """Attack that failed: the relay may flip published_at once (USING (true)); the guard trigger blocks undo."""
    event = _outbox(db, SOCIETY_A)
    with db.worker_conn() as conn:
        conn.execute("UPDATE outbox SET published_at = now() WHERE event_id = %s", (event,))
        with pytest.raises(psycopg.DatabaseError, match="already published"):
            conn.execute("UPDATE outbox SET published_at = NULL WHERE event_id = %s", (event,))


# ------------------------------------------------------------------------------------------------
# (4) audit/outbox atomicity under failure injection
# ------------------------------------------------------------------------------------------------
def _counts(db: DbHandle) -> tuple[int, int, int]:
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        things = conn.execute("SELECT count(*) FROM probe_things").fetchone()
        audits = conn.execute("SELECT count(*) FROM audit_log").fetchone()
        events = conn.execute("SELECT count(*) FROM outbox").fetchone()
    assert things and audits and events
    return things[0], audits[0], events[0]


def _apply(name: str = "x") -> Any:
    def apply(c: Any) -> MutationResult:
        row = c.execute(
            text("INSERT INTO probe_things (society_id, name) VALUES (:s, :n) RETURNING id"),
            {"s": SOCIETY_A, "n": name},
        ).one()
        return MutationResult(row[0], 1, after={"name": name}, event_payload={"name": name})

    return apply


def _ctx() -> RequestContext:
    return RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.uuid4())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"object_type": "t" * 101},  # audit CHECK fails AFTER the domain insert
        {"operation": "Bad Operation!"},  # audit CHECK fails
        {"event_type": "bad type"},  # DomainEvent validation fails AFTER audit insert
        {"aggregate_type": "a" * 101},  # outbox CHECK/validation fails AFTER audit insert
    ],
)
def test_any_failure_in_audit_or_outbox_rolls_back_the_domain_write(
    core: CoreHarness, kwargs: dict[str, Any]
) -> None:
    base: dict[str, Any] = {
        "operation": "probe.thing.create",
        "object_type": "probe_thing",
        "event_type": "ThingCreated",
    }
    base.update(kwargs)
    before = _counts(core.db)
    ctx = _ctx()
    with pytest.raises(Exception):  # noqa: B017, PT011
        with core.database.app_tx(ctx) as conn:
            mutation(conn, ctx, apply=_apply(), **base)
    assert _counts(core.db) == before


def test_caught_failure_does_not_poison_a_later_successful_mutation_in_the_same_transaction(
    core: CoreHarness,
) -> None:
    ctx = _ctx()
    with core.database.app_tx(ctx) as conn:
        with pytest.raises(Exception):  # noqa: B017, PT011
            mutation(
                conn,
                ctx,
                operation="probe.a",
                object_type="t" * 101,
                event_type="E",
                apply=_apply("bad"),
            )
        mutation(
            conn,
            ctx,
            operation="probe.b",
            object_type="probe_thing",
            event_type="ThingCreated",
            apply=_apply("good"),
        )
    assert _counts(core.db) == (1, 1, 1)


def test_mutation_with_a_context_that_disagrees_with_the_transaction_scope_is_rejected(
    core: CoreHarness,
) -> None:
    """Audit/outbox take society from ``ctx`` while RLS takes it from the transaction GUC: a mismatch must
    fail in the database (WITH CHECK), not write a society-B audit row from a society-A transaction."""
    tx_ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.uuid4())
    lying_ctx = RequestContext(SOCIETY_B, COMMITTEE_A, "committee", uuid.uuid4())
    before = _counts(core.db)
    with pytest.raises(Exception):  # noqa: B017, PT011
        with core.database.app_tx(tx_ctx) as conn:
            mutation(
                conn,
                lying_ctx,
                operation="probe.x",
                object_type="probe_thing",
                event_type="ThingCreated",
                apply=_apply(),
            )
    assert _counts(core.db) == before


def test_backend_killed_between_domain_write_and_commit_leaves_nothing(core: CoreHarness) -> None:
    before = _counts(core.db)
    ctx = _ctx()
    with pytest.raises((DBAPIError, psycopg.Error)):
        with core.database.app_tx(ctx) as conn:
            mutation(
                conn,
                ctx,
                operation="probe.thing.create",
                object_type="probe_thing",
                event_type="ThingCreated",
                apply=_apply(),
            )
            pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
            with core.db.admin_conn() as admin:
                admin.execute("SELECT pg_terminate_backend(%s)", (pid,))
            conn.execute(text("SELECT 1"))  # forces the failure
    assert _counts(core.db) == before


def test_idempotent_http_failure_after_insert_leaves_no_rows_and_frees_the_key(
    core: CoreHarness,
) -> None:
    client = core.client()
    headers = {**core.auth(COMMITTEE_A), "Idempotency-Key": "partial-failure-0001"}
    before = _counts(core.db)
    for name in ("__policy__", "__crash__"):
        resp = client.post(f"/v1/probe/{SOCIETY_A}/things", headers=headers, json={"name": name})
        assert resp.status_code in (422, 500)
        assert _counts(core.db) == before
    ok = client.post(f"/v1/probe/{SOCIETY_A}/things", headers=headers, json={"name": "fine"})
    assert ok.status_code == 201
    assert _counts(core.db) == (before[0] + 1, before[1] + 1, before[2] + 1)
