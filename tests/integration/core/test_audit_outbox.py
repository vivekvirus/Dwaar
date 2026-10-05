"""audit_log + outbox + domain change are ONE transaction (PRD 12.4); masked diffs; outbox relay claim."""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError

from dwaar_api.core.audit import (
    AuditError,
    MutationResult,
    emit_event,
    masked_diff,
    mutation,
    record_audit,
)
from dwaar_api.core.db import Database, RequestContext
from dwaar_common.events import CanonicalJsonError, DomainEvent, payload_hash
from dwaar_common.ids import is_uuid7
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    SOCIETY_A,
    SOCIETY_B,
    create_probe_table,
)

pytestmark = pytest.mark.req("INV-01", "INV-02", "DB-02")

REQUEST_ID = uuid.UUID("0192f300-0000-7000-8000-0000000000aa")
CTX = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", REQUEST_ID)


@pytest.fixture
def database(db: DbHandle) -> Iterator[Database]:
    create_probe_table(db)
    database = Database(db.app_dsn, db.worker_dsn)
    try:
        yield database
    finally:
        database.dispose()


def totals(db: DbHandle) -> dict[str, int]:
    with db.admin_conn() as conn:
        result: dict[str, int] = {}
        for table in ("probe_things", "audit_log", "outbox"):
            row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()  # type: ignore[call-overload]  # noqa: S608
            assert row is not None
            result[table] = int(row[0])
        return result


def insert_thing(conn: Connection, name: str = "pass", phone: str | None = None) -> MutationResult:
    row = (
        conn.execute(
            text(
                "INSERT INTO probe_things (society_id, name, phone) VALUES (:s, :n, :p) RETURNING id, version"
            ),
            {"s": SOCIETY_A, "n": name, "p": phone},
        )
        .mappings()
        .one()
    )
    return MutationResult(
        object_id=row["id"],
        object_version=row["version"],
        after={"id": row["id"], "name": name, "phone": phone},
        event_payload={"name": name},
    )


def run(database: Database, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "operation": "probe.thing.create",
        "object_type": "probe_thing",
        "event_type": "ThingCreated",
        "apply": insert_thing,
    }
    kwargs.update(overrides)
    with database.app_tx(CTX) as conn:
        return mutation(conn, CTX, **kwargs)


def test_mutation_commits_domain_audit_and_outbox_together(
    db: DbHandle, database: Database
) -> None:
    def apply(conn: Connection) -> MutationResult:
        return insert_thing(conn, "Visitor pass", phone="+91 99999 00123")

    outcome = run(
        database, apply=apply, reason="created by committee", approver_id=uuid.UUID(int=7)
    )
    assert totals(db) == {"probe_things": 1, "audit_log": 1, "outbox": 1}
    with db.app_conn(society_id=SOCIETY_A) as conn:
        audit = conn.execute(
            "SELECT society_id, actor_id, effective_role, operation, object_type, object_id, object_version,"
            " diff_masked, reason, approver_id, request_id, at IS NOT NULL FROM audit_log"
        ).fetchone()
        event = conn.execute(
            "SELECT event_id, schema_version, society_id, aggregate_type, aggregate_id, aggregate_version, event_type,"
            " occurred_at, actor_ref, correlation_id, causation_id, payload, payload_hash, published_at, attempts"
            " FROM outbox"
        ).fetchone()
    assert audit is not None
    assert event is not None
    assert audit[:7] == (
        SOCIETY_A, COMMITTEE_A, "committee", "probe.thing.create", "probe_thing", outcome.result.object_id, 1,
    )  # fmt: skip
    assert audit[8:] == ("created by committee", uuid.UUID(int=7), REQUEST_ID, True)
    assert is_uuid7(outcome.audit_id)
    # PRD 12.4 event contract
    assert event[0] == outcome.event.event_id
    assert is_uuid7(event[0])
    assert event[1:7] == (1, SOCIETY_A, "probe_thing", outcome.result.object_id, 1, "ThingCreated")
    assert event[8] == f"person:{COMMITTEE_A}"
    assert event[9] == REQUEST_ID  # correlation id = request id
    assert event[10] is None
    assert event[11] == {"name": "Visitor pass"}
    assert event[12] == payload_hash({"name": "Visitor pass"})
    assert event[13] is None
    assert event[14] == 0
    DomainEvent.from_wire(
        outcome.event.to_wire()
    )  # the stored event round-trips through the shared contract


def test_failure_in_the_domain_function_persists_nothing(db: DbHandle, database: Database) -> None:
    def apply(conn: Connection) -> MutationResult:
        insert_thing(conn)
        raise RuntimeError("domain rule failed after the insert")

    with pytest.raises(RuntimeError, match="domain rule"):
        run(database, apply=apply)
    assert totals(db) == {"probe_things": 0, "audit_log": 0, "outbox": 0}


def test_failure_writing_the_audit_row_rolls_back_domain_and_outbox(
    db: DbHandle, database: Database
) -> None:
    with pytest.raises(DBAPIError):  # operation violates the audit_log CHECK
        run(database, operation="NOT A VALID OPERATION NAME")
    assert totals(db) == {"probe_things": 0, "audit_log": 0, "outbox": 0}


def test_failure_writing_the_outbox_row_rolls_back_domain_and_audit(
    db: DbHandle, database: Database
) -> None:
    with db.owner_conn() as conn:  # inject a database-side failure into the outbox insert
        conn.execute(
            "CREATE FUNCTION fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
            " RAISE EXCEPTION 'injected outbox failure'; END $$"
        )
        conn.execute(
            "CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION fail_outbox()"
        )
    with pytest.raises(DBAPIError):
        run(database)
    assert totals(db) == {"probe_things": 0, "audit_log": 0, "outbox": 0}


def test_invalid_event_envelope_rolls_everything_back(db: DbHandle, database: Database) -> None:
    with pytest.raises(
        ValidationError
    ):  # the shared DomainEvent contract rejects it before any outbox write
        run(database, event_type="bad event type!")
    assert totals(db) == {"probe_things": 0, "audit_log": 0, "outbox": 0}


def test_non_canonical_event_payload_rolls_everything_back(
    db: DbHandle, database: Database
) -> None:
    def apply(conn: Connection) -> MutationResult:
        base = insert_thing(conn)
        return MutationResult(
            base.object_id, base.object_version, after=base.after, event_payload={"amount": 1.5}
        )

    with pytest.raises(CanonicalJsonError):  # money/quantities must not be floats (INV-02)
        run(database, apply=apply)
    assert totals(db) == {"probe_things": 0, "audit_log": 0, "outbox": 0}


def test_caller_can_swallow_a_failed_mutation_and_still_commit_the_rest(
    db: DbHandle, database: Database
) -> None:
    """The savepoint makes the helper atomic on its own, not only when the caller aborts the transaction."""

    def apply_then_fail(conn: Connection) -> MutationResult:
        insert_thing(conn, "doomed")
        raise RuntimeError("nope")

    with database.app_tx(CTX) as conn:
        first = mutation(
            conn,
            CTX,
            operation="probe.thing.create",
            object_type="probe_thing",
            event_type="ThingCreated",
            apply=insert_thing,
        )
        with pytest.raises(RuntimeError):
            mutation(
                conn, CTX, operation="probe.thing.create", object_type="probe_thing", event_type="ThingCreated",
                apply=apply_then_fail,
            )  # fmt: skip
        second = mutation(
            conn,
            CTX,
            operation="probe.thing.create",
            object_type="probe_thing",
            event_type="ThingCreated",
            apply=insert_thing,
        )
    assert first.audit_id != second.audit_id
    assert totals(db) == {"probe_things": 2, "audit_log": 2, "outbox": 2}


def _mutate_then_fail(database: Database) -> None:
    with database.app_tx(CTX) as conn:
        mutation(
            conn,
            CTX,
            operation="probe.thing.create",
            object_type="probe_thing",
            event_type="ThingCreated",
            apply=insert_thing,
        )
        raise RuntimeError("late failure before commit")


def test_outer_transaction_failure_after_a_successful_mutation_rolls_all_back(
    db: DbHandle, database: Database
) -> None:
    with pytest.raises(RuntimeError, match="late"):
        _mutate_then_fail(database)
    assert totals(db) == {"probe_things": 0, "audit_log": 0, "outbox": 0}


def test_audit_and_events_need_a_society_context(database: Database) -> None:
    anonymous = RequestContext(None, COMMITTEE_A, "committee", REQUEST_ID)
    with database.app_tx(anonymous) as conn:
        with pytest.raises(AuditError):
            record_audit(conn, anonymous, operation="probe.x", object_type="probe_thing")
        with pytest.raises(AuditError):
            emit_event(
                conn,
                anonymous,
                aggregate_type="t",
                aggregate_id=uuid.uuid4(),
                aggregate_version=1,
                event_type="X",
            )


def test_platform_level_audit_row_has_no_society(db: DbHandle, database: Database) -> None:
    anonymous = RequestContext(None, None, None, REQUEST_ID)
    with database.app_tx(anonymous) as conn:
        record_audit(
            conn,
            anonymous,
            operation="auth.sign_in_failed",
            object_type="session",
            platform_level=True,
        )
    with db.admin_conn() as conn:
        row = conn.execute("SELECT society_id, actor_id, effective_role FROM audit_log").fetchone()
    assert row == (None, None, "system")


def test_audit_row_for_another_society_is_refused_by_rls(db: DbHandle, database: Database) -> None:
    mismatched = RequestContext(SOCIETY_B, COMMITTEE_A, "committee", REQUEST_ID)
    with (
        pytest.raises(DBAPIError),
        database.app_tx(CTX) as conn,
    ):  # transaction context is A, row says B
        record_audit(conn, mismatched, operation="probe.forged", object_type="probe_thing")
    assert totals(db)["audit_log"] == 0


# ------------------------------------------------------------------------------------ masking
def test_diff_masks_personal_and_secret_fields_but_keeps_the_change_visible() -> None:
    before = {
        "name": "Asha",
        "phone": "+91 99999 00123",
        "phone_enc": "v1:abcdef",
        "aadhaar": "1234 5678 9012",
        "otp": "123456",
        "bank_account_number": "123456789012",
        "pan_enc": "v1:zzzz",
        "status": "pending",
        "note": "call +91 99999 00456 or 9999900789 about it",
        "unchanged": "same",
    }
    after = {
        **before,
        "phone": "+91 99999 00999",
        "status": "verified",
        "note": "reach 099999 00456 later",
    }
    diff = masked_diff(before, after)
    changed = diff["changed"]
    assert diff["op"] == "update"
    assert set(changed) == {"phone", "status", "note"}  # unchanged fields are not copied
    assert changed["phone"] == {
        "before": "[REDACTED]",
        "after": "[REDACTED]",
    }  # THAT it changed is visible
    assert changed["status"] == {"before": "pending", "after": "verified"}
    dumped = json.dumps(diff)
    for secret in (
        "99999 00123",
        "99999 00999",
        "99999 00456",
        "9999900789",
        "123456789012",
        "1234 5678 9012",
        "abcdef",
    ):
        assert secret not in dumped


def test_diff_for_create_and_delete_and_nested_values() -> None:
    created = masked_diff(
        None,
        {"id": uuid.UUID(int=1), "contact": {"phone": "9999900123", "city": "Pune"}, "tags": ["a"]},
    )
    assert created["op"] == "create"
    assert created["changed"]["contact"]["after"] == {"phone": "[REDACTED]", "city": "Pune"}
    assert created["changed"]["id"]["after"] == str(uuid.UUID(int=1))
    deleted = masked_diff({"secret_token": "tok-123", "label": "x"}, None)
    assert deleted["op"] == "delete"
    assert deleted["changed"]["secret_token"]["before"] == "[REDACTED]"
    custom = masked_diff({"nickname": "Ash"}, {"nickname": "Ashu"}, redact=["nickname"])
    assert custom["changed"]["nickname"] == {"before": "[REDACTED]", "after": "[REDACTED]"}


def test_audit_row_in_the_database_contains_no_raw_pii(db: DbHandle, database: Database) -> None:
    def apply(conn: Connection) -> MutationResult:
        return insert_thing(conn, "Pass for 9999900123 holder", phone="+91 99999 00123")

    run(database, apply=apply, reason="requested by +91 99999 00123")
    with db.admin_conn() as conn:
        diff, reason = conn.execute("SELECT diff_masked::text, reason FROM audit_log").fetchone()  # type: ignore[misc]
    assert "00123" not in diff
    assert "9999900123" not in diff
    assert "00123" not in reason


# ------------------------------------------------------------------------------------ outbox relay
def _seed_events(database: Database, count: int) -> None:
    for i in range(count):
        with database.app_tx(CTX) as conn:
            emit_event(
                conn, CTX, aggregate_type="probe_thing", aggregate_id=uuid.uuid4(), aggregate_version=1,
                event_type="ThingCreated", payload={"n": i},
            )  # fmt: skip


def test_relay_claims_disjoint_batches_with_skip_locked(db: DbHandle, database: Database) -> None:
    _seed_events(database, 6)
    claim_sql = text(
        "SELECT event_id FROM outbox WHERE published_at IS NULL AND next_attempt_at <= now()"
        " ORDER BY next_attempt_at, event_id FOR UPDATE SKIP LOCKED LIMIT 3"
    )
    claimed: list[set[uuid.UUID]] = []
    first_has_claimed = threading.Event()
    second_done = threading.Event()

    def relay_one() -> None:
        with database.worker_tx() as conn:
            rows = {r[0] for r in conn.execute(claim_sql)}
            claimed.append(rows)
            first_has_claimed.set()
            second_done.wait(10)  # keep the row locks while the second relay claims
            conn.execute(
                text(
                    "UPDATE outbox SET published_at = now(), attempts = attempts + 1 WHERE event_id = ANY(:ids)"
                ),
                {"ids": list(rows)},
            )

    thread = threading.Thread(target=relay_one)
    thread.start()
    assert first_has_claimed.wait(10)
    with database.worker_tx() as conn:
        second = {r[0] for r in conn.execute(claim_sql)}
    second_done.set()
    thread.join(10)
    assert len(claimed[0]) == 3
    assert len(second) == 3
    assert claimed[0].isdisjoint(second)
    with db.admin_conn() as conn:
        assert conn.execute(
            "SELECT count(*) FROM outbox WHERE published_at IS NOT NULL"
        ).fetchone() == (3,)


def test_claim_query_can_use_the_partial_index(db: DbHandle, database: Database) -> None:
    _seed_events(database, 3)
    with db.admin_conn() as conn:
        conn.execute("SET enable_seqscan = off")
        plan = "\n".join(
            r[0]
            for r in conn.execute(
                "EXPLAIN SELECT event_id FROM outbox WHERE published_at IS NULL AND next_attempt_at <= now()"
                " ORDER BY next_attempt_at, event_id FOR UPDATE SKIP LOCKED LIMIT 10"
            )
        )
    assert "outbox_claim_idx" in plan
