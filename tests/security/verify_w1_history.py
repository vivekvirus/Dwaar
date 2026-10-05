"""OPEN findings from W1 verification: append-only history (audit_log / outbox) and mutation atomicity (DB-02, PRD 12.4).

Not collected by ``make test``; run explicitly with
``uv run --no-sync pytest tests/security/verify_w1_history.py -p no:cacheprovider``.

A FAILING test asserts the secure behaviour and marks a defect that is NOT fixed yet (not part of fix round 1).
When one is fixed, move it to ``tests/security/test_w1_history.py``. Tests for fixed findings live in
``tests/security/test_w1_*.py``.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import text

from dwaar_api.core.audit import MutationResult, mutation
from dwaar_api.core.db import RequestContext
from dwaar_common.errors import DwaarError
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    SOCIETY_A,
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


def test_owner_can_delete_history_by_forging_the_flag_and_leave_no_purge_log(db: DbHandle) -> None:
    """The purge flag is a plain GUC. Only the table owner may forge it, and the migration role IS the
    owner, so a compromised migration/deploy credential erases audit rows with no purge_log entry.
    Documented trust boundary; reported so the owner credential is treated as break-glass."""
    audit_id = _audit(db)
    with db.owner_conn() as conn:
        conn.execute(
            "SELECT set_config('dwaar.purge_table', 'audit_log'::regclass::oid::text, true)"
        )
        deleted = conn.execute("DELETE FROM audit_log WHERE id = %s", (audit_id,)).rowcount
    with db.owner_conn() as conn:
        conn.execute(
            "SELECT set_config('dwaar.purge_table', 'audit_log'::regclass::oid::text, true)"
        )
        purge_rows = conn.execute("SELECT count(*) FROM purge_log").fetchone()
    assert deleted == 0 or purge_rows != (0,), (
        "history deleted by owner without any purge_log evidence"
    )


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


def test_unserialisable_event_payloads_fail_as_controlled_errors_not_500s(
    core: CoreHarness,
) -> None:
    """Lone surrogates make canonical_json raise UnicodeEncodeError (not a DwaarError/ValueError the API maps)."""
    ctx = _ctx()

    def apply(c: Any) -> MutationResult:
        return MutationResult(uuid.uuid4(), 1, after={}, event_payload={"note": "\ud800"})

    with pytest.raises(DwaarError):
        with core.database.app_tx(ctx) as conn:
            mutation(
                conn,
                ctx,
                operation="probe.x",
                object_type="probe_thing",
                event_type="ThingCreated",
                apply=apply,
            )


def test_http_nul_byte_in_a_text_field_is_a_400_not_a_500(core: CoreHarness) -> None:
    from tests.integration.core._support import RESIDENT_A  # noqa: F401

    client = core.client()
    resp = client.post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "nul-byte-key-0001"},
        json={"name": "a\u0000b"},
    )
    assert resp.status_code in (400, 422), (resp.status_code, resp.text[:200])
