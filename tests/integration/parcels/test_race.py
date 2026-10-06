"""Custody exactly-one invariants under concurrency, and the append-only chain in the database (AT-13, PAR-02, PAR-03, DB-02).

REQ: PAR-02 (exactly one current custodian), PAR-03 (single-use token: one winner), DB-02 (custody history is append-only).
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("PAR-02", "PAR-03", "DB-02")]


# REQ: PAR-03
def test_concurrent_collect_attempts_with_real_threads_have_exactly_one_winner(pw: PW) -> None:
    h = pw.household("A-101")
    stored = pw.stored_parcel(h.unit)
    _, token = pw.issue_token(h.owner, stored)
    barrier = threading.Barrier(8)

    def attempt(_: int) -> tuple[int, str | None]:
        barrier.wait()
        r = pw.call(
            pw.guard, "POST", f"/v1/parcels/{stored['id']}/collect", json=pw.collect_body(token)
        )
        return r.status_code, (r.json().get("details") or {}).get("reason")

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    winners = [r for r in results if r[0] == 200]
    losers = [r for r in results if r[0] != 200]
    assert len(winners) == 1, results
    assert all(code == 409 and reason == "already_collected" for code, reason in losers), results
    assert pw.rows(
        "SELECT count(*) FROM custody_transfers WHERE parcel_id = %s AND reason = 'collected'",
        (stored["id"],),
    ) == [(1,)]
    assert pw.rows(
        "SELECT count(*) FROM parcel_pickup_attempts WHERE parcel_id = %s AND outcome = 'granted'",
        (stored["id"],),
    ) == [(1,)]
    assert pw.rows(
        "SELECT count(*) FROM parcel_pickup_attempts WHERE parcel_id = %s AND outcome = 'denied'",
        (stored["id"],),
    ) == [(7,)]
    assert pw.rows(
        "SELECT count(*) FROM outbox WHERE event_type = 'ParcelCollected' AND aggregate_id = %s",
        (stored["id"],),
    ) == [(1,)]


def test_concurrent_store_and_collect_never_fork_the_chain(pw: PW) -> None:
    h = pw.household("A-101")
    received = pw.receive(h.unit)
    barrier = threading.Barrier(6)

    def store(i: int) -> int:
        barrier.wait()
        r = pw.call(
            pw.guard,
            "POST",
            f"/v1/parcels/{received['id']}/store",
            json={"bin_code": f"B-{i}", "expected_version": received["version"]},
        )
        return int(r.status_code)

    with ThreadPoolExecutor(6) as pool:
        codes = list(pool.map(store, range(6)))
    assert sorted(codes).count(200) == 1, codes
    assert pw.rows(
        "SELECT count(*) FROM custody_transfers WHERE parcel_id = %s", (received["id"],)
    ) == [(2,)]


# REQ: DB-02
def test_the_custody_chain_is_append_only_for_every_runtime_role(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.stored_parcel(h.unit)
    for sql in (
        "UPDATE custody_transfers SET to_party = 'lost' WHERE parcel_id = %s",
        "DELETE FROM custody_transfers WHERE parcel_id = %s",
        "UPDATE parcel_pickup_attempts SET outcome = 'granted' WHERE parcel_id = %s",
        "DELETE FROM courier_observations WHERE parcel_id = %s",
    ):
        with pytest.raises(psycopg.DatabaseError), pw.idh.db.app_conn(society_id=pw.soc.id) as conn:
            conn.execute(sql, (p["id"],))  # type: ignore[call-overload]
    with pytest.raises(psycopg.DatabaseError), pw.idh.db.admin_conn() as conn:
        conn.execute(
            "DELETE FROM custody_transfers WHERE parcel_id = %s", (p["id"],)
        )  # even a superuser: the trigger refuses


def test_the_database_refuses_a_forked_or_broken_chain(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.stored_parcel(h.unit)  # chain: 1 courier->guard, 2 guard->storage

    def raw(sql: str, params: tuple[object, ...]) -> None:
        with pw.idh.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(pw.soc.id),))
            conn.execute(sql, params)  # type: ignore[call-overload]

    insert = "INSERT INTO custody_transfers (society_id, parcel_id, seq, prev_seq, from_party, to_party, reason) VALUES (%s, %s, %s, %s, %s, %s, 'collected')"
    with pytest.raises(
        psycopg.errors.UniqueViolation
    ):  # a second successor of link 1: a fork, two custodians
        raw(insert, (pw.soc.id, p["id"], 2, 1, f"guard:{pw.guard.id}", "resident"))
    with pytest.raises(psycopg.errors.CheckViolation):  # from_party is not the current custodian
        raw(insert, (pw.soc.id, p["id"], 3, 2, "guard:somebody-else", "resident"))
    with pytest.raises(psycopg.errors.CheckViolation):  # a skipped link
        raw(insert, (pw.soc.id, p["id"], 5, 3, "storage:B-07", "resident"))
    raw(
        insert, (pw.soc.id, p["id"], 3, 2, "storage:B-07", "resident")
    )  # the legitimate next link is accepted


def test_a_parcel_row_must_not_claim_custody_before_receipt(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit)
    with pytest.raises(psycopg.errors.CheckViolation), pw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(pw.soc.id),))
        conn.execute(
            "UPDATE parcels SET custodian = 'guard:x', custody_seq = 1 WHERE id = %s", (exp["id"],)
        )  # type: ignore[call-overload]
    assert uuid.UUID(exp["id"])
