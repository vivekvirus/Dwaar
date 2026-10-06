"""Courier claims are external observations (PAR-04); reminders at 24 h and 48 h and the custody report (PAR-05).

REQ: PAR-04, PAR-05, INV-07.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from dramatiq import Worker

from dwaar_api.modules.parcels import jobs
from dwaar_worker.broker import make_stub_broker
from tests.integration.parcels._support import PW, iso, now

pytestmark = [pytest.mark.req("PAR-04", "PAR-05", "INV-07")]


def _claim(pw: PW, parcel_id: str, claim: str = "delivered", who=None):  # type: ignore[no-untyped-def]
    return pw.call(
        who or pw.guard, "POST", f"/v1/parcels/{parcel_id}/courier-claims",
        json={"source": "courier_app", "claim": claim, "claimed_at": iso(now()), "external_ref": "EXT-77"},
    )  # fmt: skip


# REQ: PAR-04
def test_a_courier_delivered_claim_is_an_external_observation_and_never_custody(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit, "Zomart")
    before_chain = pw.rows("SELECT count(*) FROM custody_transfers")[0][0]
    r = _claim(pw, exp["id"])
    assert r.status_code == 201 and r.json()["external"] is True
    view = pw.call(h.owner, "GET", f"/v1/parcels/{exp['id']}").json()
    assert view["state"] == "expected", "a claim never moves the parcel"
    assert view["in_society_custody"] is False and view["custodian"] is None
    assert view["courier_says_delivered"] is True
    assert (
        view["courier_claims"][0]["external"] is True
        and view["courier_claims"][0]["claim"] == "delivered"
    )
    assert pw.rows("SELECT count(*) FROM custody_transfers")[0][0] == before_chain, (
        "separate from society custody"
    )
    assert pw.rows("SELECT external FROM courier_observations")[0][0] is True


def test_a_claim_after_receipt_keeps_custody_and_the_claim_apart(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.receive(h.unit)
    _claim(pw, p["id"], "attempted")
    _claim(pw, p["id"], "delivered")
    view = pw.call(h.owner, "GET", f"/v1/parcels/{p['id']}").json()
    assert view["state"] == "received_at_gate" and view["in_society_custody"] is True
    assert [c["claim"] for c in view["courier_claims"]] == ["attempted", "delivered"]
    assert all(c["external"] for c in view["courier_claims"])


def test_a_gate_entry_is_never_shown_as_a_delivery(pw: PW) -> None:
    h = pw.household("A-101")
    visit = pw.vw.raise_request(h.unit, kind="delivery", visitor_alias="Rider")
    pw.vw.decide(h.owner, visit)
    assert pw.call(h.owner, "GET", "/v1/parcels").json()["items"] == []
    assert pw.rows("SELECT count(*) FROM parcels")[0][0] == 0, (
        "a delivery visit creates no parcel and no custody"
    )


def test_only_gate_staff_record_claims_and_a_stranger_cannot_read_them(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.receive(h.unit)
    assert _claim(pw, p["id"], who=h.owner).status_code == 403
    stranger = pw.household("A-102")
    assert pw.call(stranger.owner, "GET", f"/v1/parcels/{p['id']}").status_code == 404
    assert _claim(pw, "00000000-0000-4000-8000-000000000001").status_code == 404


# REQ: PAR-05
def test_reminders_at_24_and_48_hours_are_created_once(pw: PW) -> None:
    h = pw.household("A-101")
    fresh = pw.receive(h.unit, "Fresh")
    old = pw.stored_parcel(h.unit, "Old")
    pw.sql(
        "UPDATE parcels SET received_at = clock_timestamp() - interval '25 hours' WHERE id = %s",
        (old["id"],),
    )
    ctx_now = now()
    first = jobs.run_reminders(pw.idh.database, now=ctx_now, societies=[pw.soc.id])
    assert first.reminders == {"h24": 1} and first.failed == {}
    again = jobs.run_reminders(pw.idh.database, now=ctx_now, societies=[pw.soc.id])
    assert again.total == 0, "idempotent: a second run creates nothing"
    pw.sql(
        "UPDATE parcels SET received_at = clock_timestamp() - interval '49 hours' WHERE id = %s",
        (old["id"],),
    )
    second = jobs.run_reminders(pw.idh.database, now=ctx_now, societies=[pw.soc.id])
    assert second.reminders == {"h48": 1}
    assert jobs.run_reminders(pw.idh.database, now=ctx_now, societies=[pw.soc.id]).total == 0
    kinds = pw.rows(
        "SELECT kind FROM parcel_reminders WHERE parcel_id = %s ORDER BY kind", (old["id"],)
    )
    assert kinds == [("h24",), ("h48",)]
    assert pw.rows(
        "SELECT count(*) FROM parcel_reminders WHERE parcel_id = %s", (fresh["id"],)
    ) == [(0,)]
    events = pw.outbox("ParcelReminderDue")
    assert len(events) == 2 and {e["payload"]["kind"] for e in events} == {"h24", "h48"}
    assert all("unit_id" in e["payload"] and "parcel_id" in e["payload"] for e in events)


def test_the_injectable_clock_decides_and_collected_parcels_get_no_reminder(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.stored_parcel(h.unit)
    assert jobs.run_reminders(pw.idh.database, now=now(), societies=[pw.soc.id]).total == 0
    future = now() + timedelta(hours=30)
    assert jobs.run_reminders(pw.idh.database, now=future, societies=[pw.soc.id]).reminders == {
        "h24": 1
    }
    q = pw.stored_parcel(h.unit, "Other")
    _, token = pw.issue_token(h.owner, q)
    assert (
        pw.call(
            pw.guard, "POST", f"/v1/parcels/{q['id']}/collect", json=pw.collect_body(token)
        ).status_code
        == 200
    )
    far = now() + timedelta(hours=60)
    out = jobs.run_reminders(pw.idh.database, now=far, societies=[pw.soc.id])
    assert out.reminders == {"h48": 1}
    assert pw.rows("SELECT count(*) FROM parcel_reminders WHERE parcel_id = %s", (q["id"],)) == [
        (0,)
    ]
    assert p["id"]


def test_reminders_run_as_dramatiq_actors_on_the_stub_broker_and_a_duplicate_message_is_harmless(
    pw: PW,
) -> None:
    h = pw.household("A-101")
    old = pw.stored_parcel(h.unit)
    pw.sql(
        "UPDATE parcels SET received_at = clock_timestamp() - interval '50 hours' WHERE id = %s",
        (old["id"],),
    )
    broker = make_stub_broker()
    results: dict[str, object] = {}
    actor = jobs.build_parcel_actors(broker, pw.idh.database, queue="parcels-test", results=results)
    worker = Worker(broker, worker_timeout=100)
    worker.start()
    try:
        actor.send()
        actor.send()  # duplicated or replayed message
        broker.join("parcels-test")
        worker.join()
    finally:
        worker.stop()
        broker.close()
    assert pw.rows(
        "SELECT kind FROM parcel_reminders WHERE parcel_id = %s ORDER BY kind", (old["id"],)
    ) == [("h24",), ("h48",)]
    assert len(pw.outbox("ParcelReminderDue")) == 2


# REQ: PAR-05
def test_the_custody_report_reconciles_the_physical_count_and_never_auto_resolves(pw: PW) -> None:
    h = pw.household("A-101")
    a = pw.stored_parcel(h.unit, "A")
    pw.store(pw.receive(h.unit, "B"), "B-08")
    pw.receive(h.unit, "C")
    body = {"physical_count": 3, "bin_counts": {"B-07": 1, "B-08": 1}, "gate_id": str(pw.gate_id)}
    ok = pw.call(pw.guard, "POST", "/v1/parcel-custody-reports", json=body)
    assert ok.status_code == 201
    assert (
        ok.json()["system_count"] == 3
        and ok.json()["discrepancy"] == 0
        and ok.json()["status"] == "reconciled"
    )
    short = pw.call(
        pw.guard,
        "POST",
        "/v1/parcel-custody-reports",
        json={"physical_count": 2, "bin_counts": {"B-07": 0, "B-08": 1}},
    )
    assert short.json()["discrepancy"] == -1 and short.json()["status"] == "physical_short"
    assert short.json()["details"]["bin_discrepancies"]["B-07"] == {"system": 1, "physical": 0}
    over = pw.call(pw.guard, "POST", "/v1/parcel-custody-reports", json={"physical_count": 5})
    assert over.json()["discrepancy"] == 2 and over.json()["status"] == "physical_over"
    assert pw.rows("SELECT state FROM parcels WHERE id = %s", (a["id"],)) == [("stored",)], (
        "a shortfall marks nothing lost"
    )
    listed = pw.call(pw.guard_sup, "GET", "/v1/parcel-custody-reports").json()
    assert [i["discrepancy"] for i in listed["items"]] == [2, -1, 0]
    assert pw.call(h.owner, "GET", "/v1/parcel-custody-reports").status_code == 403
    assert pw.call(h.owner, "POST", "/v1/parcel-custody-reports", json=body).status_code == 403


def test_the_custody_list_counts_only_what_the_society_holds(pw: PW) -> None:
    h = pw.household("A-101")
    pw.expect(h.owner, h.unit, "NotYet")  # expected: not in custody
    q = pw.stored_parcel(h.unit)
    _, token = pw.issue_token(h.owner, q)
    pw.call(
        pw.guard, "POST", f"/v1/parcels/{q['id']}/collect", json=pw.collect_body(token)
    )  # collected: not in custody
    held = pw.receive(h.unit, "Held")
    r = pw.call(pw.guard, "POST", "/v1/parcel-custody-reports", json={"physical_count": 1})
    assert r.json()["system_count"] == 1 and r.json()["details"]["system_parcel_ids"] == [
        held["id"]
    ]
