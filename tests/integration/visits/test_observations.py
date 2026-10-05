"""Observations (INV-07, GATE-05, GATE-07 egress): entry and exit are recorded facts that never create permission;
exit time is never manufactured; events are deduplicated; devices must be active; overstay and permission expiry sweeps.

REQ: INV-07, GATE-05, GATE-07, GATE-11, GATE-04.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest

from dwaar_api.core.db import RequestContext
from dwaar_api.modules.visits import policy as policy_mod
from dwaar_api.modules.visits import visits as visits_svc
from tests.integration.visits._support import VW, new_key

pytestmark = [pytest.mark.req("INV-07", "GATE-05")]


@pytest.fixture
def gate(vw: VW) -> VW:
    vw.setup_gate()
    return vw


def authorised(vw: VW, unit_label: str = "A-101", **extra: Any) -> tuple[str, Any]:
    h = vw.household(unit_label)
    req = vw.raise_request(h.unit, **extra)
    assert vw.decide(h.owner, req).status_code == 200
    return str(req["visit_id"]), h


def _iso(delta: dt.timedelta) -> str:
    return (dt.datetime.now(dt.UTC) + delta).isoformat()


def test_entry_is_a_separate_observed_fact_after_authorisation(gate: VW) -> None:
    visit_id, h = authorised(gate)
    before = gate.call(
        gate.guard, "GET", f"/v1/visits/{visit_id}", params={"gate_id": str(gate.gate_id)}
    ).json()
    assert (
        before["state"] == "authorised"
        and before["entry_observed"] is False
        and before["entered_at"] is None
    )
    r = gate.observe(
        visit_id,
        "entry",
        credential_kind="guard_assisted",
        decision_source="resident_app",
        policy_version=7,
    )
    assert r.status_code == 201, r.text
    out = r.json()
    assert (
        out["accepted"]
        and out["deduplicated"] is False
        and out["state_changed"]
        and out["permission_created"] is False
    )
    assert out["visit"]["state"] == "inside" and out["visit"]["entry_observed"] is True
    assert out["visit"]["inside_confidence"] == "observed" and out["visit"]["entered_at"]
    assert out["event"]["type"] == "EntryObserved" and out["event"]["payload_hash"].startswith(
        "sha256:"
    )
    ev = gate.rows(
        "SELECT event_type, gate_id, device_id, seq, decision_source, policy_version, recorded_by FROM access_events"
    )
    assert ev == [
        ("EntryObserved", gate.gate_id, gate.device_id, 1, "resident_app", 7, gate.guard.id)
    ]
    assert len(gate.outbox("EntryObserved")) == 1 and len(gate.audit("visit.entry_observed")) == 1
    # the approval's canonical state now tells the truth about entry
    request_id = gate.rows("SELECT id FROM approval_requests")[0][0]
    seen = gate.call(h.owner, "GET", f"/v1/approval-requests/{request_id}").json()
    assert seen["status"] == "approved" and seen["entry_observed"] is True


def test_an_observation_never_creates_permission(gate: VW) -> None:
    """Entry observed for a visit that nobody authorised: the fact is recorded, the visit is NOT authorised, a supervisor is told."""
    h = gate.household("A-101")
    pending = gate.raise_request(h.unit)
    r = gate.observe(
        pending["visit_id"], "entry"
    )  # tailgated through while the request was still pending
    assert r.status_code == 201
    out = r.json()
    assert (
        out["state_changed"] is False and out["permission_created"] is False and out["exception_id"]
    )
    assert out["visit"]["state"] == "requested" and out["visit"]["entry_observed"] is True
    assert gate.rows("SELECT state, authorised_at, authorised_until, entered_at FROM visits") == [
        ("requested", None, None, None)
    ]
    exc = gate.rows(
        "SELECT kind, state, entry_happened, raised_by_system, actor_id, reason FROM exceptions"
    )
    assert (
        exc[0][:3] == ("unauthorised_entry", "open", True)
        and exc[0][4] == gate.guard.id
        and exc[0][5]
    )
    # the request is still pending and a LATER approval is a normal decision: the observation did not decide anything
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "pending"
    # a denied visit, an expired one and a cancelled one stay exactly as they are
    denied = gate.raise_request(h.unit, visitor_alias="Denied")
    gate.decide(h.owner, denied, "deny")
    r2 = gate.observe(denied["visit_id"], "entry")
    assert r2.json()["visit"]["state"] == "cancelled" and r2.json()["state_changed"] is False
    assert gate.rows("SELECT count(*) FROM exceptions WHERE kind = 'unauthorised_entry'")[0][0] == 2
    assert (
        gate.rows("SELECT count(*) FROM approval_decisions WHERE valid")[0][0] == 1
    )  # only the denial exists


def test_entry_after_the_permission_window_is_an_exception_unless_the_clock_uncertainty_covers_it(
    gate: VW,
) -> None:
    visit_id, _h = authorised(gate)
    gate.sql(
        "UPDATE visits SET authorised_until = now() - interval '2 minutes' WHERE id = %s",
        (visit_id,),
    )
    late = gate.observe(visit_id, "entry", occurred_at=_iso(dt.timedelta(0)))
    assert (
        late.json()["state_changed"] is False
        and late.json()["outcome"] == "entry_without_authorisation"
    )
    assert gate.rows("SELECT state FROM visits WHERE id = %s", (visit_id,))[0][0] == "authorised"
    assert "permission_expired" in gate.rows("SELECT reason FROM exceptions")[0][0]
    # the edge clock says 30 s late with 5 minutes of uncertainty: the entry was inside the window
    visit2, _ = authorised(gate, "A-102")
    gate.sql(
        "UPDATE visits SET authorised_until = now() - interval '30 seconds' WHERE id = %s",
        (visit2,),
    )
    ok = gate.observe(visit2, "entry", clock_uncertainty_ms=300_000)
    assert ok.json()["state_changed"] is True and ok.json()["visit"]["state"] == "inside"


def test_exit_scanned_or_observed_records_the_observed_time(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    gate.observe(visit_id, "entry")
    when = _iso(dt.timedelta(seconds=1))
    r = gate.observe(
        visit_id,
        "exit",
        exit_basis="scanned",
        occurred_at=when,
        credential_kind="qr",
        decision_source="cached_policy",
    )
    assert r.status_code == 201, r.text
    visit = r.json()["visit"]
    assert visit["state"] == "exited" and visit["exit_basis"] == "scanned" and visit["exited_at"]
    assert visit["inside_confidence"] == "none" and r.json()["exception_id"] is None
    assert dt.datetime.fromisoformat(visit["exited_at"]) == dt.datetime.fromisoformat(when)


@pytest.mark.req("GATE-05")
def test_an_exit_reconciled_as_unknown_never_gets_an_exit_time(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    gate.observe(visit_id, "entry")
    r = gate.observe(visit_id, "exit", exit_basis="reconciled_unknown")
    assert r.status_code == 201, r.text
    visit = r.json()["visit"]
    assert visit["state"] == "exited" and visit["exit_basis"] == "reconciled_unknown"
    assert visit["exited_at"] is None  # we do not know when: no time is invented
    assert visit["exit_reconciled_at"] and visit["inside_confidence"] == "unknown"
    row = gate.rows(
        "SELECT exited_at, exit_reconciled_at, exit_basis, confidence_inside FROM visits"
    )[0]
    assert row[0] is None and row[1] is not None and row[2:] == ("reconciled_unknown", "unknown")
    exc = gate.rows("SELECT kind, state, entry_happened FROM exceptions")
    assert exc == [
        ("exit_unknown", "open", True)
    ]  # a supervisor can see that an exit was never really observed


def test_exit_rules_basis_is_required_and_only_for_exits(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    gate.observe(visit_id, "entry")
    r = gate.call(
        gate.guard, "POST", f"/v1/visits/{visit_id}/observations",
        json={"type": "exit", "gate_id": str(gate.gate_id), "device_id": str(gate.device_id), "event_id": str(uuid.uuid4()),
              "seq": 50, "occurred_at": _iso(dt.timedelta(0))},
    )  # fmt: skip
    assert r.status_code == 400 and r.json()["details"]["fields"][0]["issue"] == "required_for_exit"
    bad = gate.observe(visit_id, "entry", exit_basis="scanned")
    assert bad.status_code == 400
    assert gate.rows("SELECT count(*) FROM access_events")[0][0] == 1


@pytest.mark.req("GATE-07", "GATE-05")
def test_egress_is_never_gated_an_exit_is_recorded_for_any_visit(gate: VW) -> None:
    """Essential egress does not depend on authorisation, on the household, or on anything about money (GATE-07)."""
    h = gate.household("A-101")
    cancelled = gate.raise_request(h.unit)
    gate.decide(h.owner, cancelled, "deny")
    r = gate.observe(cancelled["visit_id"], "exit", exit_basis="observed")
    assert r.status_code == 201 and r.json()["visit"]["state"] == "cancelled"
    assert r.json()["state_changed"] is False and r.json()["exception_id"]
    visit_id, _ = authorised(gate, "A-102")
    never_seen_entering = gate.observe(visit_id, "exit", exit_basis="observed")
    assert (
        never_seen_entering.status_code == 201
        and never_seen_entering.json()["visit"]["state"] == "exited"
    )
    assert never_seen_entering.json()["outcome"] == "exit_without_observed_entry"
    kinds = {r[0] for r in gate.rows("SELECT kind FROM exceptions")}
    assert kinds == {"exit_without_entry"}
    # an exit twice is recorded as a duplicate fact, not a second state change
    again = gate.observe(visit_id, "exit", exit_basis="observed")
    assert (
        again.status_code == 201
        and again.json()["state_changed"] is False
        and again.json()["outcome"] == "duplicate_exit"
    )


def test_the_same_event_is_deduplicated_and_changed_content_is_flagged(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    event = uuid.uuid4()
    fixed = _iso(dt.timedelta(0))
    first = gate.observe(visit_id, "entry", event_id=event, seq=3, occurred_at=fixed)
    again = gate.observe(visit_id, "entry", event_id=event, seq=3, occurred_at=fixed)
    assert first.status_code == again.status_code == 201
    assert first.json()["deduplicated"] is False and again.json()["deduplicated"] is True
    assert again.json()["event"]["id"] == first.json()["event"]["id"]
    assert (
        gate.rows("SELECT count(*) FROM access_events")[0][0] == 1
        and len(gate.outbox("EntryObserved")) == 1
    )
    changed = gate.observe(
        visit_id, "entry", event_id=event, seq=3, occurred_at=fixed, clock_uncertainty_ms=999
    )
    assert changed.status_code == 409 and changed.json()["code"] == "duplicate_payload_mismatch"
    clash = gate.observe(
        visit_id, "entry", seq=3
    )  # the device sequence 3 is taken by ANOTHER event
    assert clash.status_code == 409 and clash.json()["code"] == "stale_version"
    assert gate.rows("SELECT count(*) FROM access_events")[0][0] == 1
    dup_entry = gate.observe(
        visit_id, "entry", seq=4
    )  # a second entry of an inside visit: a recorded duplicate
    assert (
        dup_entry.json()["outcome"] == "duplicate_entry"
        and dup_entry.json()["state_changed"] is False
    )


def test_replay_with_one_idempotency_key_returns_the_same_event(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    body = {
        "type": "entry", "gate_id": str(gate.gate_id), "device_id": str(gate.device_id), "event_id": str(uuid.uuid4()),
        "seq": 9, "occurred_at": _iso(dt.timedelta(0)),
    }  # fmt: skip
    a = gate.call(
        gate.guard, "POST", f"/v1/visits/{visit_id}/observations", json=body, key="obs-key-000001"
    )
    b = gate.call(
        gate.guard, "POST", f"/v1/visits/{visit_id}/observations", json=body, key="obs-key-000001"
    )
    assert a.status_code == b.status_code == 201 and b.headers["Idempotent-Replayed"] == "true"
    assert a.json()["event"]["id"] == b.json()["event"]["id"]
    assert gate.rows("SELECT count(*) FROM access_events")[0][0] == 1


def test_devices_must_be_active_and_at_their_gate_and_lanes_must_match(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    other_gate = gate.make_gate("Back gate", "pedestrian")
    # a device that was only REQUESTED is not usable
    r = gate.call(
        gate.guard, "POST", gate.s("devices"),
        json={"kind": "terminal", "name": "Unapproved", "gate_id": str(gate.gate_id), "public_key": new_key()},
    )  # fmt: skip
    pending = r.json()["id"]
    bad = gate.call(
        gate.guard, "POST", f"/v1/visits/{visit_id}/observations",
        json={"type": "entry", "gate_id": str(gate.gate_id), "device_id": pending, "event_id": str(uuid.uuid4()), "seq": 1,
              "occurred_at": _iso(dt.timedelta(0))},
    )  # fmt: skip
    assert (
        bad.status_code == 400
        and bad.json()["details"]["fields"][0]["issue"] == "unknown_or_inactive_device"
    )
    # an unknown device, an unknown gate, a lane of another gate
    for patch, status in (
        ({"device_id": str(uuid.uuid4())}, 400),
        ({"gate_id": str(uuid.uuid4())}, 400),
        ({"gate_id": str(other_gate)}, 422),  # the device is bound to the main gate
    ):
        body = {"type": "entry", "gate_id": str(gate.gate_id), "device_id": str(gate.device_id), "event_id": str(uuid.uuid4()),
                "seq": 2, "occurred_at": _iso(dt.timedelta(0)), **patch}  # fmt: skip
        assert (
            gate.call(
                gate.guard, "POST", f"/v1/visits/{visit_id}/observations", json=body
            ).status_code
            == status
        ), patch
    lane = gate.call(
        gate.secretary,
        "POST",
        gate.s(f"gates/{other_gate}/lanes"),
        json={"label": "Lane 1", "direction": "in"},
    ).json()
    mismatch = gate.observe(visit_id, "entry", lane_id=lane["id"])
    assert (
        mismatch.status_code == 400
        and mismatch.json()["details"]["fields"][0]["issue"] == "unknown_lane"
    )
    # a revoked device stops being usable at once
    dev = gate.call(gate.guard_sup, "GET", gate.s(f"devices/{gate.device_id}")).json()
    assert gate.call(
        gate.guard_sup, "POST", gate.s(f"devices/{gate.device_id}/revoke"),
        json={"expected_version": dev["version"], "reason": "Terminal reported lost"},
    ).status_code == 200  # fmt: skip
    assert gate.observe(visit_id, "entry").status_code == 400
    assert gate.rows("SELECT count(*) FROM access_events")[0][0] == 0


def test_who_may_record_observations(gate: VW) -> None:
    visit_id, h = authorised(gate)
    for who in (h.owner, gate.secretary):
        assert gate.observe(visit_id, "entry", who=who).status_code == 403
    assert gate.observe(visit_id, "entry", who=gate.person()).status_code == 404
    assert gate.observe(uuid.uuid4(), "entry").status_code == 404
    assert gate.observe(visit_id, "entry", who=gate.guard_sup).status_code == 201
    r = gate.call(
        gate.guard,
        "POST",
        f"/v1/visits/{visit_id}/observations",
        json={"type": "entry"},
        society=uuid.uuid4(),
    )
    assert r.status_code == 404


# ------------------------------------------------------------------------------------------ sweeps
def _sweep(vw: VW, **kwargs: Any) -> Any:
    ctx = RequestContext(vw.soc.id, None, "system", uuid.uuid4())
    with vw.idh.database.app_tx(ctx) as conn:
        policy = policy_mod.load_policy(conn)
        return visits_svc.sweep(conn, ctx, policy, **kwargs)


@pytest.mark.req("GATE-11")
def test_delivery_overstay_after_20_minutes_opens_one_exception_and_marks_the_count_stale(
    gate: VW,
) -> None:
    delivery, _h = authorised(gate, "A-101", kind="delivery")
    service, _ = authorised(gate, "A-102", kind="service")
    guest, _ = authorised(gate, "B-201", kind="guest")
    for v in (delivery, service, guest):
        gate.observe(v, "entry")
    gate.sql("UPDATE visits SET entered_at = now() - interval '15 minutes'")
    assert _sweep(gate).overstays_opened == 0  # inside every threshold
    gate.sql("UPDATE visits SET entered_at = now() - interval '25 minutes'")
    first = _sweep(gate)
    assert (
        first.overstays_opened == 1
    )  # delivery default 20 minutes; service 4 hours and guests are not time-boxed
    assert _sweep(gate).overstays_opened == 0  # idempotent
    exc = gate.rows(
        "SELECT kind, visit_id::text, state, raised_by_system, entry_happened FROM exceptions"
    )
    assert exc == [("overstay", delivery, "open", True, True)]
    states = dict(gate.rows("SELECT id::text, confidence_inside FROM visits"))
    assert (
        states[delivery] == "stale"
        and states[service] == "observed"
        and states[guest] == "observed"
    )
    assert len(gate.outbox("ExceptionOpened")) == 1
    gate.sql("UPDATE visits SET entered_at = now() - interval '5 hours'")
    assert _sweep(gate).overstays_opened == 1  # now the service visit (4 h default) overstays too
    # the inside list shows the confidence indicator
    listing = gate.call(
        gate.secretary,
        "GET",
        gate.s("visits"),
        params={"state": "inside", "purpose": "Inside count review"},
    ).json()
    assert {i["id"]: i["inside_confidence"] for i in listing["items"]} == {
        delivery: "stale",
        service: "stale",
        guest: "observed",
    }


@pytest.mark.req("GATE-11")
def test_overstay_thresholds_are_configuration_per_society_and_per_booking(gate: VW) -> None:
    put = gate.call(
        gate.secretary,
        "PUT",
        gate.s("gate-policy"),
        json={"overstay_minutes": {"delivery": 60, "service": 180}},
    )
    assert (
        put.status_code == 200
        and put.json()["overstay_minutes"]["delivery"] == 60
        and put.json()["overstay_minutes"]["cab"] == 15
    )
    for bad in ({"service": 30}, {"service": 600}, {"delivery": 1}, {"guest": 10}):
        r = gate.call(
            gate.secretary,
            "PUT",
            gate.s("gate-policy"),
            json={"overstay_minutes": bad, "expected_version": 1},
        )
        assert r.status_code == 400, bad  # service is 2 to 8 hours (GATE-11)
    d, _ = authorised(gate, "A-101", kind="delivery")
    booked, _ = authorised(gate, "A-102", kind="delivery", expected_minutes=10)
    for v in (d, booked):
        gate.observe(v, "entry")
    gate.sql("UPDATE visits SET entered_at = now() - interval '30 minutes'")
    assert (
        _sweep(gate).overstays_opened == 1
    )  # 30 min < the society's 60, but > the booking's own 10
    assert gate.rows("SELECT visit_id::text FROM exceptions") == [(booked,)]
    r = gate.call(
        gate.guard,
        "POST",
        "/v1/approval-requests",
        json=gate.request_body(gate.unit("B-202"), kind="service", expected_minutes=60),
    )  # a service booking shorter than 2 hours is refused
    assert r.status_code == 400
    assert (
        gate.call(
            gate.guard,
            "POST",
            "/v1/approval-requests",
            json=gate.request_body(gate.unit("B-202"), kind="guest", expected_minutes=30),
        ).status_code
        == 400
    )


def test_the_sweep_expires_unused_permissions_and_passes_and_never_enters_anybody(gate: VW) -> None:
    _visit_id, h = authorised(gate)
    inv = gate.call(
        h.owner, "POST", gate.s("invitations"),
        json={"unit_id": str(h.unit), "purpose": "Dinner", "windows": [{"start": _iso(-dt.timedelta(hours=1)), "end": _iso(dt.timedelta(hours=1))}]},
    ).json()  # fmt: skip
    gate.sql("UPDATE visits SET authorised_until = now() - interval '1 minute'")
    gate.sql("UPDATE invitation_windows SET window_end = now() - interval '1 second'")
    gate.sql("UPDATE invitations SET window_end = now() - interval '1 second'")
    swept = _sweep(gate)
    assert (
        swept.authorisations_expired == 1 and swept.invitations_expired == 1 and swept.total() == 2
    )
    assert gate.rows("SELECT state, closed_reason FROM visits") == [
        ("expired", "permission_expired")
    ]
    assert gate.rows("SELECT authorised, state FROM visit_stops") == [(False, "expired")]
    assert gate.rows("SELECT state FROM invitations WHERE id = %s", (inv["id"],)) == [("expired",)]
    assert _sweep(gate).total() == 0
    assert len(gate.outbox("VisitExpired")) == 1 and len(gate.outbox("InvitationExpired")) == 1


def test_visit_cancel_withdraws_authorisation(gate: VW) -> None:
    visit_id, _h = authorised(gate)
    v = gate.call(
        gate.guard, "GET", f"/v1/visits/{visit_id}", params={"gate_id": str(gate.gate_id)}
    ).json()
    stale = gate.call(
        gate.guard,
        "POST",
        f"/v1/visits/{visit_id}/cancel",
        json={"expected_version": 99, "reason": "Visitor left the gate"},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    ok = gate.call(
        gate.guard,
        "POST",
        f"/v1/visits/{visit_id}/cancel",
        json={"expected_version": v["version"], "reason": "Visitor left the gate"},
    )
    assert ok.status_code == 200 and ok.json()["state"] == "cancelled"
    assert gate.rows("SELECT authorised, state FROM visit_stops") == [(False, "cancelled")]
    assert len(gate.outbox("VisitCancelled")) == 1
    entered = gate.observe(visit_id, "entry")
    assert (
        entered.json()["state_changed"] is False and entered.json()["visit"]["state"] == "cancelled"
    )
    inside_id, _ = authorised(gate, "A-102")
    gate.observe(inside_id, "entry")
    v2 = gate.call(
        gate.guard, "GET", f"/v1/visits/{inside_id}", params={"gate_id": str(gate.gate_id)}
    ).json()
    r = gate.call(
        gate.guard,
        "POST",
        f"/v1/visits/{inside_id}/cancel",
        json={"expected_version": v2["version"], "reason": "Cannot cancel inside"},
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "not_cancellable"
