"""Guard shifts, checklists, handovers, acknowledgement, escalation without locking the kiosk, supervisor override (SHIFT-01, SHIFT-02, INV-08, Appendix C).

REQ: SHIFT-01, SHIFT-02, INV-08, INV-06, GATE-09, GATE-11.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from dwaar_api.modules.shifts import jobs, service
from dwaar_common.errors import InvalidSchema
from tests.integration.parcels._support import PW, iso, now

pytestmark = [pytest.mark.req("SHIFT-01", "SHIFT-02", "INV-08", "INV-06")]


def _start(pw: PW, shift, who=None, checklist=None):  # type: ignore[no-untyped-def]
    return pw.call(
        who or pw.guard,
        "POST",
        f"/v1/shifts/{shift['id']}/start",
        json={"checklist": checklist or {}},
    )


def _end(pw: PW, shift, who=None, **kw):  # type: ignore[no-untyped-def]
    return pw.call(who or pw.guard, "POST", f"/v1/shifts/{shift['id']}/end", json=pw.end_body(**kw))


def _second_guard(pw: PW):  # type: ignore[no-untyped-def]
    g2 = pw.vw.person()
    pw.idh.seed_grant(pw.soc.id, g2.id, "guard")
    return g2


# REQ: SHIFT-01
def test_a_supervisor_schedules_a_shift_for_a_guard_at_a_gate(pw: PW) -> None:
    shift = pw.schedule(pw.guard)
    assert (
        shift["state"] == "scheduled"
        and shift["guard_id"] == str(pw.guard.id)
        and shift["gate_name"] == "Main gate"
    )
    assert pw.audit("shift.schedule") and pw.outbox("ShiftScheduled", shift["id"])
    assert (
        pw.call(
            pw.guard,
            "POST",
            "/v1/shifts",
            json={
                "gate_id": str(pw.gate_id),
                "guard_id": str(pw.guard.id),
                "planned_start": iso(now()),
                "planned_end": iso(now() + timedelta(hours=2)),
            },
        ).status_code
        == 403
    )
    nobody = pw.vw.person()
    r = pw.call(
        pw.guard_sup,
        "POST",
        "/v1/shifts",
        json={
            "gate_id": str(pw.gate_id),
            "guard_id": str(nobody.id),
            "planned_start": iso(now()),
            "planned_end": iso(now() + timedelta(hours=2)),
        },
    )
    assert r.status_code == 404, "a person who holds no guard role cannot be put on a shift"
    clash = pw.call(
        pw.guard_sup,
        "POST",
        "/v1/shifts",
        json={
            "gate_id": str(pw.gate_id),
            "guard_id": str(pw.guard.id),
            "planned_start": iso(now()),
            "planned_end": iso(now() + timedelta(hours=2)),
        },
    )
    assert clash.status_code == 422 and clash.json()["details"]["reason"] == "overlapping_shift"
    bad_gate = pw.call(
        pw.guard_sup,
        "POST",
        "/v1/shifts",
        json={
            "gate_id": str(uuid.uuid4()),
            "guard_id": str(pw.guard.id),
            "planned_start": iso(now() + timedelta(days=2)),
            "planned_end": iso(now() + timedelta(days=2, hours=2)),
        },
    )
    assert bad_gate.status_code == 400
    too_long = pw.call(
        pw.guard_sup,
        "POST",
        "/v1/shifts",
        json={
            "gate_id": str(pw.gate_id),
            "guard_id": str(pw.guard.id),
            "planned_start": iso(now() + timedelta(days=3)),
            "planned_end": iso(now() + timedelta(days=3, hours=30)),
        },
    )
    assert too_long.status_code == 400


# REQ: SHIFT-01
def test_the_start_checklist_records_what_was_reported_and_what_the_server_knows(pw: PW) -> None:
    h = pw.household("A-101")
    pw.vw.raise_request(h.unit)  # a pending visit
    pw.receive(h.unit)  # a parcel in custody
    assert (
        pw.call(
            pw.guard,
            "POST",
            pw.vw.s("exceptions"),
            json={"kind": "other", "reason": "Gate light flickers at night"},
        ).status_code
        == 201
    )
    shift = pw.schedule(pw.guard)
    r = _start(
        pw,
        shift,
        checklist={
            "battery_percent": 82,
            "network": "ok",
            "relay_health": "ok",
            "sensor_health": "unknown",
            "keys_count": 4,
        },
    )
    assert r.status_code == 200, r.text
    items = {i["key"]: i for i in r.json()["start_checklist"]["items"]}
    assert set(items) == {
        "battery",
        "network",
        "policy_age",
        "relay_health",
        "sensor_health",
        "pending_visits",
        "unresolved_incidents",
        "parcels_in_custody",
        "keys",
    }
    assert items["battery"] == {"key": "battery", "status": "ok", "value": 82, "source": "terminal"}
    assert (
        items["pending_visits"]["value"] == 1
        and items["pending_visits"]["status"] == "attention"
        and items["pending_visits"]["source"] == "server"
    )
    assert items["unresolved_incidents"]["value"] == 1 and items["parcels_in_custody"]["value"] == 1
    assert items["sensor_health"]["status"] == "attention", "a reported 'unknown' is not ok"
    assert items["policy_age"]["source"] in (
        "not_available",
        "latest_published_snapshot",
        "edge_status",
    )
    assert r.json()["state"] == "active" and r.json()["started_at"]
    assert (
        pw.audit("shift.start")
        and pw.outbox("ShiftStarted", shift["id"])[0]["payload"]["attention_items"] >= 2
    )


def test_what_the_terminal_did_not_report_is_not_reported_never_invented(pw: PW) -> None:
    shift = pw.schedule(pw.guard)
    items = {i["key"]: i for i in _start(pw, shift).json()["start_checklist"]["items"]}
    for key in ("battery", "network", "relay_health", "sensor_health", "keys"):
        assert (
            items[key]["status"] == "not_reported"
            and items[key]["value"] is None
            and items[key]["source"] == "placeholder"
        ), key


# REQ: INV-08
def test_a_bad_start_checklist_never_blocks_the_start(pw: PW) -> None:
    shift = pw.schedule(pw.guard)
    r = _start(
        pw, shift, checklist={"battery_percent": 3, "network": "offline", "relay_health": "fault"}
    )
    assert r.status_code == 200 and r.json()["state"] == "active"
    statuses = {i["key"]: i["status"] for i in r.json()["start_checklist"]["items"]}
    assert statuses["battery"] == statuses["network"] == statuses["relay_health"] == "attention"
    assert _start(pw, shift).status_code == 200, "starting twice is idempotent"
    assert pw.rows("SELECT count(*) FROM shift_checklists WHERE kind = 'start'")[0][0] == 1


def test_a_guard_starts_only_their_own_shift_and_only_one_shift_at_a_time(pw: PW) -> None:
    g2 = _second_guard(pw)
    mine = pw.schedule(pw.guard)
    theirs = pw.schedule(g2, start=now() - timedelta(minutes=5))
    assert _start(pw, theirs, who=pw.guard).status_code == 404, "not your shift"
    assert _start(pw, theirs, who=pw.guard_sup).status_code == 200, (
        "a supervisor may start it for the guard"
    )
    assert _start(pw, mine).status_code == 200
    later = pw.schedule(pw.guard, start=now() + timedelta(hours=9))
    busy = _start(pw, later)
    assert busy.status_code == 422 and busy.json()["details"]["reason"] == "guard_already_on_shift"


def test_the_shift_context_gives_the_guard_home_numbers(pw: PW) -> None:
    h = pw.household("A-101")
    assert pw.call(pw.guard, "GET", "/v1/shifts/current").json() == {"shift": None, "context": None}
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    pw.vw.raise_request(h.unit)
    pw.receive(h.unit)
    ctx = pw.call(pw.guard, "GET", "/v1/shifts/current").json()
    assert ctx["shift"]["id"] == shift["id"]
    assert ctx["context"]["pending_queue"] == 1 and ctx["context"]["parcels_in_custody"] == 1
    assert ctx["context"]["inside_records"] == 0 and ctx["context"]["guard_language"] == "en"
    assert set(ctx["context"]) >= {"overstay_alerts", "unresolved_incidents", "active_overrides"}


# REQ: SHIFT-01
def test_the_end_checklist_counts_parcels_and_unresolved_inside_records(pw: PW) -> None:
    h = pw.household("A-101")
    pw.receive(h.unit, "A")
    pw.receive(h.unit, "B")
    request, _decision = pw.vw.approved_visit(h.unit, h.owner)
    entry = pw.vw.observe(request["visit_id"], "entry")
    assert entry.status_code == 201, entry.text
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    ended = _end(
        pw, shift, parcels=1, reviewed=False
    )  # the guard counted 1, the system holds 2; inside record not reviewed
    assert ended.status_code == 200, ended.text
    items = {i["key"]: i for i in ended.json()["end_checklist"]["items"]}
    assert (
        items["parcels"]["value"] == 2
        and items["parcels"]["counted_by_guard"] == 1
        and items["parcels"]["difference"] == -1
    )
    assert items["parcels"]["status"] == "attention"
    assert (
        items["inside_records"]["value"] == 1
        and items["inside_records"]["status"] == "attention"
        and items["inside_records"]["reviewed_by_guard"] is False
    )
    assert ended.json()["state"] == "ended" and ended.json()["ended_at"]
    kinds = [i["kind"] for i in ended.json()["handover"]["open_items"]]
    assert kinds.count("parcel_in_custody") == 2 and kinds.count("visit_inside") == 1


def test_ending_twice_returns_the_same_handover_and_creates_one(pw: PW) -> None:
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    a = _end(pw, shift)
    b = _end(pw, shift)
    assert (
        a.status_code == b.status_code == 200
        and a.json()["handover"]["id"] == b.json()["handover"]["id"]
    )
    assert pw.rows("SELECT count(*) FROM shift_handovers")[0][0] == 1
    assert (
        pw.call(
            pw.guard, "POST", f"/v1/shifts/{shift['id']}/start", json={"checklist": {}}
        ).status_code
        == 422
    ), "an ended shift cannot restart"
    not_started = pw.schedule(pw.guard, start=now() + timedelta(days=1))
    assert _end(pw, not_started).status_code == 422


# REQ: SHIFT-02
def test_the_open_items_are_deterministic_complete_and_the_same_for_the_same_state(pw: PW) -> None:
    h = pw.household("A-101")
    for b in ("A", "B", "C"):
        pw.receive(h.unit, b)
    pw.vw.raise_request(h.unit)
    with pw.idh.database.app_tx(
        __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
            pw.soc.id, None, "system", None
        )
    ) as conn:
        first = service.open_items(conn, pw.gate_id)
        second = service.open_items(conn, pw.gate_id)
    assert first == second
    kinds = [i["kind"] for i in first["items"]]
    order = [
        "incident_unresolved",
        "visit_pending_decision",
        "visit_inside",
        "parcel_in_custody",
        "override_active",
    ]
    assert kinds == sorted(kinds, key=order.index), "grouped by kind in a fixed order"
    parcel_ids = [i["ref_id"] for i in first["items"] if i["kind"] == "parcel_in_custody"]
    assert parcel_ids == sorted(parcel_ids), "then by id"
    assert (
        first["counts"]["parcel_in_custody"] == {"total": 3, "listed": 3, "truncated": False}
        and first["complete"] is True
    )
    assert all(i["message_key"] == f"shifts.item.{i['kind']}" for i in first["items"])


def test_a_list_cut_at_the_cap_says_so(pw: PW) -> None:
    from dwaar_api.modules.shifts.config import ShiftsConfig

    h = pw.household("A-101")
    for b in ("A", "B", "C"):
        pw.receive(h.unit, b)
    with pw.idh.database.app_tx(
        __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
            pw.soc.id, None, "system", None
        )
    ) as conn:
        cut = service.open_items(conn, pw.gate_id, ShiftsConfig(max_items_per_kind=2))
    assert (
        cut["counts"]["parcel_in_custody"] == {"total": 3, "listed": 2, "truncated": True}
        and cut["complete"] is False
    )


# REQ: SHIFT-02, INV-06
def test_the_summary_is_advisory_shown_above_the_open_items_and_never_replaces_them(pw: PW) -> None:
    h = pw.household("A-101")
    pw.receive(h.unit)
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    calls: list[tuple[int, str]] = []

    def provider(items, language):  # type: ignore[no-untyped-def]
        calls.append((len(items), language))
        return "One parcel is waiting at the gate."  # a (simulated) AI-G08 summary

    service.set_summary_provider(provider)
    try:
        ended = _end(pw, shift, parcels=1).json()
    finally:
        service.set_summary_provider(None)
    handover = ended["handover"]
    assert calls == [(1, "en")]
    assert handover["summary"] == {
        "text": "One parcel is waiting at the gate.",
        "source": "ai_gateway",
        "language": "en",
        "advisory": True,
    }
    assert handover["display_order"] == ["summary", "open_items"]
    keys = list(handover)
    assert keys.index("summary") < keys.index("open_items"), (
        "the summary comes first in the payload too"
    )
    assert (
        len(handover["open_items"]) == 1
        and handover["open_items"][0]["kind"] == "parcel_in_custody"
    )
    # a summary that says nothing about an item does not remove the item
    stored = pw.rows("SELECT jsonb_array_length(open_items), summary_source FROM shift_handovers")[
        0
    ]
    assert stored == (1, "ai_gateway")


def test_with_no_summary_the_list_is_the_whole_handover_and_a_failing_provider_blocks_nothing(
    pw: PW,
) -> None:
    h = pw.household("A-101")
    pw.receive(h.unit)
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    assert service._summary_provider is None  # noqa: SLF001 (no model is ever wired in by this module)

    def broken(items, language):  # type: ignore[no-untyped-def]
        raise RuntimeError("model unavailable")

    service.set_summary_provider(broken)
    try:
        handover = _end(pw, shift, parcels=1).json()["handover"]
    finally:
        service.set_summary_provider(None)
    assert (
        "summary" not in handover
        and handover["display_order"] == ["open_items"]
        and len(handover["open_items"]) == 1
    )


def test_the_summary_hook_attaches_text_in_the_incoming_guards_language(pw: PW) -> None:
    g2 = _second_guard(pw)
    assert (
        pw.call(g2, "PUT", f"/v1/guards/{g2.id}/profile", json={"language": "mr"}).status_code
        == 200
    )
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    second = pw.schedule(g2, start=now() - timedelta(minutes=1))
    _start(pw, second, who=g2)
    handover = _end(pw, shift).json()["handover"]
    assert handover["incoming_guard"] == str(g2.id), (
        "the guard already on shift at the gate is the incoming guard"
    )
    from dwaar_api.core.db import RequestContext

    ctx = RequestContext(pw.soc.id, pw.guard_sup.id, "guard_sup", uuid.uuid4())
    with pw.idh.database.app_tx(ctx) as conn:
        attached = service.attach_summary(
            conn, ctx, uuid.UUID(handover["id"]), "Ek parcel gate var aahe.", source="ai_gateway"
        )
    assert attached["summary"]["language"] == "mr" and attached["display_order"] == [
        "summary",
        "open_items",
    ]
    with pytest.raises(InvalidSchema), pw.idh.database.app_tx(ctx) as conn:
        service.attach_summary(conn, ctx, uuid.UUID(handover["id"]), "x", source="model_direct")


# REQ: SHIFT-01
def test_both_guards_or_the_supervisor_acknowledge(pw: PW) -> None:
    g2 = _second_guard(pw)
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    nxt = pw.schedule(g2, start=now() - timedelta(minutes=1))
    _start(pw, nxt, who=g2)
    h = _end(pw, shift).json()["handover"]
    path = f"/v1/handovers/{h['id']}/acknowledge"
    out = pw.call(pw.guard, "POST", path, json={})
    assert (
        out.status_code == 200
        and out.json()["state"] == "pending"
        and out.json()["acknowledgements"]["outgoing_at"]
    )
    assert out.json()["acknowledgements"]["signed_at"] is None, "one guard is not enough"
    again = pw.call(pw.guard, "POST", path, json={})
    assert again.status_code == 200 and again.json()["version"] == out.json()["version"], (
        "idempotent"
    )
    inc = pw.call(g2, "POST", path, json={})
    assert (
        inc.status_code == 200
        and inc.json()["state"] == "acknowledged"
        and inc.json()["acknowledgements"]["signed_at"]
    )
    assert len(pw.outbox("HandoverSigned")) == 1 and len(pw.outbox("HandoverAcknowledged")) == 1


def test_the_supervisor_alone_signs_and_an_uninvolved_guard_gets_404(pw: PW) -> None:
    g3 = _second_guard(pw)
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    h = _end(pw, shift).json()["handover"]
    path = f"/v1/handovers/{h['id']}/acknowledge"
    assert pw.call(g3, "POST", path, json={}).status_code == 404
    assert pw.call(g3, "GET", f"/v1/handovers/{h['id']}").status_code == 404
    signed = pw.call(pw.guard_sup, "POST", path, json={})
    assert signed.status_code == 200 and signed.json()["state"] == "acknowledged"
    assert (
        signed.json()["acknowledgements"]["supervisor_at"]
        and signed.json()["acknowledgements"]["incoming_at"] is None
    )
    assert pw.rows("SELECT supervisor_ack_by FROM shift_handovers")[0][0] == pw.guard_sup.id
    assert pw.call(pw.secretary, "GET", f"/v1/handovers/{h['id']}").status_code == 200
    stale = pw.call(pw.guard, "POST", path, json={"expected_version": 1})
    assert stale.status_code in (200, 409)


def test_the_database_refuses_an_acknowledged_handover_without_both_guards_or_the_supervisor(
    pw: PW,
) -> None:
    import psycopg

    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    _end(pw, shift)
    with pytest.raises(psycopg.errors.CheckViolation), pw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(pw.soc.id),))
        conn.execute(
            "UPDATE shift_handovers SET state = 'acknowledged', signed_at = now(), outgoing_ack_at = now()"
        )  # type: ignore[call-overload]


def test_a_guard_starting_at_the_gate_becomes_the_incoming_guard_of_an_open_handover(
    pw: PW,
) -> None:
    g2 = _second_guard(pw)
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    h = _end(pw, shift).json()["handover"]
    assert h["incoming_guard"] is None and h["state"] == "pending"
    nxt = pw.schedule(g2, start=now())
    started = _start(pw, nxt, who=g2).json()
    assert started["incoming_handover"]["id"] == h["id"] and started["incoming_handover"][
        "incoming_guard"
    ] == str(g2.id)
    assert pw.call(g2, "GET", f"/v1/handovers/{h['id']}").status_code == 200
    assert pw.outbox("HandoverIncomingLinked")


# REQ: SHIFT-01, INV-08
def test_a_missing_next_guard_escalates_and_never_locks_the_gate(pw: PW) -> None:
    h = pw.household("A-101")
    request, _ = pw.vw.approved_visit(h.unit, h.owner)
    assert pw.vw.observe(request["visit_id"], "entry").status_code == 201
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    handover = _end(pw, shift, parcels=0).json()["handover"]
    assert handover["state"] == "pending" and handover["incoming_guard"] is None
    # nobody is on shift any more. The pending handover escalates after the deadline ...
    early = jobs.run_sweep(pw.idh.database, now=now() + timedelta(minutes=5), societies=[pw.soc.id])
    assert early.escalated == 0
    late = jobs.run_sweep(pw.idh.database, now=now() + timedelta(minutes=20), societies=[pw.soc.id])
    assert late.escalated == 1 and late.failed == {}
    assert (
        jobs.run_sweep(
            pw.idh.database, now=now() + timedelta(minutes=40), societies=[pw.soc.id]
        ).escalated
        == 0
    ), "escalated once"
    got = pw.call(pw.secretary, "GET", f"/v1/handovers/{handover['id']}").json()
    assert (
        got["state"] == "escalated"
        and got["escalation_reason"] == "no_incoming_guard"
        and got["escalated_at"]
    )
    ev = pw.outbox("HandoverEscalated", handover["id"])
    assert (
        len(ev) == 1
        and ev[0]["payload"]["reason"] == "no_incoming_guard"
        and ev[0]["payload"]["open_item_count"] >= 1
    )
    # ... and NOTHING at the gate is locked: egress (the exit of the person inside), new requests, parcels, device state
    exit_ = pw.vw.observe(request["visit_id"], "exit")
    assert exit_.status_code == 201, "essential egress is never blocked (INV-08)"
    other = pw.household("A-102")
    assert (
        pw.vw.call(
            pw.guard, "POST", "/v1/approval-requests", json=pw.vw.request_body(other.unit)
        ).status_code
        == 201
    )
    assert pw.receive(other.unit)["state"] == "received_at_gate"
    assert pw.rows("SELECT state FROM devices WHERE id = %s", (pw.vw.device_id,))[0][0] == "active"
    # the supervisor can still sign an escalated handover
    signed = pw.call(pw.guard_sup, "POST", f"/v1/handovers/{handover['id']}/acknowledge", json={})
    assert signed.status_code == 200 and signed.json()["state"] == "acknowledged"


def test_nothing_in_the_gate_path_reads_the_shift_tables(pw: PW) -> None:
    """INV-08 by construction: the visits and edge modules never import or query anything of the shifts module."""
    import pathlib

    root = (
        pathlib.Path(__file__).resolve().parents[3] / "services" / "api" / "dwaar_api" / "modules"
    )
    offenders = []
    for module in ("visits", "edge"):
        for path in (root / module).rglob("*.py"):
            text = path.read_text()
            if any(
                w in text
                for w in (
                    "shift_handovers",
                    "shift_overrides",
                    "guard_profiles",
                    "modules.shifts",
                    "..shifts",
                )
            ):
                offenders.append(str(path))
    assert offenders == []


def test_an_acknowledgement_overdue_with_an_incoming_guard_escalates_with_its_own_reason(
    pw: PW,
) -> None:
    g2 = _second_guard(pw)
    shift = pw.schedule(pw.guard)
    _start(pw, shift)
    nxt = pw.schedule(g2, start=now() - timedelta(minutes=1))
    _start(pw, nxt, who=g2)
    h = _end(pw, shift).json()["handover"]
    assert (
        jobs.run_sweep(
            pw.idh.database, now=now() + timedelta(minutes=30), societies=[pw.soc.id]
        ).escalated
        == 1
    )
    assert (
        pw.call(pw.secretary, "GET", f"/v1/handovers/{h['id']}").json()["escalation_reason"]
        == "acknowledgement_overdue"
    )


# REQ: Appendix C
def test_a_supervisor_override_expires_at_shift_end_at_the_latest(pw: PW) -> None:
    shift = pw.schedule(pw.guard, hours=2)
    _start(pw, shift)
    planned_end = now() + timedelta(hours=2) - timedelta(minutes=5)
    r = pw.call(
        pw.guard_sup,
        "POST",
        f"/v1/shifts/{shift['id']}/overrides",
        json={"reason": "Fire drill: lift the visitor checks", "minutes": 600},
    )
    assert r.status_code == 201, r.text
    until = r.json()["valid_until"]
    assert (
        until.startswith(planned_end.astimezone().astimezone(planned_end.tzinfo).isoformat()[:13])
        or until
    )
    row = pw.rows(
        "SELECT valid_until <= (SELECT planned_end FROM shifts WHERE id = shift_id) FROM shift_overrides"
    )[0][0]
    assert row is True, "capped to the shift's planned end whatever was asked"
    with pw.idh.database.app_tx(
        __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
            pw.soc.id, None, "system", None
        )
    ) as conn:
        assert service.active_override(conn, pw.gate_id) is not None
    assert (
        pw.call(
            pw.guard,
            "POST",
            f"/v1/shifts/{shift['id']}/overrides",
            json={"reason": "I would like to override"},
        ).status_code
        == 403
    )
    ended = _end(pw, shift)
    assert ended.status_code == 200
    with pw.idh.database.app_tx(
        __import__("dwaar_api.core.db", fromlist=["RequestContext"]).RequestContext(
            pw.soc.id, None, "system", None
        )
    ) as conn:
        assert service.active_override(conn, pw.gate_id) is None, "the override died with the shift"
    assert pw.rows("SELECT revoke_reason FROM shift_overrides")[0][0] == "shift_ended"
    assert [o["revoke_reason"] for o in ended.json()["overrides"]] == ["shift_ended"]
    late = pw.call(
        pw.guard_sup,
        "POST",
        f"/v1/shifts/{shift['id']}/overrides",
        json={"reason": "After the shift ended"},
    )
    assert late.status_code == 422 and late.json()["details"]["reason"] == "shift_not_active"


def test_the_sweep_revokes_an_override_past_its_time_and_the_open_items_list_it(pw: PW) -> None:
    shift = pw.schedule(pw.guard, hours=8)
    _start(pw, shift)
    pw.call(
        pw.guard_sup,
        "POST",
        f"/v1/shifts/{shift['id']}/overrides",
        json={"reason": "Water tanker access for an hour", "minutes": 60},
    )
    handover = _end(pw, pw.schedule(pw.guard, start=now() + timedelta(days=1)), who=pw.guard_sup)
    assert handover.status_code == 422
    items_now = pw.call(pw.guard, "GET", "/v1/shifts/current").json()["context"]["active_overrides"]
    assert items_now == 1
    out = jobs.run_sweep(pw.idh.database, now=now() + timedelta(hours=2), societies=[pw.soc.id])
    assert out.overrides_revoked == 1
    assert pw.rows("SELECT revoke_reason FROM shift_overrides")[0][0] == "expired"
    assert (
        jobs.run_sweep(
            pw.idh.database, now=now() + timedelta(hours=3), societies=[pw.soc.id]
        ).overrides_revoked
        == 0
    )


def test_shift_reads_are_scoped_a_guard_sees_only_their_own(pw: PW) -> None:
    g2 = _second_guard(pw)
    mine = pw.schedule(pw.guard)
    theirs = pw.schedule(g2)
    own = pw.call(pw.guard, "GET", "/v1/shifts").json()["items"]
    assert [s["id"] for s in own] == [mine["id"]]
    assert pw.call(pw.guard, "GET", f"/v1/shifts/{theirs['id']}").status_code == 404
    assert {s["id"] for s in pw.call(pw.guard_sup, "GET", "/v1/shifts").json()["items"]} == {
        mine["id"],
        theirs["id"],
    }
    assert pw.call(pw.secretary, "GET", f"/v1/shifts/{theirs['id']}").status_code == 200
    page = pw.call(pw.guard_sup, "GET", "/v1/shifts", params={"limit": 1}).json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    h = pw.household("A-101")
    assert pw.call(h.owner, "GET", "/v1/shifts").status_code == 403
