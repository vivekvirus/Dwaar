"""OPS-01: acknowledgement and resolution clocks, pause log with approver, immutable priority history, breaches survive.

Clock-driven tests call the SERVICE layer with an explicit ``now`` (one real transaction per step, real RLS context); the API
tests elsewhere cover the same behaviour over HTTP with the real clock. 2026-10-05 is a Monday; hours are Asia/Kolkata.
"""

from __future__ import annotations

import datetime as dt

import psycopg
import pytest

from dwaar_api.modules.helpdesk import service
from dwaar_api.modules.helpdesk.schemas import (
    AssignIn,
    Note,
    PriorityIn,
    TicketCreate,
    TransitionIn,
    TriageIn,
)
from dwaar_common.errors import PolicyViolation
from tests.integration.helpdesk._flow import crew

pytestmark = pytest.mark.req("OPS-01")
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def ist(d: int, hh: int, mm: int = 0, month: int = 10) -> dt.datetime:
    return dt.datetime(2026, month, d, hh, mm, tzinfo=IST).astimezone(dt.UTC)


def make(hw, who, now, **kw):
    body = {"scope": "society", "category": "common_area", "title": "Lobby door does not close"}
    body.update(kw)
    with hw.svc(who, "secretary") as (conn, ctx, actor):
        return service.create_ticket(conn, ctx, actor, TicketCreate(**body), now=now)["ticket"]


def step(hw, who, role, fn, ticket, body, now):
    with hw.svc(who, role) as (conn, ctx, actor):
        return fn(conn, ctx, actor, ticket, body, now)


def ticket_row(hw, tid):
    cols = "state, priority, sla_ack_by, sla_fix_by, ack_at, sla_paused_since, resolved_at"
    return dict(
        zip(
            cols.split(", "),
            hw.rows(f"SELECT {cols} FROM tickets WHERE id = %s", (tid,))[0],
            strict=True,
        )
    )


def breaches(hw, tid):
    return [
        (r[0], r[1], r[2])
        for r in hw.rows(
            "SELECT clock, basis, priority_at_breach FROM ticket_sla_breaches WHERE ticket_id = %s ORDER BY clock",
            (tid,),
        )
    ]


def test_normal_ticket_gets_working_hour_targets_and_an_ontime_ack_is_clean(hw) -> None:
    c = crew(hw)
    t = make(hw, c.secretary, ist(5, 10))
    assert t["sla_ack_by"] == ist(5, 14)  # 4 working hours
    assert t["sla_fix_by"] == ist(7, 10)  # 2 working days of 9 h
    step(hw, c.secretary, "secretary", service.acknowledge, t["id"], Note(), ist(5, 11))
    assert ticket_row(hw, t["id"])["ack_at"] == ist(5, 11) and breaches(hw, t["id"]) == []


def test_a_late_acknowledgement_is_recorded_as_a_breach(hw) -> None:
    c = crew(hw)
    t = make(hw, c.secretary, ist(5, 10))
    step(hw, c.secretary, "secretary", service.acknowledge, t["id"], Note(), ist(6, 10))
    assert breaches(hw, t["id"]) == [("acknowledgement", "met_late", "normal")]
    # a second acknowledgement is idempotent: nothing new is written
    step(hw, c.secretary, "secretary", service.acknowledge, t["id"], Note(), ist(6, 11))
    assert len(breaches(hw, t["id"])) == 1 and ticket_row(hw, t["id"])["ack_at"] == ist(6, 10)


def test_emergency_has_a_two_minute_acknowledgement_target(hw) -> None:
    c = crew(hw)
    t = make(
        hw,
        c.secretary,
        ist(5, 3),
        category="lift",
        title="Lift cabin is sparking",
        unsafe_observation=True,
    )
    assert t["priority"] == "emergency" and t["sla_ack_by"] == ist(5, 3) + dt.timedelta(minutes=2)
    alert = hw.outbox("TicketEmergencyAlert", t["id"])
    assert len(alert) == 1 and alert[0]["payload"]["ack_target_seconds"] == 120


def test_pause_extends_the_resolution_clock_and_records_reason_and_approver(hw) -> None:
    c = crew(hw)
    tech = hw.staff("estate_mgr")
    t = make(hw, c.secretary, ist(5, 10))
    tid = t["id"]
    step(
        hw,
        c.secretary,
        "secretary",
        service.assign,
        tid,
        AssignIn(assignee_id=tech.id),
        ist(5, 10, 30),
    )
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        tid,
        TransitionIn(to="in_progress"),
        ist(5, 11),
    )
    fix_before = ticket_row(hw, tid)["sla_fix_by"]
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        tid,
        TransitionIn(to="awaiting_material", approver_id=c.estate.id),
        ist(5, 15),
    )
    assert ticket_row(hw, tid)["sla_paused_since"] == ist(5, 15)
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        tid,
        TransitionIn(to="in_progress"),
        ist(6, 11),
    )
    row = ticket_row(hw, tid)
    # stopped from Mon 15:00 to Tue 11:00 = 3 h + 2 h of working time
    assert (
        row["sla_fix_by"] == fix_before + dt.timedelta(hours=5) and row["sla_paused_since"] is None
    )
    log = hw.rows(
        "SELECT kind, reason, approver_id, fix_due_before, fix_due_after FROM ticket_sla_log WHERE ticket_id = %s ORDER BY seq",
        (tid,),
    )
    assert (
        [r[0] for r in log] == ["pause", "resume"]
        and log[0][1] == "awaiting_material"
        and log[0][2] == c.estate.id
    )
    assert log[1][3] == fix_before and log[1][4] == row["sla_fix_by"]
    assert (
        hw.audit("ticket.awaiting_material")[0][6] == c.estate.id
    )  # approver in the audit row too


def test_a_pause_cannot_hide_a_breach_that_already_happened(hw) -> None:
    c = crew(hw)
    t = make(hw, c.secretary, ist(5, 10), priority="urgent")  # ack by 10:15
    tid = t["id"]
    step(
        hw,
        c.secretary,
        "secretary",
        service.assign,
        tid,
        AssignIn(contractor_name="Acme Facilities"),
        ist(5, 12),
    )
    assert breaches(hw, tid) == [("acknowledgement", "met_late", "urgent")]


def test_priority_history_is_append_only_and_records_the_approver(hw) -> None:
    c = crew(hw)
    t = make(hw, c.secretary, ist(5, 10))
    tid = t["id"]
    step(hw, c.secretary, "secretary", service.triage, tid, TriageIn(), ist(5, 10, 5))
    step(
        hw,
        c.secretary,
        "secretary",
        service.change_priority,
        tid,
        PriorityIn(priority="urgent", reason="water entering the flat"),
        ist(5, 10, 6),
    )
    row = ticket_row(hw, tid)
    assert row["priority"] == "urgent" and row["sla_ack_by"] == ist(
        5, 10, 15
    )  # counted from the ORIGINAL start
    hist = hw.rows(
        "SELECT seq, priority, previous_priority, rule, approver_id, ack_due_at FROM ticket_priority_history WHERE ticket_id = %s ORDER BY seq",
        (tid,),
    )
    assert [(h[1], h[2], h[3]) for h in hist] == [
        ("normal", None, "initial"),
        ("urgent", "normal", "manual"),
    ]
    # the app role can neither rewrite nor delete a history row
    with hw.idh.db.app_conn(hw.soc.id, c.secretary.id, "secretary") as conn:
        for sql in (
            "UPDATE ticket_priority_history SET priority = 'low'",
            "DELETE FROM ticket_priority_history",
            "UPDATE ticket_sla_log SET reason = 'awaiting_resident'",
            "DELETE FROM ticket_sla_breaches",
            "UPDATE ticket_events SET note = 'x'",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)  # type: ignore[call-overload]
            conn.rollback()


def test_lowering_urgent_or_emergency_needs_a_different_approver(hw) -> None:
    c = crew(hw)
    t = make(hw, c.secretary, ist(5, 10), category="gas", title="Gas cylinder store door is jammed")
    tid = t["id"]
    assert t["priority"] == "urgent"  # the gas category alone is urgent, with the procedure shown
    for approver in (
        None,
        c.secretary.id,
    ):  # no approver, and the person lowering it approving their own change
        body = PriorityIn(
            priority="normal", reason="downgrade, checked on site", approver_id=approver
        )
        with pytest.raises(PolicyViolation) as exc:
            step(hw, c.secretary, "secretary", service.change_priority, tid, body, ist(5, 10, 1))
        assert exc.value.details["reason"] == "approver_required"
    step(
        hw,
        c.secretary,
        "secretary",
        service.change_priority,
        tid,
        PriorityIn(priority="normal", reason="downgrade, checked on site", approver_id=c.estate.id),
        ist(5, 10, 2),
    )
    last = hw.rows(
        "SELECT priority, approver_id, set_by FROM ticket_priority_history WHERE ticket_id = %s ORDER BY seq DESC LIMIT 1",
        (tid,),
    )[0]
    assert last == ("normal", c.estate.id, c.secretary.id)
    assert hw.audit("ticket.priority_change")[0][6] == c.estate.id


def test_changing_priority_later_cannot_erase_a_breach(hw) -> None:
    c = crew(hw)
    t = make(hw, c.secretary, ist(5, 10), priority="urgent")  # ack due 10:15, nobody acknowledges
    tid = t["id"]
    step(
        hw,
        c.secretary,
        "secretary",
        service.change_priority,
        tid,
        PriorityIn(priority="low", reason="not urgent after all", approver_id=c.estate.id),
        ist(5, 12),
    )
    # the breach of the URGENT acknowledgement target is on record, with the due time of that target and that priority
    assert breaches(hw, tid) == [("acknowledgement", "before_change", "urgent")]
    due = hw.rows("SELECT due_at FROM ticket_sla_breaches WHERE ticket_id = %s", (tid,))[0][0]
    assert due == ist(5, 10, 15)
    # the new (low) target is later, yet nothing is un-breached
    assert ticket_row(hw, tid)["sla_ack_by"] > ist(5, 12)
    step(
        hw,
        c.secretary,
        "secretary",
        service.change_priority,
        tid,
        PriorityIn(priority="normal", reason="back to normal"),
        ist(5, 12, 5),
    )
    assert breaches(hw, tid) == [("acknowledgement", "before_change", "urgent")]
    api = hw.call(c.secretary, "GET", f"/v1/tickets/{tid}/sla").json()
    assert [b["clock"] for b in api["breaches"]] == ["acknowledgement"]
    assert [h["priority"] for h in api["priority_history"]] == ["urgent", "low", "normal"]


def test_late_resolution_is_a_breach_and_resolution_clock_runs_to_the_original_due(hw) -> None:
    c = crew(hw)
    tech = hw.staff("estate_mgr")
    t = make(hw, c.secretary, ist(5, 10))
    tid = t["id"]
    step(
        hw, c.secretary, "secretary", service.assign, tid, AssignIn(assignee_id=tech.id), ist(5, 11)
    )
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        tid,
        TransitionIn(to="in_progress"),
        ist(5, 12),
    )
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        tid,
        TransitionIn(to="resolved"),
        ist(8, 10),
    )  # due was Wed 7 Oct 10:00
    assert ("resolution", "met_late", "normal") in breaches(hw, tid)
    assert ticket_row(hw, tid)["resolved_at"] == ist(8, 10)


def test_sweep_records_breaches_once_and_closes_after_the_feedback_window(hw) -> None:
    c = crew(hw)
    tech = hw.staff("estate_mgr")
    late = make(hw, c.secretary, ist(5, 10))
    ontime = make(hw, c.secretary, ist(5, 10), title="Gate lamp is dim")
    step(
        hw,
        c.secretary,
        "secretary",
        service.assign,
        ontime["id"],
        AssignIn(assignee_id=tech.id),
        ist(5, 10, 30),
    )
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        ontime["id"],
        TransitionIn(to="in_progress"),
        ist(5, 11),
    )
    step(
        hw,
        c.secretary,
        "secretary",
        service.transition,
        ontime["id"],
        TransitionIn(to="resolved"),
        ist(5, 12),
    )
    with hw.svc(None, "system") as (conn, ctx, _a):
        first = service.sweep_society(conn, ctx, now=ist(6, 9))
    assert first["breached"] == 1 and breaches(hw, late["id"]) == [
        ("acknowledgement", "sweep", "normal")
    ]
    assert breaches(hw, ontime["id"]) == []
    with hw.svc(None, "system") as (conn, ctx, _a):
        again = service.sweep_society(conn, ctx, now=ist(6, 9))
    assert again == {"closed": 0, "breached": 0}
    # 48 h feedback window after Mon 12:00 -> closed by the sweep, on the system's authority
    with hw.svc(None, "system") as (conn, ctx, _a):
        later = service.sweep_society(conn, ctx, now=ist(7, 13))
    assert later["closed"] == 1
    row = hw.rows("SELECT state, closed_basis FROM tickets WHERE id = %s", (ontime["id"],))[0]
    assert row == ("closed", "feedback_window_elapsed")
    assert hw.audit("ticket.close")[-1][2] == "system"
