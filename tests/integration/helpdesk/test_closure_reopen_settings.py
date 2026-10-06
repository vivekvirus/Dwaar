"""OPS-04 closure and reopen (original SLA retained); OPS-01/INV-10 SLA and window configuration."""

from __future__ import annotations

import copy

import pytest

from dwaar_api.modules.helpdesk import sla
from tests.integration.helpdesk._flow import act, crew, get, household, raise_ticket, tid

pytestmark = pytest.mark.req("OPS-04")


def resolved_ticket(hw, c, owner, unit):
    tech = hw.staff("estate_mgr")
    t = tid(
        raise_ticket(
            hw,
            owner,
            scope="private",
            unit_id=str(unit),
            category="plumbing",
            title="Geyser not heating",
        )
    )
    act(hw, c.secretary, t, "assign", {"assignee_id": str(tech.id)})
    act(hw, c.secretary, t, "transition", {"to": "in_progress"})
    act(hw, c.secretary, t, "transition", {"to": "resolved"})
    return t


def test_feedback_window_closes_the_ticket_and_names_the_basis(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    t = resolved_ticket(hw, c, owner, unit)
    due = hw.rows("SELECT feedback_due_at - resolved_at FROM tickets WHERE id = %s", (t,))[0][0]
    assert due.total_seconds() == 48 * 3600  # default feedback window
    assert get(hw, owner, t)["ticket"]["state"] == "resolved"
    hw.sql("UPDATE tickets SET feedback_due_at = now() - interval '1 minute' WHERE id = %s", (t,))
    closed = get(hw, owner, t)["ticket"]
    assert closed["state"] == "closed" and closed["closed_basis"] == "feedback_window_elapsed"
    assert hw.outbox("TicketClosed", t)[0]["payload"]["basis"] == "feedback_window_elapsed"
    assert hw.audit("ticket.close")[0][2] == "system"


def test_resident_confirmation_closes_before_the_window_and_a_manager_close_is_labelled(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    t = resolved_ticket(hw, c, owner, unit)
    act(hw, c.secretary, t, "confirm", {})  # not the raiser: recorded as a manager close
    assert get(hw, owner, t)["ticket"]["closed_basis"] == "manager_closed"
    t2 = resolved_ticket(hw, c, owner, unit)
    assert (
        act(hw, owner, t2, "confirm", {"note": "all good"})["ticket"]["closed_basis"]
        == "resident_confirmed"
    )
    act(hw, owner, t2, "confirm", {}, expect=409)  # only a RESOLVED ticket can be confirmed


def test_reopen_keeps_the_original_sla_history(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    t = resolved_ticket(hw, c, owner, unit)
    act(hw, owner, t, "confirm", {})
    before = hw.rows(
        "SELECT sla_started_at, sla_ack_by, sla_fix_by, ack_at, priority FROM tickets WHERE id = %s",
        (t,),
    )[0]
    hist_before = hw.rows(
        "SELECT seq, priority, ack_due_at, fix_due_at, at FROM ticket_priority_history WHERE ticket_id = %s ORDER BY seq",
        (t,),
    )
    breaches_before = hw.rows(
        "SELECT clock, due_at FROM ticket_sla_breaches WHERE ticket_id = %s ORDER BY clock", (t,)
    )
    r = act(hw, owner, t, "reopen", {"reason": "the geyser stopped again after one day"})
    assert (
        r["ticket"]["state"] == "assigned"
        and r["ticket"]["reopen_count"] == 1
        and r["ticket"]["resolved_at"] is None
    )
    after = hw.rows(
        "SELECT sla_started_at, sla_ack_by, sla_fix_by, ack_at, priority FROM tickets WHERE id = %s",
        (t,),
    )[0]
    assert after == before  # the clocks were NOT restarted
    assert (
        hw.rows(
            "SELECT seq, priority, ack_due_at, fix_due_at, at FROM ticket_priority_history WHERE ticket_id = %s ORDER BY seq",
            (t,),
        )
        == hist_before
    )
    assert (
        hw.rows(
            "SELECT clock, due_at FROM ticket_sla_breaches WHERE ticket_id = %s ORDER BY clock",
            (t,),
        )
        == breaches_before
    )
    kinds = [e["kind"] for e in get(hw, c.secretary, t)["events"]]
    assert kinds.count("resolved") == 1 and kinds.count("closed") == 1 and kinds[-1] == "reopened"
    assert hw.outbox("TicketReopened", t)[0]["payload"]["reopen_count"] == 1
    # it can be resolved and reopened again; the history only grows
    act(hw, c.secretary, t, "transition", {"to": "in_progress"})
    act(hw, c.secretary, t, "transition", {"to": "resolved"})
    assert (
        act(hw, owner, t, "reopen", {"reason": "still not hot enough"})["ticket"]["reopen_count"]
        == 2
    )


def test_a_reopened_ticket_overdue_against_the_original_target_is_flagged(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    t = resolved_ticket(hw, c, owner, unit)
    hw.sql("UPDATE tickets SET sla_fix_by = now() - interval '1 hour' WHERE id = %s", (t,))
    act(hw, owner, t, "reopen", {"reason": "not fixed properly"})
    from dwaar_api.modules.helpdesk import service

    with hw.svc(None, "system") as (conn, ctx, _a):
        assert service.sweep_society(conn, ctx)["breached"] == 1
    assert hw.rows("SELECT clock, basis FROM ticket_sla_breaches WHERE ticket_id = %s", (t,)) == [
        ("resolution", "sweep")
    ]


def test_reopen_window_is_enforced_and_a_merged_ticket_cannot_reopen(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    t = resolved_ticket(hw, c, owner, unit)
    act(hw, owner, t, "confirm", {})
    hw.sql("UPDATE tickets SET resolved_at = now() - interval '8 days' WHERE id = %s", (t,))
    r = hw.call(owner, "POST", f"/v1/tickets/{t}/reopen", json={"reason": "too late now"})
    assert r.status_code == 422 and r.json()["details"]["reason"] == "reopen_window_passed"
    hw.sql("UPDATE tickets SET resolved_at = now() - interval '6 days' WHERE id = %s", (t,))
    assert (
        hw.call(
            owner, "POST", f"/v1/tickets/{t}/reopen", json={"reason": "just in time"}
        ).status_code
        == 200
    )
    open_ticket = tid(
        raise_ticket(
            hw,
            owner,
            scope="private",
            unit_id=str(unit),
            category="plumbing",
            title="Drain smells bad",
        )
    )
    act(hw, owner, open_ticket, "reopen", {"reason": "not resolved at all"}, expect=409)


def test_household_members_can_reopen_but_strangers_cannot(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    family = hw.resident(unit, "family")
    stranger = hw.resident(hw.unit("A-102"), "owner")
    t = resolved_ticket(hw, c, owner, unit)
    assert (
        hw.call(
            stranger, "POST", f"/v1/tickets/{t}/reopen", json={"reason": "not my flat"}
        ).status_code
        == 404
    )
    assert (
        hw.call(
            family, "POST", f"/v1/tickets/{t}/reopen", json={"reason": "still leaking"}
        ).status_code
        == 200
    )


# ------------------------------------------------------------------------------------------------ configuration (INV-10)
def test_pilot_defaults_are_labelled_and_a_society_can_configure_them(hw) -> None:
    c = crew(hw)
    s = hw.call(c.committee, "GET", "/v1/helpdesk/settings").json()
    assert (
        s["sla_source"] == "pilot_default"
        and s["feedback_window_hours"] == 48
        and s["reopen_window_days"] == 7
    )
    assert (
        s["sla"]["emergency"]["ack"] == {"mode": "clock", "minutes": 2}
        and s["sla"]["urgent"]["ack"]["minutes"] == 15
    )
    assert s["sla"]["normal"]["ack"] == {"mode": "working", "minutes": 240} and s[
        "working_days"
    ] == [1, 2, 3, 4, 5, 6]
    new_sla = copy.deepcopy(sla.PILOT_SLA)
    new_sla["normal"]["fix"] = {"mode": "working", "days": 3}
    body = {
        "timezone": "Asia/Kolkata",
        "working_days": [1, 2, 3, 4, 5],
        "opens_at": "10:00",
        "closes_at": "17:00",
        "holidays": ["2026-10-20"],
        "sla": new_sla,
        "feedback_window_hours": 24,
        "reopen_window_days": 3,
        "duplicate_similarity": 0.6,
        "expected_version": s["version"],
    }
    r = hw.call(c.estate, "PUT", "/v1/helpdesk/settings", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert (
        out["sla_source"] == "society_configured"
        and out["feedback_window_hours"] == 24
        and out["duplicate_similarity"] == "0.60"
    )
    assert hw.audit("helpdesk.settings.update") and hw.outbox("HelpdeskSettingsChanged")
    assert (
        hw.call(c.estate, "PUT", "/v1/helpdesk/settings", json=body).status_code == 409
    )  # stale expected_version
    unit, owner = household(hw, "A-101")
    t = resolved_ticket(hw, c, owner, unit)
    due = hw.rows("SELECT feedback_due_at - resolved_at FROM tickets WHERE id = %s", (t,))[0][0]
    assert due.total_seconds() == 24 * 3600  # the new window applies to new resolutions


def test_settings_validation_and_permissions(hw) -> None:
    c = crew(hw)
    _unit, owner = household(hw, "A-101")
    s = hw.call(c.secretary, "GET", "/v1/helpdesk/settings").json()
    ok = {
        "timezone": "Asia/Kolkata",
        "working_days": [1, 2],
        "opens_at": "09:00",
        "closes_at": "18:00",
        "sla": s["sla"],
    }
    assert hw.call(owner, "GET", "/v1/helpdesk/settings").status_code == 403
    assert hw.call(owner, "PUT", "/v1/helpdesk/settings", json=ok).status_code == 403
    assert hw.call(c.committee, "PUT", "/v1/helpdesk/settings", json=ok).status_code == 403
    assert hw.call(c.guard, "GET", "/v1/helpdesk/settings").status_code == 403
    assert hw.call(c.auditor, "GET", "/v1/helpdesk/settings").status_code == 403
    for bad in (
        {**ok, "timezone": "Mars/Base"},
        {**ok, "closes_at": "08:00"},
        {**ok, "sla": {"normal": {}}},
        {**ok, "working_days": [9]},
        {**ok, "feedback_window_hours": 0},
        {**ok, "society_id": "x"},
    ):
        assert hw.call(c.secretary, "PUT", "/v1/helpdesk/settings", json=bad).status_code == 400, (
            bad
        )
