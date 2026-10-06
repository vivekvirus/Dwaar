"""OPS-09 hazard rules, emergency procedure, contractor routing; UX-07 support/privacy issue while membership is disputed."""

from __future__ import annotations

import pytest

from dwaar_api.modules.helpdesk import hazards
from tests.integration.helpdesk._flow import act, crew, get, household, raise_ticket, tid
from tests.integration.helpdesk._support import text_of

PROC = {
    "headline": "Lift emergency: press the alarm and call the guard room",
    "steps": "Stay calm. Use the in-cabin intercom. The guard room will call the lift contractor and the secretary.",
    "contacts": [
        {"role": "Secretary", "name": "Test Secretary", "phone": "+919999900901"},
        {"role": "Guard room", "name": "Gate 1", "phone": "+919999900902"},
    ],
    "qualified_contractor": "Test Lift Services Pvt Ltd",
}


# ------------------------------------------------------------------------------------------------ rules (pure)
@pytest.mark.req("OPS-09")
@pytest.mark.parametrize(
    ("category", "text", "declared", "kind", "emergency"),
    [
        ("lift", "People are stuck in the lift between floors 3 and 4", False, "lift", True),
        ("lift", "Lift button is worn out", False, None, None),
        ("lift", "Lift button is worn out", True, "lift", True),
        ("electrical", "Sparking from the meter room panel", False, "electrical", True),
        ("electrical", "Corridor bulb needs replacing", False, None, None),
        ("plumbing", "There is a smell of gas near the kitchen", False, "gas", True),
        ("gas", "Pipeline valve is rusty", False, "gas", False),
        ("fire_safety", "Extinguisher refill due", False, "fire", False),
        ("cleaning", "Smoke coming out of the garbage room", False, "fire", True),
        ("cleaning", "Lobby needs mopping", False, None, None),
        ("other", "आग लगी है बेसमेंट में", False, "fire", True),
        ("other", "आगे का रास्ता बंद है", False, None, None),
        ("other", "लिफ्टमध्ये अडकले आहेत दोन जण", False, "lift", True),
        ("other", "fireplace tiles are cracked", False, None, None),
    ],
)
def test_hazard_rules_are_deterministic(category, text, declared, kind, emergency) -> None:
    match = hazards.detect(category, text, unsafe_declared=declared)
    if kind is None:
        assert match is None
    else:
        assert match is not None and match.kind == kind and match.emergency is emergency
        assert match.rule.endswith(hazards.RULESET_VERSION)


# ------------------------------------------------------------------------------------------------ API
@pytest.mark.req("OPS-09")
def test_unsafe_lift_report_shows_the_procedure_at_once_and_alerts(hw) -> None:
    c = crew(hw)
    _unit, owner = household(hw, "A-101")
    assert (
        hw.call(c.secretary, "PUT", "/v1/helpdesk/emergency-procedures/lift", json=PROC).status_code
        == 200
    )
    r = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={
            "scope": "society",
            "category": "lift",
            "title": "Lift is sparking and smells of burning",
            "unsafe_observation": True,
        },
    )
    assert r.status_code == 201
    body = r.json()
    t, em = body["ticket"], body["emergency"]
    assert (
        t["priority"] == "emergency"
        and t["state"] == "submitted"
        and t["hazard_kind"] == "lift"
        and t["routing"] == "qualified_contractor"
    )
    assert em["procedure"]["configured"] is True and em["procedure"]["headline"] == PROC["headline"]
    assert [x["role"] for x in em["procedure"]["contacts"]] == ["Secretary", "Guard room"]
    assert em["no_rescue_guarantee"] is True and em["no_repair_instructions"] is True
    assert "ops.emergency.no_rescue_guarantee" in em["procedure"]["message_keys"]
    # never repair advice: the response carries only the society's own procedure text plus keys
    assert "repair" not in text_of(r).lower().replace("do_not_attempt_repair", "").replace(
        "no_repair_instructions", ""
    ).replace("beyond_staff", "")
    alert = hw.outbox("TicketEmergencyAlert", t["id"])
    assert (
        len(alert) == 1
        and alert[0]["payload"]["emergency"] is True
        and alert[0]["payload"]["ack_target_seconds"] == 120
    )
    assert hw.outbox("TicketSubmitted", t["id"])[0]["payload"]["priority"] == "emergency"
    # a resident can never lower it: priority input is managers-only, and the rule wins over a manager's lower choice too
    low = hw.call(
        c.secretary,
        "POST",
        "/v1/tickets",
        json={
            "scope": "society",
            "category": "lift",
            "title": "Lift door sparking badly",
            "unsafe_observation": True,
            "priority": "low",
        },
    )
    assert low.json()["ticket"]["priority"] == "emergency"


@pytest.mark.req("OPS-09")
def test_an_unsafe_observation_is_never_left_as_a_draft(hw) -> None:
    _unit, owner = household(hw, "A-101")
    r = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={
            "scope": "society",
            "category": "electrical",
            "title": "Live wire hanging in parking",
            "unsafe_observation": True,
            "submit": False,
        },
    )
    assert (
        r.json()["ticket"]["state"] == "submitted" and r.json()["ticket"]["priority"] == "emergency"
    )


@pytest.mark.req("OPS-09")
def test_missing_procedure_says_so_plainly(hw) -> None:
    _unit, owner = household(hw, "A-101")
    r = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={"scope": "society", "category": "other", "title": "Gas leak smell near block B"},
    )
    proc = r.json()["emergency"]["procedure"]
    assert (
        proc["configured"] is False
        and proc["steps"] is None
        and "ops.emergency.not_configured" in proc["message_keys"]
    )
    got = hw.call(owner, "GET", "/v1/helpdesk/emergency-procedures").json()
    assert (
        set(got) == {"lift", "electrical", "gas", "fire", "general"}
        and not got["gas"]["configured"]
    )


@pytest.mark.req("OPS-09")
def test_general_procedure_is_the_fallback_and_editing_is_secretary_only(hw) -> None:
    c = crew(hw)
    _unit, owner = household(hw, "A-101")
    for who in (owner, c.estate, c.committee, c.guard, c.auditor):
        assert (
            hw.call(who, "PUT", "/v1/helpdesk/emergency-procedures/general", json=PROC).status_code
            == 403
        )
    first = hw.call(c.secretary, "PUT", "/v1/helpdesk/emergency-procedures/general", json=PROC)
    assert first.status_code == 200 and first.json()["version"] == 1
    again = hw.call(
        c.secretary,
        "PUT",
        "/v1/helpdesk/emergency-procedures/general",
        json={**PROC, "headline": "Updated headline", "expected_version": 1},
    )
    assert again.json()["version"] == 2
    assert (
        hw.call(
            c.secretary,
            "PUT",
            "/v1/helpdesk/emergency-procedures/general",
            json={**PROC, "expected_version": 1},
        ).status_code
        == 409
    )
    r = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={
            "scope": "society",
            "category": "fire_safety",
            "title": "Fire alarm panel shows a fault",
        },
    )
    assert r.json()["emergency"]["procedure"]["headline"] == "Updated headline"
    assert (
        r.json()["ticket"]["priority"] == "urgent"
    )  # the category alone is urgent, not an emergency
    # the guard may read the procedure (create-only role, but must know it); auditors may not
    assert hw.call(c.guard, "GET", "/v1/helpdesk/emergency-procedures").status_code == 200
    assert hw.call(c.auditor, "GET", "/v1/helpdesk/emergency-procedures").status_code == 403
    assert (
        hw.call(
            c.secretary, "PUT", "/v1/helpdesk/emergency-procedures/volcano", json=PROC
        ).status_code
        == 400
    )
    assert hw.audit("helpdesk.emergency_procedure.put") and hw.outbox("EmergencyProcedureChanged")


@pytest.mark.req("OPS-09")
def test_hazard_work_goes_to_a_qualified_contractor_not_in_house_staff(hw) -> None:
    c = crew(hw)
    tech = hw.staff("estate_mgr")
    _unit, owner = household(hw, "A-101")
    t = tid(
        raise_ticket(
            hw,
            owner,
            category="electrical",
            title="Sparks from the common panel",
            unsafe_observation=True,
        )
    )
    r = hw.call(c.secretary, "POST", f"/v1/tickets/{t}/assign", json={"assignee_id": str(tech.id)})
    assert r.status_code == 422 and r.json()["details"]["reason"] == "contractor_required"
    ok = act(hw, c.secretary, t, "assign", {"contractor_name": "Test Electrical Contractors"})
    assert (
        ok["ticket"]["routing"] == "qualified_contractor"
        and ok["ticket"]["contractor_name"] == "Test Electrical Contractors"
    )
    assert ok["ticket"]["state"] == "assigned"
    # a manager can also mark ordinary work as beyond staff competence: same routing rule
    plain = tid(
        raise_ticket(hw, c.secretary, category="civil", title="Crack in the retaining wall")
    )
    act(hw, c.secretary, plain, "triage", {"beyond_staff_competence": True})
    assert (
        hw.call(
            c.secretary, "POST", f"/v1/tickets/{plain}/assign", json={"assignee_id": str(tech.id)}
        ).status_code
        == 422
    )
    assert (
        act(hw, c.secretary, plain, "assign", {"contractor_name": "Test Civil Works"})["ticket"][
            "routing"
        ]
        == "qualified_contractor"
    )
    # exactly one of assignee or contractor
    assert hw.call(c.secretary, "POST", f"/v1/tickets/{plain}/assign", json={}).status_code == 400
    assert (
        hw.call(
            c.secretary,
            "POST",
            f"/v1/tickets/{plain}/assign",
            json={"assignee_id": str(tech.id), "contractor_name": "Both Ltd"},
        ).status_code
        == 400
    )
    # an unknown person cannot be assigned
    ordinary = tid(
        raise_ticket(hw, c.secretary, category="cleaning", title="Terrace needs cleaning")
    )
    import uuid

    assert (
        hw.call(
            c.secretary,
            "POST",
            f"/v1/tickets/{ordinary}/assign",
            json={"assignee_id": str(uuid.uuid4())},
        ).status_code
        == 400
    )


@pytest.mark.req("OPS-09", "OPS-01")
def test_guard_is_create_only_and_gets_the_procedure_without_reading_anything(hw) -> None:
    c = crew(hw)
    hw.call(
        c.secretary,
        "PUT",
        "/v1/helpdesk/emergency-procedures/fire",
        json={**PROC, "headline": "Fire: raise the alarm and evacuate"},
    )
    r = hw.call(
        c.guard,
        "POST",
        "/v1/tickets",
        json={
            "scope": "society",
            "category": "fire_safety",
            "title": "Smoke from the transformer room",
            "unsafe_observation": True,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "ticket_no", "state", "emergency"} and body["emergency"][
        "procedure"
    ]["headline"].startswith("Fire:")
    for call in (
        hw.call(c.guard, "GET", "/v1/tickets"),
        hw.call(c.guard, "GET", f"/v1/tickets/{body['id']}"),
    ):
        assert call.status_code == 403
    assert hw.call(c.guard, "POST", f"/v1/tickets/{body['id']}/triage", json={}).status_code == 403
    row = hw.rows("SELECT raised_channel, priority FROM tickets WHERE id = %s", (body["id"],))[0]
    assert row == ("guard", "emergency")


# ------------------------------------------------------------------------------------------------ UX-07
@pytest.mark.req("UX-07")
@pytest.mark.parametrize("verification", ["disputed", "pending", "reverification"])
def test_a_resident_can_raise_a_support_issue_while_the_membership_is_not_settled(
    hw, verification
) -> None:
    c = crew(hw)
    unit = hw.unit("A-101")
    who = hw.resident(unit, "tenant", verification=verification)
    r = hw.call(
        who,
        "POST",
        f"/v1/societies/{hw.soc.id}/support-requests",
        json={
            "title": "My tenancy record is wrong",
            "description": "Please correct the owner name and delete my old phone",
        },
    )
    assert r.status_code == 201, r.text
    t = r.json()["ticket"]
    assert (
        t["category"] == "support_privacy"
        and t["scope"] == "private"
        and t["unit_id"] == str(unit)
        and t["state"] == "submitted"
    )
    row = hw.rows("SELECT raised_channel FROM tickets WHERE id = %s", (t["id"],))[0]
    assert row == ("support",)
    mine = hw.call(who, "GET", f"/v1/societies/{hw.soc.id}/support-requests").json()["items"]
    assert [i["id"] for i in mine] == [t["id"]]
    # the secretary sees it (privacy officer); the estate manager and committee do not
    assert hw.call(c.secretary, "GET", f"/v1/tickets/{t['id']}").status_code == 200
    assert hw.call(c.estate, "GET", f"/v1/tickets/{t['id']}").status_code == 404
    assert hw.call(c.committee, "GET", f"/v1/tickets/{t['id']}").status_code == 404
    assert t["id"] not in {i["id"] for i in hw.call(c.estate, "GET", "/v1/tickets").json()["items"]}
    other = hw.resident(hw.unit("A-102"), "owner")
    assert hw.call(other, "GET", f"/v1/tickets/{t['id']}").status_code == 404
    assert hw.audit("ticket.submit_new")[-1][2] == "applicant"


@pytest.mark.req("UX-07")
def test_support_requests_are_not_open_to_strangers_or_rejected_members(hw) -> None:
    stranger = hw.person()  # signed in, no relationship to the society at all
    rejected = hw.resident(hw.unit("A-101"), "tenant", verification="rejected")
    for who in (stranger, rejected):
        r = hw.call(
            who,
            "POST",
            f"/v1/societies/{hw.soc.id}/support-requests",
            json={"title": "Let me in please"},
        )
        assert r.status_code == 404 and r.json()["code"] == "not_found"
        assert hw.call(who, "GET", f"/v1/societies/{hw.soc.id}/support-requests").status_code == 404
    member = hw.resident(hw.unit("A-102"), "owner")
    other_unit = hw.call(
        member,
        "POST",
        f"/v1/societies/{hw.soc.id}/support-requests",
        json={"title": "Someone else's flat", "unit_id": str(hw.unit("A-101"))},
    )
    assert other_unit.status_code == 404
    assert (
        hw.call(
            None,
            "POST",
            f"/v1/societies/{hw.soc.id}/support-requests",
            json={"title": "No token at all"},
        ).status_code
        == 401
    )


@pytest.mark.req("UX-07")
def test_a_pending_member_gets_no_other_helpdesk_access(hw) -> None:
    pending = hw.resident(hw.unit("A-101"), "tenant", verification="pending")
    c = crew(hw)
    r = hw.call(
        pending,
        "POST",
        f"/v1/societies/{hw.soc.id}/support-requests",
        json={"title": "Waiting for my verification"},
    )
    t = r.json()["ticket"]["id"]
    assert (
        hw.call(pending, "GET", "/v1/tickets").status_code == 404
    )  # no effective grant: same answer as "no such society"
    assert (
        hw.call(
            pending,
            "POST",
            "/v1/tickets",
            json={"scope": "society", "category": "other", "title": "Normal ticket"},
        ).status_code
        == 404
    )
    assert get(hw, c.secretary, t)["ticket"]["category"] == "support_privacy"


@pytest.mark.req("UX-07")
def test_a_disputed_member_can_also_use_the_normal_helpdesk(hw) -> None:
    unit = hw.unit("A-101")
    who = hw.resident(unit, "tenant", verification="disputed")
    ok = hw.call(
        who,
        "POST",
        "/v1/tickets",
        json={
            "scope": "private",
            "unit_id": str(unit),
            "category": "plumbing",
            "title": "Tap leaking in the kitchen",
        },
    )
    assert ok.status_code == 201  # a dispute never removes occupancy (IAM-05), so the grant stands
