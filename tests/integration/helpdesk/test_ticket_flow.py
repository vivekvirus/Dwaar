"""OPS-01 state machine, OPS-03 standard form and draft confirmation, audit + outbox, idempotency, optimistic concurrency."""

from __future__ import annotations

import uuid

import pytest

from tests.integration.helpdesk._flow import act, crew, get, household, raise_ticket, tid

pytestmark = pytest.mark.req("OPS-01")


def test_full_lifecycle_through_every_state(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    tech = hw.staff(
        "estate_mgr"
    )  # a person with standing in the society, used as the in-house assignee
    t = tid(
        raise_ticket(
            hw,
            owner,
            scope="private",
            unit_id=str(unit),
            category="plumbing",
            title="Kitchen tap leaking",
            description="Water drips under the sink",
        )
    )
    assert get(hw, c.secretary, t)["ticket"]["state"] == "submitted"

    act(hw, c.secretary, t, "triage", {"note": "plumber needed"})
    assert get(hw, owner, t)["ticket"]["state"] == "triaged"
    a = act(hw, c.estate, t, "assign", {"assignee_id": str(tech.id)})
    assert a["ticket"]["state"] == "assigned" and a["ticket"]["assignee_id"] == str(tech.id)
    act(hw, c.estate, t, "transition", {"to": "in_progress"})
    act(hw, c.estate, t, "transition", {"to": "awaiting_material", "note": "washer ordered"})
    act(hw, c.estate, t, "transition", {"to": "in_progress"})
    act(
        hw,
        c.estate,
        t,
        "transition",
        {"to": "awaiting_resident", "note": "need access on Saturday"},
    )
    r = act(hw, owner, t, "respond", {"note": "come at 10"})
    assert r["ticket"]["state"] == "in_progress"
    res = act(hw, c.estate, t, "transition", {"to": "resolved"})
    assert res["ticket"]["state"] == "resolved" and res["ticket"]["feedback_due_at"]
    closed = act(hw, owner, t, "confirm", {})
    assert (
        closed["ticket"]["state"] == "closed"
        and closed["ticket"]["closed_basis"] == "resident_confirmed"
    )
    kinds = [e["kind"] for e in get(hw, c.secretary, t)["events"]]
    assert kinds[:2] == ["created", "submitted"]
    for expected in ("triaged", "assigned", "paused", "resumed", "resolved", "closed"):
        assert expected in kinds


def test_invalid_moves_are_409_and_closed_is_final(hw) -> None:
    c = crew(hw)
    t = tid(raise_ticket(hw, c.secretary))
    act(hw, c.secretary, t, "transition", {"to": "resolved"}, expect=409)  # straight from submitted
    act(hw, c.secretary, t, "transition", {"to": "in_progress"}, expect=409)
    act(hw, c.secretary, t, "triage")
    act(hw, c.secretary, t, "triage")  # re-triage is allowed
    act(hw, c.secretary, t, "cancel", {"reason": "raised twice"})
    for verb, body in (
        ("triage", {}),
        ("assign", {"contractor_name": "Acme Repairs"}),
        ("confirm", {}),
        ("reopen", {"reason": "again"}),
    ):
        r = hw.call(c.secretary, "POST", f"/v1/tickets/{t}/{verb}", json=body)
        assert r.status_code == 409 and r.json()["code"] == "stale_version", (verb, r.text)


def test_cancel_is_for_the_raiser_or_a_manager(hw) -> None:
    unit, owner = household(hw, "A-101")
    other = hw.resident(hw.unit("A-102"), "owner")
    t = tid(
        raise_ticket(
            hw,
            owner,
            scope="private",
            unit_id=str(unit),
            category="noise",
            title="Loud drilling upstairs",
        )
    )
    r = hw.call(other, "POST", f"/v1/tickets/{t}/cancel", json={"reason": "not mine to cancel"})
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    assert act(hw, owner, t, "cancel", {"reason": "sorted out"})["ticket"]["state"] == "cancelled"


def test_draft_is_confirmed_before_submit_and_has_no_clock(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    d = raise_ticket(
        hw,
        owner,
        scope="private",
        unit_id=str(unit),
        category="plumbing",
        title="Slow drain in bathroom",
        submit=False,
    )
    t = d["ticket"]
    assert t["state"] == "draft" and t["sla"]["ack_by"] is None
    # nobody else sees a draft, not even the secretary
    assert hw.call(c.secretary, "GET", f"/v1/tickets/{t['id']}").status_code == 404
    assert t["id"] not in [
        x["id"] for x in hw.call(c.secretary, "GET", "/v1/tickets").json()["items"]
    ]
    assert hw.call(c.secretary, "POST", f"/v1/tickets/{t['id']}/submit", json={}).status_code == 404
    s = act(hw, owner, t["id"], "submit")
    assert (
        s["ticket"]["state"] == "submitted"
        and s["ticket"]["sla"]["ack_by"]
        and s["ticket"]["sla"]["fix_by"]
    )
    act(hw, owner, t["id"], "submit", expect=409)  # already submitted
    assert get(hw, c.secretary, t["id"])["ticket"]["state"] == "submitted"


def test_standard_form_needs_no_ai_and_validates_its_input(hw) -> None:
    _unit, owner = household(hw, "A-101")
    base = {"scope": "society", "category": "garden", "title": "Overgrown hedge near gate"}
    assert hw.call(owner, "POST", "/v1/tickets", json=base).status_code == 201
    for bad in (
        {**base, "title": "x"},
        {**base, "category": "astrology"},
        {**base, "scope": "private"},  # private needs a unit
        {**base, "unit_id": str(uuid.uuid4())},  # society scope takes none
        {**base, "photo_refs": ["short"]},
        {**base, "priority": "urgent"},  # residents cannot pick the priority
        {**base, "society_id": str(uuid.uuid4())},  # smuggled field
        {**base, "raised_by": str(uuid.uuid4())},
    ):
        r = hw.call(owner, "POST", "/v1/tickets", json=bad)
        assert r.status_code in (400, 404), (bad, r.text)
    r = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={**base, "scope": "private", "unit_id": str(hw.unit("A-102"))},
    )
    assert r.status_code == 404 and r.json()["code"] == "not_found"  # not the caller's unit
    photos = ["photo_" + "a" * 10, "photo_" + "b" * 10]
    ok = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={**base, "title": "Cracked tile in lobby", "photo_refs": photos},
    )
    assert ok.status_code == 201 and ok.json()["ticket"]["photo_refs"] == photos


def test_idempotency_replay_and_payload_mismatch(hw) -> None:
    _unit, owner = household(hw, "A-101")
    body = {"scope": "society", "category": "garden", "title": "Dead tree near block C"}
    first = hw.call(owner, "POST", "/v1/tickets", json=body, key="same-key-0001")
    again = hw.call(owner, "POST", "/v1/tickets", json=body, key="same-key-0001")
    assert first.status_code == again.status_code == 201
    assert again.headers["Idempotent-Replayed"] == "true"
    assert first.json()["ticket"]["id"] == again.json()["ticket"]["id"]
    assert hw.rows("SELECT count(*) FROM tickets")[0][0] == 1
    other = hw.call(
        owner,
        "POST",
        "/v1/tickets",
        json={**body, "title": "A different complaint"},
        key="same-key-0001",
    )
    assert other.status_code == 409 and other.json()["code"] == "duplicate_payload_mismatch"
    assert (
        hw.call(
            owner, "POST", "/v1/tickets", json=body, headers={"Idempotency-Key": ""}
        ).status_code
        == 400
    )


def test_stale_version_is_409(hw) -> None:
    c = crew(hw)
    t = raise_ticket(hw, c.secretary)["ticket"]
    act(hw, c.secretary, t["id"], "triage", {"expected_version": t["version"]})
    r = hw.call(
        c.secretary,
        "POST",
        f"/v1/tickets/{t['id']}/triage",
        json={"expected_version": t["version"]},
    )
    assert r.status_code == 409 and r.json()["code"] == "stale_version"


def test_every_mutation_has_audit_and_outbox_but_no_ticket_text(hw) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    secret_words = "Mrs Gupta flat 101 phone 9999900123 complains"
    t = tid(
        raise_ticket(
            hw,
            owner,
            scope="private",
            unit_id=str(unit),
            category="plumbing",
            title="Tap leaking again",
            description=secret_words,
        )
    )
    act(hw, c.secretary, t, "triage")
    submitted = hw.outbox("TicketSubmitted", t)
    assert len(submitted) == 1 and submitted[0]["version"] == 1
    assert hw.outbox("TicketTriaged", t)[0]["version"] == 2
    assert [a[0] for a in hw.audit("ticket.submit_new")] == ["ticket.submit_new"]
    assert hw.audit("ticket.triage")[0][2] == "secretary"
    blob = str(hw.rows("SELECT payload FROM outbox WHERE aggregate_id = %s", (t,))) + str(
        hw.rows("SELECT diff_masked FROM audit_log WHERE object_id = %s", (t,))
    )
    assert "Gupta" not in blob and "9999900123" not in blob and "Tap leaking" not in blob
    payload = submitted[0]["payload"]
    assert (
        payload["unit_id"] == str(unit)
        and payload["emergency"] is False
        and payload["to_state"] == "submitted"
    )


def test_list_is_paginated_filtered_and_rejects_unknown_filters(hw) -> None:
    c = crew(hw)
    for i in range(5):
        raise_ticket(
            hw, c.secretary, title=f"Water pressure low on floor {i}", category="water_supply"
        )
    page1 = hw.call(c.secretary, "GET", "/v1/tickets", params={"limit": 2})
    assert (
        page1.status_code == 200 and len(page1.json()["items"]) == 2 and page1.json()["next_cursor"]
    )
    page2 = hw.call(
        c.secretary,
        "GET",
        "/v1/tickets",
        params={"limit": 2, "cursor": page1.json()["next_cursor"]},
    )
    ids = {i["id"] for i in page1.json()["items"]} | {i["id"] for i in page2.json()["items"]}
    assert len(ids) == 4
    assert hw.call(c.secretary, "GET", "/v1/tickets", params={"limit": 101}).status_code == 400
    assert hw.call(c.secretary, "GET", "/v1/tickets", params={"colour": "red"}).status_code == 400
    assert hw.call(c.secretary, "GET", "/v1/tickets", params={"state": "bogus"}).status_code == 400
    only = hw.call(
        c.secretary, "GET", "/v1/tickets", params={"category": "water_supply", "state": "submitted"}
    )
    assert len(only.json()["items"]) == 5
    forged = hw.call(
        c.estate,
        "GET",
        "/v1/tickets",
        params={"limit": 2, "cursor": page1.json()["next_cursor"] + "x"},
    )
    assert forged.status_code == 400
