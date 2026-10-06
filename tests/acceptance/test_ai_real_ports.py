"""AI-F01 (ticket triage) and AI-G08 (shift handover summary) against the REAL helpdesk and shift services, with the labelled SIMULATOR provider only.

REQ: AI-F01, AI-G08, SHIFT-02 (a summary is shown above the deterministic open-items list, which is always present), INV-06 (AI proposes, deterministic
services execute), AI-SYS-04 (revalidation at confirmation), INV-01. Class B: nothing changes until a person confirms the proposal.

Not an AT scenario of its own (no ``at`` marker: it must not add evidence to AT-25/26): it closes the integration item "hook the ports to the real
modules". Dataset: the real seed; real API, real tokens and Postgres; the model is the deterministic simulator (``simulation=true``): NO model quality
is measured here, the tests prove WIRING, authority and honesty of labels.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.acceptance._world import World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.req("SHIFT-02", "INV-06", "AI-SYS-04", "INV-01"),
]


def _h(society: Any) -> dict[str, str]:
    return {"X-Society-Id": str(society.id)}


def _raise_ticket(
    world: World, who: Any, society: Any, title: str, description: str, **extra: Any
) -> dict[str, Any]:
    r = world.call(
        who, "POST", "/v1/tickets",
        json={"scope": "society", "category": "common_area", "title": title, "description": description, **extra},
        headers=_h(society),
    )  # fmt: skip
    assert r.status_code == 201, r.text
    t: dict[str, Any] = r.json()["ticket"]
    return t


def _ticket(world: World, who: Any, society: Any, ticket_id: str) -> dict[str, Any]:
    r = world.call(who, "GET", f"/v1/tickets/{ticket_id}", headers=_h(society))
    assert r.status_code == 200, r.text
    t: dict[str, Any] = r.json()["ticket"]
    return t


def _ask(world: World, who: Any, society: Any, feature: str, inputs: dict[str, Any]) -> Any:
    return world.call(
        who, "POST", "/v1/ai/proposals", json={"feature_id": feature, "inputs": inputs}, headers=_h(society)
    )  # fmt: skip


def _confirm(world: World, who: Any, society: Any, proposal: dict[str, Any]) -> Any:
    return world.call(
        who, "POST", f"/v1/ai/proposals/{proposal['id']}/confirm",
        json={"payload_hash": proposal["payload_hash"]}, headers=_h(society),
    )  # fmt: skip


def test_the_runtime_the_app_builds_carries_the_real_sources_and_ports(world: World) -> None:
    from dwaar_api.modules.ai import adapters
    from dwaar_api.modules.ai.ports import AiRuntime

    rt = world.app.state.ai
    assert isinstance(rt, AiRuntime)
    assert isinstance(rt.sources["AI-F01"], adapters.HelpdeskTicketSource)
    assert isinstance(rt.sources["AI-G08"], adapters.ShiftEventSource)
    assert isinstance(rt.ports["ticket_triage"], adapters.TicketTriagePort)
    assert isinstance(rt.ports["shift_handover"], adapters.ShiftHandoverPort)
    assert rt.gateway.config.provider == "simulator"  # no key, no network: the labelled simulator


# ------------------------------------------------------------------------------------------------------------ AI-F01
def test_a_confirmed_triage_goes_through_the_helpdesk_service_and_an_unconfirmed_one_changes_nothing(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh = world.society_ref("mh")
    sec = world.login("mh.secretary")
    tenant = world.login("neha")
    t = _raise_ticket(
        world,
        tenant,
        mh,
        "Lift stuck between floors",
        "The lift in block A is stuck and making a noise",
        category="lift",
    )
    assert t["state"] == "submitted"
    before = _ticket(world, sec, mh, t["id"])
    r = _ask(world, sec, mh, "AI-F01", {"ticket_ids": [t["id"]]})
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    body = r.json()
    assert (
        body["simulation"] is True
        and body["labels"]["ai_draft"] is True
        and body["labels"]["simulation"] is True
    )
    proposal = body["proposal"]
    assert proposal["command"] == "ticket.apply_triage" and proposal["risk_class"] == "B"
    assert proposal["target_ids"] == [t["id"]] and proposal["target_versions"] == [
        before["version"]
    ]
    # class B: until a person confirms, the ticket is exactly as it was
    assert _ticket(world, sec, mh, t["id"]) == before
    assert world.admin_rows(
        "SELECT count(*) FROM ticket_events WHERE ticket_id = %s AND kind = 'triaged'", (t["id"],)
    ) == [(0,)]

    ok = _confirm(world, sec, mh, proposal)
    assert ok.status_code == 200 and ok.json()["state"] == "confirmed", ok.text
    receipt = ok.json()["result"]
    assert (
        receipt["via"] == "ticket_triage"
        and receipt["merged"] == 0
        and receipt["team_applied"] is False
    )
    assert [a["ticket_id"] for a in receipt["applied"]] == [t["id"]] and receipt["skipped"] == []
    after = _ticket(world, sec, mh, t["id"])
    assert after["state"] == "triaged" and after["version"] == before["version"] + 1
    # the helpdesk's own history, audit and outbox: the same trail as the staff screen
    note = world.admin_rows(
        "SELECT note FROM ticket_events WHERE ticket_id = %s AND kind = 'triaged'", (t["id"],)
    )
    assert (
        len(note) == 1
        and "AI-F01 suggestion confirmed by a person" in note[0][0]
        and "team suggested" in note[0][0]
    )
    assert world.admin_rows(
        "SELECT count(*) FROM audit_log WHERE operation = 'ticket.triage' AND object_id = %s",
        (t["id"],),
    ) == [(1,)]
    assert world.admin_rows(
        "SELECT count(*) FROM outbox WHERE event_type = 'TicketTriaged' AND aggregate_id = %s",
        (t["id"],),
    ) == [(1,)]
    # a second confirmation of the same proposal executes nothing again (decided proposals never change state)
    again = _confirm(world, sec, mh, proposal)
    assert again.status_code == 409 and again.json()["code"] == "already_decided"
    assert _ticket(world, sec, mh, t["id"])["version"] == after["version"]


def test_a_triage_proposal_goes_stale_when_the_ticket_changes_and_a_new_one_is_required(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh = world.society_ref("mh")
    sec = world.login("mh.secretary")
    t = _raise_ticket(
        world,
        world.login("neha"),
        mh,
        "Water tank overflow",
        "The overhead tank overflows every morning",
        category="water_supply",
    )
    proposal = _ask(world, sec, mh, "AI-F01", {"ticket_ids": [t["id"]]}).json()["proposal"]
    ack = world.call(
        sec,
        "POST",
        f"/v1/tickets/{t['id']}/acknowledge",
        json={"expected_version": proposal["target_versions"][0]},
        headers=_h(mh),
    )
    assert ack.status_code == 200, ack.text
    late = _confirm(world, sec, mh, proposal)
    assert late.status_code == 409 and late.json()["code"] == "stale_version"
    assert late.json()["details"]["new_proposal_required"] is True
    assert world.admin_rows(
        "SELECT count(*) FROM ticket_events WHERE ticket_id = %s AND kind = 'triaged'", (t["id"],)
    ) == [(0,)]
    fresh = _ask(world, sec, mh, "AI-F01", {"ticket_ids": [t["id"]]}).json()["proposal"]
    assert fresh["id"] != proposal["id"] and fresh["target_versions"] == [
        proposal["target_versions"][0] + 1
    ]
    assert _confirm(world, sec, mh, fresh).status_code == 200


def test_triage_sees_only_what_the_caller_may_see_and_never_another_societys_ticket(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh, ka = world.society_ref("mh"), world.society_ref("ka")
    mine = _raise_ticket(
        world,
        world.login("neha"),
        mh,
        "Garden lights out",
        "The garden lights are out again",
        category="electrical",
    )
    ka_sec = world.login("ka.secretary")
    # society B's secretary names society A's ticket: no source, so no proposal and nothing of A in the answer
    r = _ask(world, ka_sec, ka, "AI-F01", {"ticket_ids": [mine["id"]]})
    assert r.status_code == 404 and r.json()["code"] == "not_found", r.text
    unknown = _ask(world, ka_sec, ka, "AI-F01", {"ticket_ids": [str(uuid.uuid4())]})
    assert (unknown.status_code, unknown.json()["code"]) == (404, "not_found"), (
        "identical to an id that does not exist"
    )
    assert "Garden lights" not in r.text and mine["id"] not in r.text
    # a resident may not use the staff triage feature at all, whatever tickets they name
    resident = world.login("neha")
    mine_again = _ask(world, resident, mh, "AI-F01", {"ticket_ids": [mine["id"]]})
    assert mine_again.status_code == 403, mine_again.text
    assert world.admin_rows(
        "SELECT count(*) FROM ticket_events WHERE kind = 'triaged' AND ticket_id = %s",
        (mine["id"],),
    ) == [(0,)]


# ------------------------------------------------------------------------------------------------------------ AI-G08
def _ended_shift_of_a(world: World) -> tuple[str, str]:
    row = world.admin_rows(
        "SELECT h.outgoing_shift_id, h.id FROM shift_handovers h JOIN shifts s ON s.id = h.outgoing_shift_id"
        " JOIN societies c ON c.id = h.society_id WHERE c.state = 'Maharashtra' AND h.summary_text IS NULL ORDER BY s.planned_start LIMIT 1"
    )[0]
    return str(row[0]), str(row[1])


def test_a_confirmed_handover_summary_is_shown_above_the_unchanged_open_items(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh = world.society_ref("mh")
    sup = world.login("mh.guard_sup")
    shift_id, handover_id = _ended_shift_of_a(world)
    before = world.call(sup, "GET", f"/v1/handovers/{handover_id}", headers=_h(mh)).json()
    assert "summary" not in before and before["display_order"] == ["open_items"]
    r = _ask(world, sup, mh, "AI-G08", {"shift_id": shift_id})
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    body = r.json()
    assert (
        body["simulation"] is True
        and body["labels"]["ai_draft"] is True
        and body["labels"]["simulation"] is True
    )
    proposal = body["proposal"]
    assert proposal["command"] == "shift.save_handover" and proposal["risk_class"] == "B"
    # nothing is saved by asking
    assert (
        "summary"
        not in world.call(sup, "GET", f"/v1/handovers/{handover_id}", headers=_h(mh)).json()
    )
    ok = _confirm(world, sup, mh, proposal)
    assert ok.status_code == 200 and ok.json()["result"]["open_items_unchanged"] is True, ok.text
    after = world.call(sup, "GET", f"/v1/handovers/{handover_id}", headers=_h(mh)).json()
    assert after["display_order"] == ["summary", "open_items"], (
        "the summary is above the deterministic list"
    )
    assert after["summary"]["advisory"] is True and after["summary"]["source"] == "ai_gateway"
    assert after["open_items"] == before["open_items"], (
        "the deterministic open items were not touched, replaced or filtered"
    )
    # the same confirmation again writes nothing twice
    versions = world.admin_rows("SELECT version FROM shift_handovers WHERE id = %s", (handover_id,))
    assert _confirm(world, sup, mh, proposal).status_code == 409
    assert (
        world.admin_rows("SELECT version FROM shift_handovers WHERE id = %s", (handover_id,))
        == versions
    )


def test_a_summary_never_replaces_a_critical_open_item_and_cannot_come_from_another_society(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh, ka = world.society_ref("mh"), world.society_ref("ka")
    shift_id, handover_id = _ended_shift_of_a(world)
    # society B's supervisor names society A's shift: the source returns nothing, nothing of A can reach the model or the answer
    ka_sup = world.login("ka.guard_sup")
    r = _ask(world, ka_sup, ka, "AI-G08", {"shift_id": shift_id})
    assert r.status_code == 404 and r.json()["code"] == "not_found", r.text
    unknown = _ask(world, ka_sup, ka, "AI-G08", {"shift_id": str(uuid.uuid4())})
    assert (unknown.status_code, unknown.json()["code"]) == (404, "not_found")
    # the deterministic open items of A are unchanged whatever B did
    assert world.admin_rows(
        "SELECT summary_text IS NULL FROM shift_handovers WHERE id = %s", (handover_id,)
    ) == [(True,)]
    # and an unfinished shift has no handover yet: confirming a summary for it is refused, nothing invented
    active = world.admin_rows(
        "SELECT id FROM shifts WHERE society_id = %s AND state = 'active' LIMIT 1", (mh.id,)
    )[0][0]
    sup = world.login("mh.guard_sup")
    live = _ask(world, sup, mh, "AI-G08", {"shift_id": str(active)})
    assert live.status_code == 200, live.text
    if live.json()["proposal"]:
        refused = _confirm(world, sup, mh, live.json()["proposal"])
        assert (
            refused.status_code == 422
            and refused.json()["details"]["reason"] == "handover_not_created_yet"
        )
        assert world.admin_rows(
            "SELECT count(*) FROM shift_handovers WHERE summary_text IS NOT NULL"
        ) == [(0,)]


def test_the_ai_module_does_not_make_the_gateway_depend_on_the_api() -> None:
    """The dependency points one way: the API module imports the gateway, never the other way round (and the API package declares it)."""
    import pathlib
    import tomllib

    root = pathlib.Path(__file__).resolve().parents[2]
    import re

    imports_api = re.compile(r"^\s*(from|import)\s+dwaar_api\b", re.MULTILINE)
    offenders = [
        str(p)
        for p in (root / "services/ai-gateway/dwaar_ai_gateway").rglob("*.py")
        if imports_api.search(p.read_text())
    ]
    assert offenders == [], "the gateway must not import the API"
    api = tomllib.loads((root / "services/api/pyproject.toml").read_text())
    assert "dwaar-ai-gateway" in api["project"]["dependencies"]
    assert api["tool"]["uv"]["sources"]["dwaar-ai-gateway"] == {"workspace": True}
    gw = tomllib.loads((root / "services/ai-gateway/pyproject.toml").read_text())
    assert "dwaar-api" not in " ".join(gw["project"]["dependencies"])


def test_an_emergency_suggestion_is_never_applied_from_the_ai_port_and_says_so(
    fresh_world: World,
) -> None:
    """The proposal flags an emergency for SEPARATE human review; the port keeps that promise: the category is applied, the emergency priority is not."""
    world = fresh_world
    mh = world.society_ref("mh")
    sec = world.login("mh.secretary")
    t = _raise_ticket(
        world, world.login("neha"), mh, "Gas smell near the lift", "There is a strong smell of gas near the lift lobby", category="other"
    )  # fmt: skip
    before = _ticket(world, sec, mh, t["id"])
    proposal = _ask(world, sec, mh, "AI-F01", {"ticket_ids": [t["id"]]}).json()["proposal"]
    suggestion = proposal["payload"]["results"][0]
    assert suggestion["priority"] == "emergency" and suggestion["needs_emergency_review"] is True
    done = _confirm(world, sec, mh, proposal)
    assert done.status_code == 200, done.text
    [applied] = done.json()["result"]["applied"]
    assert (
        applied["held_back"] == "emergency_requires_separate_human_review"
        and applied["priority"] is None
    )
    after = _ticket(world, sec, mh, t["id"])
    assert after["priority"] == before["priority"], (
        "the priority was decided by the helpdesk's own hazard rules, not by this port"
    )
