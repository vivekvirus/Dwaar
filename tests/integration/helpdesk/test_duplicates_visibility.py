"""OPS-02: scopes, common-area status for everyone, duplicate PROPOSALS that never expose another household's complaint."""

from __future__ import annotations

import uuid

import psycopg
import pytest

from dwaar_api.modules.helpdesk import duplicates
from dwaar_api.modules.helpdesk.service import ticket_ref
from tests.integration.helpdesk._flow import act, crew, get, raise_ticket
from tests.integration.helpdesk._support import text_of

pytestmark = pytest.mark.req("OPS-02")

SECRET = (
    "ceiling seepage above the master bedroom, Mrs Kulkarni's fragile medicines are stored there"
)


def private(w, who, unit, title="Ceiling seepage in the bedroom", description=SECRET, **kw):
    return raise_ticket(
        w,
        who,
        scope="private",
        unit_id=str(unit),
        category="plumbing",
        title=title,
        description=description,
        **kw,
    )


def test_duplicate_detection_proposes_links_only_inside_the_same_household(hw) -> None:
    u1, u2 = hw.unit("A-101"), hw.unit("A-102")
    a1 = hw.resident(u1, "owner")
    a2 = hw.resident(u1, "family")
    b = hw.resident(u2, "owner")
    first = private(hw, a1, u1)
    second = private(hw, a2, u1)  # same household files the same thing again
    dup = second["possible_duplicates"]
    assert (
        [d["id"] for d in dup] == [first["ticket"]["id"]]
        and dup[0]["method"] == "trigram"
        and float(dup[0]["similarity"]) >= 0.45
    )
    # another household reports an almost identical complaint: it is NEVER matched with household 1's private ticket
    other = private(
        hw, b, u2, description=SECRET.replace("Mrs Kulkarni's fragile medicines", "my books")
    )
    assert other["possible_duplicates"] == []
    for call in (
        hw.call(b, "GET", f"/v1/tickets/{other['ticket']['id']}"),
        hw.call(b, "GET", "/v1/tickets"),
    ):
        assert "Kulkarni" not in text_of(call) and first["ticket"]["id"] not in text_of(call)
    assert (
        hw.rows("SELECT count(*) FROM ticket_links WHERE ticket_id = %s", (other["ticket"]["id"],))[
            0
        ][0]
        == 0
    )
    # ... and the first household never sees household 2's ticket anywhere
    ids = {i["id"] for i in hw.call(a1, "GET", "/v1/tickets").json()["items"]}
    assert other["ticket"]["id"] not in ids
    assert hw.call(a1, "GET", f"/v1/tickets/{other['ticket']['id']}").status_code == 404


def test_common_area_status_is_shown_to_all_residents_without_private_detail(hw) -> None:
    a = hw.resident(hw.unit("A-101"), "owner")
    b = hw.resident(hw.unit("A-102"), "tenant")
    raised = raise_ticket(
        hw,
        a,
        scope="society",
        category="common_area",
        title="Clubhouse AC is leaking onto the floor",
        description="Drip from the unit, my number is 99999 00123",
    )
    t = raised["ticket"]["id"]
    seen = hw.call(b, "GET", f"/v1/tickets/{t}").json()
    assert (
        seen["ticket"]["title"].startswith("Clubhouse")
        and seen["ticket"]["state"] == "submitted"
        and seen["ticket"]["mine"] is False
    )
    blob = text_of(hw.call(b, "GET", f"/v1/tickets/{t}"))
    for forbidden in ("description", "raised_by", "assignee_id", "photo_refs", "99999 00123"):
        assert forbidden not in blob, forbidden
    assert t in {i["id"] for i in hw.call(b, "GET", "/v1/tickets").json()["items"]}
    # the second resident asking the same thing is told about the first ticket instead of opening a copy
    again = raise_ticket(
        hw,
        b,
        scope="society",
        category="common_area",
        title="Clubhouse AC is leaking onto the floor",
        description="Water dripping",
    )
    assert [d["id"] for d in again["possible_duplicates"]] == [t]
    assert "raised_by" not in str(again["possible_duplicates"]) and "description" not in str(
        again["possible_duplicates"]
    )


def test_block_scope_is_visible_only_to_residents_of_that_block(hw) -> None:
    _block_b, units_b = hw.add_block("B", ("B-1",))
    a = hw.resident(hw.unit("A-101"), "owner")
    b = hw.resident(units_b["B-1"], "owner")
    r = hw.call(
        a,
        "POST",
        "/v1/tickets",
        json={
            "scope": "block",
            "block_id": str(hw.soc.block),
            "category": "cleaning",
            "title": "Stairwell not swept",
        },
    )
    assert r.status_code == 201
    t = r.json()["ticket"]["id"]
    assert hw.call(b, "GET", f"/v1/tickets/{t}").status_code == 404
    assert t not in {i["id"] for i in hw.call(b, "GET", "/v1/tickets").json()["items"]}
    assert hw.call(a, "GET", f"/v1/tickets/{t}").status_code == 200
    wrong = hw.call(
        b,
        "POST",
        "/v1/tickets",
        json={
            "scope": "block",
            "block_id": str(hw.soc.block),
            "category": "cleaning",
            "title": "Not my block",
        },
    )
    assert wrong.status_code == 404


def test_a_hook_cannot_leak_across_households(hw) -> None:
    """The AI-F01 seam: even a proposer that returns another household's ticket id is filtered before storage and output."""
    u1, u2 = hw.unit("A-101"), hw.unit("A-102")
    a, b = hw.resident(u1, "owner"), hw.resident(u2, "owner")
    mine = private(hw, a, u1)["ticket"]["id"]
    theirs = private(hw, b, u2)["ticket"]["id"]

    class Rogue:
        method = "ai_grouping"

        def propose(self, conn, ticket, *, threshold, limit):
            return [duplicates.Proposal(uuid.UUID(theirs), 0.99, self.method)]

    with hw.svc(a, "owner_occ", wide=False, units=(u1,)) as (conn, _ctx, _actor):
        from dwaar_api.modules.helpdesk import service

        ref = ticket_ref(service.fetch_ticket(conn, uuid.UUID(mine)))
        proposals = Rogue().propose(conn, ref, threshold=0.1, limit=5)
        assert duplicates.enforce_same_audience(conn, ref, proposals) == []
    # the database refuses the link itself, whoever writes it
    with (
        hw.idh.db.app_conn(hw.soc.id, a.id, "owner_occ") as conn,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        conn.execute(
            "INSERT INTO ticket_links (society_id, ticket_id, linked_ticket_id, method) VALUES (%s, %s, %s, 'ai_grouping')",
            (hw.soc.id, mine, theirs),
        )


def test_merge_never_crosses_households_and_never_copies_private_text(hw) -> None:
    c = crew(hw)
    u1, u2 = hw.unit("A-101"), hw.unit("A-102")
    a1, a2, b = hw.resident(u1, "owner"), hw.resident(u1, "tenant"), hw.resident(u2, "owner")
    first = private(hw, a1, u1)["ticket"]["id"]
    second = private(hw, a2, u1, description="water from the roof again")["ticket"]["id"]
    theirs = private(hw, b, u2)["ticket"]["id"]
    refused = hw.call(
        c.secretary,
        "POST",
        f"/v1/tickets/{theirs}/merge",
        json={"into_ticket_id": first, "reason": "looks the same"},
    )
    assert (
        refused.status_code == 422
        and refused.json()["code"] == "policy_violation"
        and refused.json()["details"]["reason"] == "merge_scope_mismatch"
    )
    society_level = raise_ticket(hw, c.secretary)["ticket"]["id"]
    assert (
        hw.call(
            c.secretary,
            "POST",
            f"/v1/tickets/{first}/merge",
            json={"into_ticket_id": society_level, "reason": "different scope"},
        ).status_code
        == 422
    )
    ok = act(
        hw,
        c.secretary,
        second,
        "merge",
        {"into_ticket_id": first, "reason": "same leak, same flat"},
    )
    assert ok["ticket"]["id"] == first  # the surviving ticket is returned
    merged = get(hw, a2, second)["ticket"]
    assert (
        merged["state"] == "closed"
        and merged["closed_basis"] == "merged"
        and merged["merged_into"] == first
    )
    survivor = text_of(hw.call(a1, "GET", f"/v1/tickets/{first}"))
    assert "water from the roof again" not in survivor  # the merged ticket's words are not copied
    # another household learns nothing of either ticket
    assert hw.call(b, "GET", f"/v1/tickets/{first}").status_code == 404
    assert hw.call(b, "GET", f"/v1/tickets/{second}").status_code == 404
    assert hw.outbox("TicketMerged", second)[0]["payload"]["merged_into"] == first
    act(hw, c.secretary, second, "merge", {"into_ticket_id": first, "reason": "again"}, expect=409)
    # a household cannot merge anything
    assert (
        hw.call(
            a1, "POST", f"/v1/tickets/{first}/merge", json={"into_ticket_id": first, "reason": "no"}
        ).status_code
        == 403
    )
    assert (
        hw.call(
            c.secretary,
            "POST",
            f"/v1/tickets/{first}/merge",
            json={"into_ticket_id": first, "reason": "self"},
        ).status_code
        == 400
    )


def test_non_resident_owner_sees_only_the_tickets_that_person_raised(hw) -> None:
    u = hw.unit("A-101")
    tenant = hw.resident(u, "tenant")
    nr_owner = hw.resident(u, "owner", lives=False)
    t = private(hw, tenant, u)["ticket"]["id"]
    assert hw.call(nr_owner, "GET", f"/v1/tickets/{t}").status_code == 404
    assert hw.call(nr_owner, "GET", "/v1/tickets").json()["items"] == []
    own = private(hw, nr_owner, u, title="Rent related repair request", description="roof tiles")
    assert hw.call(nr_owner, "GET", f"/v1/tickets/{own['ticket']['id']}").status_code == 200
    assert hw.call(nr_owner, "POST", f"/v1/tickets/{t}/confirm", json={}).status_code == 404


def test_privacy_tickets_are_never_proposed_or_matched(hw) -> None:
    u = hw.unit("A-101")
    a = hw.resident(u, "owner")
    first = hw.call(
        a,
        "POST",
        f"/v1/societies/{hw.soc.id}/support-requests",
        json={"title": "Please delete my family photo", "description": "privacy issue"},
    )
    again = hw.call(
        a,
        "POST",
        f"/v1/societies/{hw.soc.id}/support-requests",
        json={"title": "Please delete my family photo", "description": "privacy issue"},
    )
    assert first.status_code == again.status_code == 201
    assert hw.rows("SELECT count(*) FROM ticket_links")[0][0] == 0
