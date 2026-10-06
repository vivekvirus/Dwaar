"""PRD 5.2 row "Notices": SECRETARY F, TREASURER R, COMMITTEE Draft, ESTATE_MGR Draft, GUARD N, AUDITOR N, OWNER_OCC R, OWNER_NR R,
TENANT R, FAMILY R. Registry versus the printed cells, then the behaviour of every role over HTTP."""

from __future__ import annotations

import importlib

import pytest

import dwaar_api.modules.community as community_pkg
from dwaar_api.modules.identity import matrix
from tests.integration.community._flow import crew, draft, published

cp = importlib.import_module("dwaar_api.modules.community.permissions")
pytestmark = pytest.mark.req("COM-01")

PRD_ROW = dict(zip(
    ["secretary", "treasurer", "committee", "estate_mgr", "guard", "auditor", "owner_occ", "owner_nr", "tenant", "family"],
    ["F", "R", "Draft", "Draft", "N", "N", "R", "R", "R", "R"],
    strict=True,
))  # fmt: skip


def test_registry_matches_the_printed_cells() -> None:
    assert matrix.MATRIX["notices"] == PRD_ROW
    by = {p.action: p for p in cp.permissions}
    assert {p.action for p in community_pkg.permissions} == set(by)
    readers = {r for r, cell in PRD_ROW.items() if cell != "N"}
    drafters = {r for r, cell in PRD_ROW.items() if cell in {"F", "Draft"}}
    assert (
        by["notice.read"].roles == readers
        and by["document.read"].roles == readers
        and by["poll.read"].roles == readers
    )
    assert (
        by["notice.draft"].roles
        == drafters
        == by["document.draft"].roles
        == by["poll.draft"].roles
        == by["notice.receipts.read"].roles
    )
    assert (
        by["notice.manage"].roles
        == {"secretary"}
        == by["document.manage"].roles
        == by["poll.manage"].roles
    )
    assert by["poll.respond"].roles == {"owner_occ", "owner_nr", "tenant", "family"}
    assert by["notice.emergency"].roles == {"secretary", "estate_mgr", "guard_sup"}
    for p in cp.permissions:
        assert "auditor" not in p.roles and "guard" not in p.roles  # N cells


def test_module_permissions_are_registered_in_the_app(cw) -> None:
    for p in community_pkg.permissions:
        assert cw.app.state.permissions.get(p.action) == p


ROLES = ["secretary", "treasurer", "committee", "estate_mgr", "guard", "auditor"]


@pytest.mark.parametrize("role", ROLES)
def test_staff_roles_over_http(cw, role) -> None:
    c = crew(cw)
    who = cw.staff(role)
    seed = published(cw, c, title="Seed notice for readers")
    can_read = role in {"secretary", "treasurer", "committee", "estate_mgr"}
    assert cw.call(who, "GET", "/v1/notices").status_code == (200 if can_read else 403)
    assert cw.call(who, "GET", f"/v1/notices/{seed['id']}").status_code == (
        200 if can_read else 403
    )
    can_draft = role in {"secretary", "committee", "estate_mgr"}
    r = cw.call(
        who,
        "POST",
        "/v1/notices",
        json={"title": f"Draft by {role}", "body": "A body of sufficient length."},
    )
    assert r.status_code == (201 if can_draft else 403), (role, r.text)
    d = draft(cw, c.committee, title="Another draft for approval")
    ap = cw.call(who, "POST", f"/v1/notices/{d['id']}/approve", json={})
    assert ap.status_code == (200 if role == "secretary" else 403), (role, ap.text)
    assert cw.call(who, "GET", f"/v1/notices/{seed['id']}/receipts").status_code == (
        200 if can_draft else 403
    )
    assert cw.call(who, "GET", f"/v1/notices/{seed['id']}/deliveries").status_code == (
        200 if can_draft else 403
    )
    # drafts are visible to the drafting roles only (the treasurer reads published notices)
    seen = cw.call(who, "GET", f"/v1/notices/{d['id']}").status_code
    assert seen == (200 if can_draft else (404 if can_read else 403))
    assert cw.call(
        who, "POST", f"/v1/notices/{seed['id']}/archive", json={"reason": "no longer needed"}
    ).status_code == (200 if role == "secretary" else 403)
    for path in ("/v1/documents", "/v1/polls"):
        assert cw.call(who, "GET", path).status_code == (200 if can_read else 403), (role, path)


@pytest.mark.parametrize("kind", ["owner", "tenant", "family"])
def test_household_roles_read_publish_nothing(cw, kind) -> None:
    c = crew(cw)
    who = cw.resident(cw.unit("A-101"), kind)
    seed = published(cw, c)
    assert cw.call(who, "GET", f"/v1/notices/{seed['id']}").status_code == 200
    assert (
        cw.call(
            who, "POST", f"/v1/notices/{seed['id']}/receipts", json={"kind": "acknowledged"}
        ).status_code
        == 201
    )
    for method, path, body in (
        (
            "POST",
            "/v1/notices",
            {"title": "Resident notice", "body": "Residents cannot post notices."},
        ),
        ("POST", f"/v1/notices/{seed['id']}/approve", {}),
        ("POST", f"/v1/notices/{seed['id']}/publish", {}),
        (
            "POST",
            f"/v1/notices/{seed['id']}/revisions",
            {"title": "Edit", "body": "Residents cannot revise notices."},
        ),
        ("PATCH", f"/v1/notices/{seed['id']}", {"title": "Edited by resident"}),
        (
            "POST",
            f"/v1/notices/{seed['id']}/translations",
            {"language": "hi", "title": "शीर्षक यहाँ", "body": "पाठ यहाँ है"},
        ),
        (
            "POST",
            "/v1/emergency-broadcasts",
            {"message": "A resident cannot raise an emergency broadcast"},
        ),
        (
            "POST",
            "/v1/documents",
            {"doc_type": "circular", "title": "Resident document", "authority": "Me"},
        ),
        ("POST", "/v1/polls", {"question": "A poll made by a resident?", "options": ["Yes", "No"]}),
        ("GET", f"/v1/notices/{seed['id']}/receipts", None),
    ):
        assert cw.call(who, method, path, json=body).status_code == 403, (method, path)


def test_unauthenticated_and_foreign_society_requests(cw) -> None:
    for path in ("/v1/notices", "/v1/documents", "/v1/polls"):
        assert cw.call(None, "GET", path).status_code == 401
    assert cw.call(None, "POST", "/v1/emergency-broadcasts", json={}).status_code == 401
    sec = cw.staff("secretary")
    foreign = cw.second_society()
    for path in ("/v1/notices", "/v1/documents", "/v1/polls"):
        r = cw.call(sec, "GET", path, society=foreign.id)
        assert r.status_code == 404 and r.json()["code"] == "not_found"


def test_community_is_not_a_social_feed_and_has_no_amenity_booking(cw) -> None:
    """PRD 2: no open social feed; AMEN is M2. Nothing here must look like either."""
    from dwaar_api.core.authz import iter_api_routes

    paths = {r.path for r in iter_api_routes(cw.app)}
    assert not {
        p
        for p in paths
        if any(w in p for w in ("amenit", "booking", "feed", "comment", "like", "post"))
    }
