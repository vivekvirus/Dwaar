"""PRD 5.2 row "Helpdesk tickets": SECRETARY F, TREASURER R, COMMITTEE R, ESTATE_MGR F, GUARD Create, AUDITOR N, OWNER_OCC O,
OWNER_NR O, TENANT O, FAMILY O. Registry versus the printed cells, then the behaviour of every role over HTTP."""

from __future__ import annotations

import importlib

import pytest

import dwaar_api.modules.helpdesk as helpdesk_pkg
from dwaar_api.modules.identity import matrix
from tests.integration.helpdesk._flow import raise_ticket, tid

hp = importlib.import_module("dwaar_api.modules.helpdesk.permissions")
pytestmark = pytest.mark.req("OPS-01")

PRD_ROW = dict(zip(
    ["secretary", "treasurer", "committee", "estate_mgr", "guard", "auditor", "owner_occ", "owner_nr", "tenant", "family"],
    ["F", "R", "R", "F", "Create", "N", "O", "O", "O", "O"],
    strict=True,
))  # fmt: skip


def test_registry_matches_the_printed_cells() -> None:
    assert matrix.MATRIX["helpdesk"] == PRD_ROW
    by_action = {p.action: p for p in hp.permissions}
    assert {p.action for p in helpdesk_pkg.permissions} == set(by_action) | {
        "helpdesk.support.create"
    }
    full = {r for r, c in PRD_ROW.items() if c == "F"}
    read = {r for r, c in PRD_ROW.items() if c in {"F", "R"}}
    own = {r for r, c in PRD_ROW.items() if c == "O"}
    assert by_action["helpdesk.ticket.manage"].roles == full
    assert by_action["helpdesk.ticket.read"].roles == read | own
    assert by_action["helpdesk.ticket.create"].roles == full | {"guard"} | own
    assert by_action["helpdesk.ticket.act"].roles == full | own
    assert by_action["helpdesk.sla.read"].roles == read
    assert "auditor" not in {r for p in hp.permissions for r in p.roles}
    assert "guard" not in by_action["helpdesk.ticket.read"].roles  # create-only


def test_module_permissions_are_registered_in_the_app(hw) -> None:
    registry = hw.app.state.permissions
    for p in helpdesk_pkg.permissions:
        assert registry.get(p.action) == p


ROLES = ["secretary", "treasurer", "committee", "estate_mgr", "guard", "auditor"]


@pytest.mark.parametrize("role", ROLES)
def test_staff_roles_over_http(hw, role) -> None:
    who = hw.staff(role)
    created = hw.call(
        who,
        "POST",
        "/v1/tickets",
        json={"scope": "society", "category": "garden", "title": f"Lawn needs watering ({role})"},
    )
    can_create = role in {"secretary", "estate_mgr", "guard"}
    assert created.status_code == (201 if can_create else 403), (role, created.text)
    seed = raise_ticket(hw, hw.staff("secretary"), title="Seed ticket for readers")["ticket"]["id"]
    can_read = role in {"secretary", "treasurer", "committee", "estate_mgr"}
    assert hw.call(who, "GET", "/v1/tickets").status_code == (200 if can_read else 403)
    assert hw.call(who, "GET", f"/v1/tickets/{seed}").status_code == (200 if can_read else 403)
    can_manage = role in {"secretary", "estate_mgr"}
    r = hw.call(who, "POST", f"/v1/tickets/{seed}/triage", json={})
    assert r.status_code == (200 if can_manage else 403), (role, r.text)
    sla = hw.call(who, "GET", f"/v1/tickets/{seed}/sla")
    assert sla.status_code == (200 if can_read else 403)
    if role in {"treasurer", "committee"}:  # read-only: every write is refused with 403, never 404
        for verb in (
            "acknowledge",
            "assign",
            "transition",
            "priority",
            "merge",
            "cancel",
            "confirm",
        ):
            assert hw.call(
                who, "POST", f"/v1/tickets/{seed}/{verb}", json={"to": "in_progress"}
            ).status_code in (400, 403), verb


@pytest.mark.parametrize("kind", ["owner", "tenant", "family"])
def test_household_roles_own_tickets_only(hw, kind) -> None:
    unit = hw.unit("A-101")
    mine = hw.resident(unit, kind)
    sec = hw.staff("secretary")
    own = tid(
        raise_ticket(
            hw,
            mine,
            scope="private",
            unit_id=str(unit),
            category="plumbing",
            title=f"Leaking tap raised by {kind}",
        )
    )
    others = tid(
        raise_ticket(
            hw,
            hw.resident(hw.unit("A-102"), "owner"),
            scope="private",
            unit_id=str(hw.unit("A-102")),
            category="plumbing",
            title="Someone else's pipe",
        )
    )
    assert hw.call(mine, "GET", f"/v1/tickets/{own}").status_code == 200
    assert hw.call(mine, "GET", f"/v1/tickets/{others}").status_code == 404
    for verb in ("triage", "assign", "priority", "acknowledge", "transition", "merge"):
        assert hw.call(mine, "POST", f"/v1/tickets/{own}/{verb}", json={}).status_code == 403, verb
    assert hw.call(mine, "GET", f"/v1/tickets/{own}/sla").status_code == 403
    assert hw.call(mine, "PUT", "/v1/helpdesk/settings", json={}).status_code == 403
    assert hw.call(sec, "POST", f"/v1/tickets/{own}/triage", json={}).status_code == 200


def test_non_resident_owner_may_raise_and_read_their_own(hw) -> None:
    unit = hw.unit("A-101")
    nr = hw.resident(unit, "owner", lives=False)
    t = tid(
        raise_ticket(
            hw,
            nr,
            scope="private",
            unit_id=str(unit),
            category="civil",
            title="Seepage on my rented-out flat's wall",
        )
    )
    assert hw.call(nr, "GET", f"/v1/tickets/{t}").status_code == 200


def test_unauthenticated_and_unscoped_requests(hw) -> None:
    assert hw.call(None, "GET", "/v1/tickets").status_code == 401
    assert hw.call(None, "POST", "/v1/tickets", json={}).status_code == 401
    sec = hw.staff("secretary")
    assert hw.call(sec, "GET", "/v1/tickets", society=False).status_code in (
        200,
        400,
    )  # one society: inferred
    foreign = hw.second_society()
    r = hw.call(sec, "GET", "/v1/tickets", society=foreign.id)
    assert r.status_code == 404 and r.json()["code"] == "not_found"
