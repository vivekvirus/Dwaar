"""Visitor history of a unit (AT-02 endpoint) and the visit register, for EVERY role of PRD 5.2 "Gate operations".

REQ: GATE-13, INV-04, INV-01, IAM-04, PRD 5.2.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

import pytest

from dwaar_api.modules.identity import matrix
from dwaar_api.modules.visits import (
    permissions as visit_permissions,
)  # the module's tuple of Permission
from tests.integration.identity._support import Person
from tests.integration.visits._support import VW

pytestmark = [pytest.mark.req("GATE-13", "INV-04")]

PURPOSE = {"purpose": "Security review of a complaint"}


class Scene:
    def __init__(self, vw: VW) -> None:
        self.vw = vw
        vw.setup_gate()
        self.a = vw.household("A-101", tenant=True, nr_owner=True)
        self.b = vw.household("A-102")
        self.gate = vw.gate_id
        # A-101: one visitor inside, one denied, one still pending; A-102: one inside
        self.inside = self._inside(self.a, "Inside Guest")
        denied = vw.raise_request(self.a.unit, visitor_alias="Denied Guest")
        vw.decide(self.a.owner, denied, "deny")
        self.denied_visit = denied["visit_id"]
        self.pending = vw.raise_request(self.a.unit, visitor_alias="Pending Guest")
        self.other = self._inside(self.b, "Other Household Guest")
        # a multi-destination delivery: A-102 first, then A-101
        first = vw.raise_request(self.b.unit, kind="delivery", visitor_alias="Courier")
        vw.decide(self.b.owner, first)
        visit = vw.call(
            vw.guard, "GET", f"/v1/visits/{first['visit_id']}", params={"gate_id": str(self.gate)}
        ).json()
        second = vw.call(
            vw.guard, "POST", f"/v1/visits/{first['visit_id']}/stops",
            json={"unit_id": str(self.a.unit), "destination_confirmed": True, "expected_version": visit["version"]},
        ).json()  # fmt: skip
        vw.decide(self.a.owner, second)
        self.multi = first["visit_id"]

    def _inside(self, h: Any, alias: str) -> str:
        req = self.vw.raise_request(h.unit, visitor_alias=alias, visitor_phone="+919999900555")
        self.vw.decide(h.owner, req)
        self.vw.observe(req["visit_id"], "entry")
        return str(req["visit_id"])

    def history(self, who: Person, unit: uuid.UUID | None = None, **params: Any) -> Any:
        return self.vw.call(
            who, "GET", self.vw.s(f"units/{unit or self.a.unit}/visits"), params=params
        )


@pytest.fixture
def scene(vw: VW) -> Scene:
    return Scene(vw)


def _staff(vw: VW, role: str) -> Person:
    who = vw.person()
    vw.idh.seed_grant(
        vw.soc.id,
        who.id,
        role,
        expires="30 days" if role in ("auditor", "plat_support", "vendor_tech") else None,
    )
    if role in matrix.ELEVATED_ROLES:
        vw.idh.elevate_session(who)
    return who


@pytest.mark.parametrize("member", ["owner", "tenant", "family"])
def test_the_household_reads_its_own_unit_history(scene: Scene, member: str) -> None:
    who = getattr(scene.a, member)
    r = scene.history(who)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["view"] == "household" and body["unit_id"] == str(scene.a.unit)
    ids = {i["id"] for i in body["items"]}
    assert ids == {scene.inside, scene.denied_visit, scene.pending["visit_id"], scene.multi}
    assert scene.other not in ids  # another household's visitor is not in this unit's history
    by_id = {i["id"]: i for i in body["items"]}
    assert (
        by_id[scene.inside]["state"] == "inside"
        and by_id[scene.inside]["inside_confidence"] == "observed"
    )
    assert by_id[scene.denied_visit]["state"] == "cancelled"
    # the multi-destination delivery shows ONLY this household's stop (the courier's other destination is not ours to see)
    assert [s["unit_label"] for s in by_id[scene.multi]["stops"]] == ["A-101"]
    text = r.text
    assert "visitor_contact_token" not in text and "9999900555" not in text and "A-102" not in text
    assert not any(k in text for k in ("invitation_id", "consent_recorded"))


def test_a_non_resident_owner_is_refused_and_so_is_every_role_the_matrix_denies(
    scene: Scene,
) -> None:
    vw = scene.vw
    assert scene.history(scene.a.nr_owner).status_code == 403  # type: ignore[arg-type]
    assert scene.history(scene.a.nr_owner).json()["code"] == "not_authorised"  # type: ignore[arg-type]
    for role in ("treasurer", "auditor"):
        who = _staff(vw, role)
        r = scene.history(who, **PURPOSE)
        assert r.status_code == 403 and r.json()["code"] == "not_authorised", role
    # a person whose ONLY standing is non-resident ownership of another unit
    other_nr = vw.resident(vw.unit("B-201"), "owner", lives=False)
    tenant_b = vw.resident(vw.unit("B-201"), "tenant")
    assert scene.history(other_nr, vw.unit("B-201")).status_code == 403
    assert vw.call(tenant_b, "GET", vw.s(f"units/{vw.unit('B-201')}/visits")).status_code == 200
    # an owner who LIVES elsewhere and rents this unit out: the target is outside the grants that qualify -> 404
    sanjay = vw.resident(vw.unit("B-202"), "owner")
    vw.idh.seed_membership(vw.soc.id, sanjay.id, vw.unit("C-301"), "owner", lives=False)
    assert scene.history(sanjay, vw.unit("C-301")).status_code == 404
    assert scene.history(sanjay, vw.unit("B-202")).status_code == 200


def test_other_households_strangers_and_other_societies_get_404(scene: Scene) -> None:
    vw = scene.vw
    assert scene.history(scene.b.owner).status_code == 404
    assert scene.history(scene.b.family).status_code == 404  # type: ignore[arg-type]
    assert scene.history(vw.person()).status_code == 404
    other = vw.idh.society("Elsewhere", units=("Z-1",))
    foreign_secretary = vw.person()
    vw.idh.seed_grant(other.id, foreign_secretary.id, "secretary")
    vw.idh.elevate_session(foreign_secretary)
    r = vw.call(
        foreign_secretary,
        "GET",
        f"/v1/societies/{vw.soc.id}/units/{scene.a.unit}/visits",
        params=PURPOSE,
    )
    assert r.status_code == 404
    unknown = vw.call(scene.a.owner, "GET", vw.s(f"units/{uuid.uuid4()}/visits"))
    assert unknown.status_code == 404
    # a unit of ANOTHER society used in my society's path
    assert (
        vw.call(scene.a.owner, "GET", vw.s(f"units/{other.units['Z-1']}/visits")).status_code == 404
    )
    assert (
        vw.call(
            vw.secretary, "GET", vw.s(f"units/{other.units['Z-1']}/visits"), params=PURPOSE
        ).status_code
        == 404
    )


@pytest.mark.parametrize("role", ["secretary", "committee", "estate_mgr"])
def test_society_roles_read_with_a_purpose_and_the_read_is_audited(scene: Scene, role: str) -> None:
    vw = scene.vw
    who = vw.secretary if role == "secretary" else _staff(vw, role)
    assert scene.history(who).status_code == 400  # no purpose, no read
    assert scene.history(who, purpose="x").status_code == 400
    r = scene.history(who, **PURPOSE)
    assert r.status_code == 200 and r.json()["view"] == "full"
    assert {i["id"] for i in r.json()["items"]} == {
        scene.inside,
        scene.denied_visit,
        scene.pending["visit_id"],
        scene.multi,
    }
    multi = next(i for i in r.json()["items"] if i["id"] == scene.multi)
    assert {s["unit_label"] for s in multi["stops"]} == {
        "A-101",
        "A-102",
    }  # society roles see the whole visit
    assert "visitor_contact_token" not in r.text
    rows = vw.audit("read.visit_history")
    assert (
        rows and rows[-1][2] == role and PURPOSE["purpose"] in str(rows[-1][4]) + str(rows[-1][5])
    )


def test_the_guard_sees_only_the_current_gates_active_visits_masked(scene: Scene) -> None:
    vw = scene.vw
    assert scene.history(vw.guard).status_code == 400  # the gate must be named
    back = vw.make_gate("Back gate", "pedestrian")
    assert scene.history(vw.guard, gate_id=str(back)).json()["items"] == []
    r = scene.history(vw.guard, gate_id=str(scene.gate))
    assert r.status_code == 200 and r.json()["view"] == "guard"
    states = {i["id"]: i["state"] for i in r.json()["items"]}
    assert scene.denied_visit not in states  # a cancelled visit is not "active"
    assert states[scene.inside] == "inside" and states[scene.pending["visit_id"]] == "requested"
    assert all(s in ("requested", "authorised", "inside") for s in states.values())
    assert not any(
        k in r.text
        for k in ("invitation_id", "consent_recorded", "visitor_contact_token", "9999900555")
    )
    assert scene.history(vw.guard_sup, gate_id=str(scene.gate)).status_code == 200
    assert scene.history(vw.guard, gate_id=str(uuid.uuid4())).status_code == 400
    assert (
        scene.history(vw.guard, unit=None, gate_id=str(scene.gate), state="exited").json()["items"]
        == []
    )


def test_pagination_filters_and_date_range(scene: Scene) -> None:
    vw = scene.vw
    first = scene.history(scene.a.owner, limit=2)
    assert (
        first.status_code == 200 and len(first.json()["items"]) == 2 and first.json()["next_cursor"]
    )
    second = scene.history(scene.a.owner, limit=2, cursor=first.json()["next_cursor"])
    assert len(second.json()["items"]) == 2 and second.json()["next_cursor"] is None
    seen = [i["id"] for i in first.json()["items"] + second.json()["items"]]
    assert len(set(seen)) == 4  # no row twice, none skipped
    created = [i["created_at"] for i in first.json()["items"] + second.json()["items"]]
    assert created == sorted(created, reverse=True)
    # a cursor belongs to one unit and one filter set
    moved = vw.call(
        scene.b.owner,
        "GET",
        vw.s(f"units/{scene.b.unit}/visits"),
        params={"limit": 2, "cursor": first.json()["next_cursor"]},
    )
    assert moved.status_code == 400
    assert scene.history(scene.a.owner, limit=2, cursor="garbage").status_code == 400
    assert scene.history(scene.a.owner, limit=500).status_code == 400
    assert scene.history(scene.a.owner, state="inside").json()["items"][0]["id"] == scene.inside
    assert scene.history(scene.a.owner, kind="delivery").json()["items"][0]["id"] == scene.multi
    assert scene.history(scene.a.owner, colour="red").status_code == 400
    assert scene.history(scene.a.owner, state="flying").status_code == 400
    old = (dt.datetime.now(dt.UTC) - dt.timedelta(days=400)).isoformat()
    assert scene.history(scene.a.owner, **{"from": old}).status_code == 400  # wider than 92 days
    future = (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).isoformat()
    soon = (dt.datetime.now(dt.UTC) + dt.timedelta(days=2)).isoformat()
    assert scene.history(scene.a.owner, **{"from": future, "to": soon}).json()["items"] == []
    assert (
        scene.history(scene.a.owner, **{"from": "2026-01-01T00:00:00"}).status_code == 400
    )  # no time zone


def test_visit_register_for_society_roles_and_guard(scene: Scene) -> None:
    vw = scene.vw
    assert vw.call(scene.a.owner, "GET", vw.s("visits")).status_code == 403
    assert vw.call(scene.a.nr_owner, "GET", vw.s("visits")).status_code == 403  # type: ignore[arg-type]
    assert vw.call(vw.secretary, "GET", vw.s("visits")).status_code == 400
    r = vw.call(vw.secretary, "GET", vw.s("visits"), params={**PURPOSE, "limit": 100})
    assert r.status_code == 200 and len(r.json()["items"]) == 5
    only_a = vw.call(
        vw.secretary, "GET", vw.s("visits"), params={**PURPOSE, "unit_id": str(scene.a.unit)}
    )
    assert len(only_a.json()["items"]) == 4
    guard = vw.call(vw.guard, "GET", vw.s("visits"), params={"gate_id": str(scene.gate)})
    assert guard.status_code == 200 and all(
        i["state"] in ("requested", "authorised", "inside") for i in guard.json()["items"]
    )
    assert vw.call(vw.guard, "GET", vw.s("visits")).status_code == 400
    treasurer = _staff(vw, "treasurer")
    assert vw.call(treasurer, "GET", vw.s("visits"), params=PURPOSE).status_code == 403


def test_visit_detail_by_audience(scene: Scene) -> None:
    vw = scene.vw
    assert vw.call(scene.a.owner, "GET", f"/v1/visits/{scene.inside}").status_code == 200
    assert (
        vw.call(scene.a.owner, "GET", f"/v1/visits/{scene.other}").status_code == 404
    )  # another household's visitor
    assert vw.call(scene.a.family, "GET", f"/v1/visits/{scene.multi}").status_code == 200  # type: ignore[arg-type]
    assert vw.call(scene.a.nr_owner, "GET", f"/v1/visits/{scene.inside}").status_code == 403  # type: ignore[arg-type]
    assert vw.call(vw.guard, "GET", f"/v1/visits/{scene.inside}").status_code == 400
    assert (
        vw.call(
            vw.guard, "GET", f"/v1/visits/{scene.inside}", params={"gate_id": str(scene.gate)}
        ).status_code
        == 200
    )
    assert (
        vw.call(
            vw.guard, "GET", f"/v1/visits/{scene.denied_visit}", params={"gate_id": str(scene.gate)}
        ).status_code
        == 404
    )
    assert vw.call(vw.secretary, "GET", f"/v1/visits/{scene.inside}").status_code == 400
    ok = vw.call(vw.secretary, "GET", f"/v1/visits/{scene.inside}", params=PURPOSE)
    assert ok.status_code == 200 and ok.json()["id"] == scene.inside
    assert (
        vw.call(vw.secretary, "GET", f"/v1/visits/{uuid.uuid4()}", params=PURPOSE).status_code
        == 404
    )
    assert vw.call(vw.person(), "GET", f"/v1/visits/{scene.inside}").status_code == 404


def test_no_audience_ever_sees_the_visitor_contact_token_or_a_resident_identity(
    scene: Scene,
) -> None:
    vw = scene.vw
    token = vw.rows(
        "SELECT visitor_contact_token FROM visits WHERE visitor_contact_token IS NOT NULL LIMIT 1"
    )[0][0]
    blobs: list[str] = []
    for who, params in (
        (scene.a.owner, {}),
        (vw.guard, {"gate_id": str(scene.gate)}),
        (vw.secretary, PURPOSE),
    ):
        blobs.append(scene.history(who, **params).text)  # type: ignore[arg-type]
    blobs.append(vw.call(vw.secretary, "GET", vw.s("visits"), params=PURPOSE).text)
    for blob in blobs:
        assert token not in blob
        for person in (scene.a.owner, scene.a.family, scene.b.owner):
            assert str(person.id) not in blob  # type: ignore[union-attr]


def test_registry_roles_follow_prd_5_2_cell_for_cell() -> None:
    by_action = {p.action: p for p in visit_permissions}
    gate_ops, passes = matrix.MATRIX["gate_ops"], matrix.MATRIX["visitor_passes"]
    # the household that LIVES there: the O cells of "Gate operations" (OWNER_NR is N)
    assert by_action["gate.request.decide"].roles == {r for r, c in gate_ops.items() if c == "O"}
    assert "owner_nr" not in by_action["gate.history.read"].roles and gate_ops["owner_nr"] == "N"
    # "Create visitor passes": O for OWNER_OCC, TENANT, FAMILY only
    assert by_action["gate.invitation.create"].roles == {r for r, c in passes.items() if c == "O"}
    # society roles that read: R cells; the guard is F and stands at the gate; treasurer and auditor have nothing
    readers = {r for r, c in gate_ops.items() if c in ("R", "F")}
    assert readers <= by_action["gate.history.read"].roles
    assert not ({"treasurer", "auditor"} & by_action["gate.history.read"].roles)
    assert not ({"treasurer", "auditor"} & by_action["gate.visit.read"].roles)
    # the supervisor is declared module-locally (no matrix column): device status, exceptions, emergency override
    assert "guard_sup" in by_action["gate.device.decide"].roles and by_action[
        "gate.exception.authorise_entry"
    ].roles == {"guard_sup"}
    assert json.dumps(sorted(by_action)) and all(
        p.action.startswith("gate.") for p in by_action.values()
    )
