"""AT-02 (M0): a non-resident owner asks for the visitor history of their tenant -> denied; the owner's financial rights stay.

PRD 16: "Non-resident owner requests tenant visitor history. Required outcome: Denied; owner's financial rights intact."
PRD 5.1/5.2: ownership, occupancy and billing liability are independent (INV-04); the "Gate operations" row gives OWNER_NR
``N`` and OWNER_OCC / TENANT / FAMILY ``O`` (own unit); the "Bill runs" row gives OWNER_NR ``O (bills)``.

WHAT RUNS, AND AT WHICH LEVEL (slice 2 added the endpoint, so the denial is now proven end to end as well):

* END TO END: ``GET /v1/societies/{id}/units/{unit_id}/visits`` (visits module, permission ``gate.history.read``, the PRD 5.2 "Gate
  operations" row): the non-resident owner of a tenant-occupied unit is refused (403 ``not_authorised``, or 404 ``not_found`` when the
  person lives elsewhere as an occupying owner, see the quirk below) and no visitor of the tenant appears in the answer; the tenant
  and the occupying owner read the history of their unit (200); a stranger, a member of another society and another household get
  404. The owner's financial rights are intact through the endpoints that exist: the unit record, the unit register scope and
  the stored liability and voting facts.
* PERMISSION LEVEL (kept as the second, independent proof): the real registry (``app.state.permissions``, PRD 5.2 as data), the
  real database-backed grant resolver and the real ``decide()`` that every ``require(...)`` route calls, fed by the REAL seeded
  memberships, for ``matrix.gate_ops.read_own`` (there is no ``gate.history`` matrix string; the module action is
  ``gate.history.read``) and the owner's own-unit bills/register/audit capabilities.
* ``test_visitor_history_route_is_registered_and_never_lists_the_non_resident_owner`` replaces the slice 1 tripwire: it fails if
  the route disappears or if OWNER_NR ever becomes a role of the visits history permissions.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from dwaar_api.core.authn import Principal
from dwaar_api.core.authz import Scope, decide, iter_api_routes
from dwaar_api.modules.identity import matrix
from dwaar_api.seed.people import by_key
from dwaar_common.errors import DwaarError, NotAuthorised, NotFound
from tests.acceptance._world import DATASET, Session, World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-02", dataset=DATASET),
    pytest.mark.req("IAM-01", "IAM-03", "INV-04", "IAM-12", "ARCH-02"),
]

#: PRD 5.2 "Gate operations", own-unit read: the visitor / gate history of a unit.
GATE_HISTORY = "matrix.gate_ops.read_own"
#: PRD 5.2 "Bill runs", owner cell "O (bills)": the owner's own bills.
OWN_BILLS = "matrix.bill_runs.read_own"
#: PRD 5.2 "Unit and member register", owner cell "O": the own unit's register entry.
OWN_UNIT = "matrix.unit_register.read_own"
#: PRD 5.2 "Audit log", owner cell "O (about them)": records about oneself.
OWN_AUDIT = "matrix.audit_log.read_own"

# (person key, block, label) of a non-resident owner and the unit whose tenant's history they ask for
# The last column is the status of the denial. A person whose ONLY standing in the society is non-resident ownership is
# refused with 403 ``not_authorised`` (standing, but this role may not). Sanjay also LIVES in another unit as owner_occ, a
# role the capability allows, so for his rented-out flat the target is simply outside the grants that qualify: 404
# ``not_found``. Both are denials and neither returns data; the difference is a documented quirk of ``decide()``.
NON_RESIDENT_OWNERS = [
    pytest.param("ka.secretary", "B", "205", 403, id="Meera-B205-tenant-Priya"),
    pytest.param("smita", "A", "305", 403, id="Smita-A305-tenant-Dev-disputed-move-out"),
    pytest.param("sanjay", "C", "101", 404, id="Sanjay-C101-investment-flat"),
]


def _decide(
    world: World, who: Session, action: str, society: uuid.UUID, unit: uuid.UUID | None
) -> Scope:
    """What ``require(action, unit_param=...)`` computes for this caller, from the live registry and live grants."""
    permission = world.app.state.permissions.get(action)
    assert permission is not None, f"{action} is not registered"
    principal = Principal(
        subject=str(who.person_id),
        person_id=who.person_id,
        session_id=who.session_id,
        simulation=True,
    )
    grants = world.app.state.grant_resolver.resolve(principal, society_hint=society, fresh=True)
    return decide(permission, grants, society_hint=society, unit_target=unit)


def _unit(world: World, block: str, label: str) -> tuple[uuid.UUID, uuid.UUID]:
    mh = world.objects("mh")
    return mh.society, mh.ref.unit(block, label)


@pytest.mark.parametrize(("who", "block", "label", "status"), NON_RESIDENT_OWNERS)
def test_non_resident_owner_is_denied_the_visitor_history_of_their_unit(
    world: World, who: str, block: str, label: str, status: int
) -> None:
    owner = world.login(who)
    society, unit = _unit(world, block, label)
    with pytest.raises(DwaarError) as denied:
        _decide(world, owner, GATE_HISTORY, society, unit)
    assert denied.value.status == status
    assert denied.value.code == ("not_authorised" if status == 403 else "not_found")


@pytest.mark.parametrize(("who", "block", "label", "status"), NON_RESIDENT_OWNERS)
def test_owner_financial_rights_stay_intact(
    world: World, who: str, block: str, label: str, status: int
) -> None:
    """Same person, same unit, same session: the history is denied while own bills, own register entry and own audit
    trail stay allowed, and the effective role is ``owner_nr`` (not a downgrade of ownership)."""
    owner = world.login(who)
    society, unit = _unit(world, block, label)
    with pytest.raises(DwaarError) as denied:
        _decide(world, owner, GATE_HISTORY, society, unit)
    assert denied.value.status == status
    for action in (OWN_BILLS, OWN_UNIT):
        scope = _decide(world, owner, action, society, unit)
        assert scope.role == "owner_nr", (action, scope)
        assert scope.unit_id == unit and unit in scope.unit_ids and not scope.society_wide
    audit = _decide(world, owner, OWN_AUDIT, society, None)
    assert audit.role == "owner_nr" and not audit.society_wide
    # ... and only for their own unit: another unit is simply not theirs (404, no existence leak)
    other = world.objects("mh").ref.unit("A", "104")
    with pytest.raises(NotFound):
        _decide(world, owner, OWN_BILLS, society, other)


def test_residents_of_the_same_unit_do_keep_the_history(world: World) -> None:
    """Control: the tenant of Meera's unit (and the owner who LIVES in a unit) are allowed the very same capability on their
    own unit, and a stranger's unit is a 404. So the denial above is about the ROLE, not a broken capability."""
    society, unit = _unit(world, "B", "205")
    priya = world.login("priya")
    scope = _decide(world, priya, GATE_HISTORY, society, unit)
    assert scope.role == "tenant" and scope.unit_id == unit
    with pytest.raises(NotFound):
        _decide(world, priya, GATE_HISTORY, society, world.objects("mh").ref.unit("A", "104"))
    # Dev (tenant, move-out disputed by the owner): occupancy continues, so he keeps the history of his unit
    dev = world.login("dev")
    s2, u2 = _unit(world, "A", "305")
    assert _decide(world, dev, GATE_HISTORY, s2, u2).role == "tenant"
    # Ganesh lives in A-203 as owner: allowed
    ganesh = world.login("ganesh")
    s3, u3 = _unit(world, "A", "203")
    assert _decide(world, ganesh, GATE_HISTORY, s3, u3).role == "owner_occ"


def test_one_person_two_memberships_two_answers(world: World) -> None:
    """INV-04 in one person: Sanjay owns A-402 and LIVES there (allowed) and owns C-101 as an investment (denied). The
    answer follows the membership of THAT unit, not the person."""
    sanjay = world.login("sanjay")
    society, lives = _unit(world, "A", "402")
    assert _decide(world, sanjay, GATE_HISTORY, society, lives).role == "owner_occ"
    _s, rented = _unit(world, "C", "101")
    with pytest.raises(DwaarError) as denied:
        _decide(world, sanjay, GATE_HISTORY, society, rented)
    assert denied.value.status in (403, 404)
    # financial rights on both
    assert _decide(world, sanjay, OWN_BILLS, society, lives).role == "owner_occ"
    assert _decide(world, sanjay, OWN_BILLS, society, rented).role == "owner_nr"


def test_a_role_in_another_society_buys_nothing_here(world: World) -> None:
    """Meera is secretary of Society B, whose role CAN read gate operations society-wide there. In Society A she is only a
    non-resident owner, and the gate history of A's units stays denied: roles are per society (INV-01/INV-04)."""
    meera = world.login("ka.secretary")
    ka = world.objects("ka")
    mh, unit = _unit(world, "B", "205")
    in_b = _decide(world, meera, "matrix.gate_ops.read", ka.society, None)
    assert in_b.role == "secretary" and in_b.society_wide
    with pytest.raises(NotAuthorised):
        _decide(world, meera, "matrix.gate_ops.read", mh, None)
    with pytest.raises(NotAuthorised):
        _decide(world, meera, "matrix.gate_ops.read", mh, unit)


def test_the_matrix_says_what_the_prd_says() -> None:
    """The permission data under the checks above is PRD 5.2 cell for cell: OWNER_NR has N on Gate operations, the
    resident roles that live there have O, and the explicit denied-by-default list names this very case."""
    row = matrix.MATRIX["gate_ops"]
    assert row["owner_nr"] == "N"
    assert (row["owner_occ"], row["tenant"], row["family"]) == ("O", "O", "O")
    assert matrix.MATRIX["bill_runs"]["owner_nr"] == "O (bills)"
    assert "owner_nr" not in matrix.roles_for("gate_ops", "read_own")
    assert "owner_nr" in matrix.roles_for("bill_runs", "read_own")
    assert (
        matrix.OWNER_NR,
        GATE_HISTORY,
        "non-resident owner cannot see the tenant's visitor history",
    ) in matrix.DENIED_BY_DEFAULT


# ===================================================================================================== end to end today
def test_owner_keeps_the_ownership_record_and_liability_while_the_tenant_lives_there(
    world: World,
) -> None:
    """End to end through the endpoints that exist: Meera, a non-resident owner, reads her unit's record (200) and only
    that unit; the database says she, not the tenant, is the liable and voting-entitled party while the tenant is the one
    who lives there (billing liability and occupancy are separate facts, INV-04)."""
    meera = world.login("ka.secretary")
    mh = world.objects("mh")
    unit = mh.ref.unit("B", "205")
    r = world.call(meera, "GET", f"/v1/societies/{mh.society}/units/{unit}")
    assert r.status_code == 200 and r.json()["id"] == str(unit)
    listing = world.call(meera, "GET", f"/v1/societies/{mh.society}/units", params={"limit": 100})
    assert [u["id"] for u in listing.json()["items"]] == [str(unit)]
    me: dict[str, Any] = world.call(meera, "GET", "/v1/me").json()
    mine = next(s for s in me["societies"] if s["society_id"] == str(mh.society))
    membership = mine["memberships"][0]
    assert membership["kind"] == "owner" and membership["lives_in_unit"] is False
    assert membership["verification"] == "verified"
    owner_m = world.membership_of(mh.society, "ka.secretary", "B", "205", "owner")
    tenant_m = world.membership_of(mh.society, "priya", "B", "205", "tenant")
    rows = {
        r[0]: r[1:]
        for r in world.admin_rows(
            "SELECT id, billing_liable, voting_entitled, lives_in_unit, verification FROM memberships WHERE id = ANY(%s)",
            ([owner_m, tenant_m],),
        )
    }
    assert rows[owner_m] == (True, True, False, "verified")
    assert rows[tenant_m] == (False, False, True, "verified")


def test_secretary_without_a_step_up_is_not_authorised_but_the_owner_role_is_unaffected(
    world: World,
) -> None:
    """Elevated roles need a fresh TOTP step-up (403 ``not_authorised`` without it, ADR-0011); the same person's
    non-elevated owner role in A needs none and keeps working: financial rights do not depend on MFA."""
    phone = by_key()["ka.secretary"].phone
    person_id = world.login("ka.secretary").person_id
    c = world.client
    c.post("/v1/auth/otp/request", json={"phone": phone})
    code = c.get("/v1/dev/otp", params={"phone": phone}).json()["otp"]
    body = c.post(
        "/v1/auth/otp/verify",
        json={
            "phone": phone,
            "code": code,
            "device": {"device_id": "no-mfa", "label": "no step-up"},
        },
    ).json()
    bare = Session(
        "ka.secretary",
        person_id,
        phone,
        {"Authorization": f"Bearer {body['access_token']}"},
        body["session_id"],
    )
    ka = world.objects("ka")
    denied = world.call(bare, "GET", f"/v1/societies/{ka.society}/units")
    assert denied.status_code == 403 and denied.json()["code"] == "not_authorised"
    mh = world.objects("mh")
    ok = world.call(bare, "GET", f"/v1/societies/{mh.society}/units/{mh.ref.unit('B', '205')}")
    assert ok.status_code == 200


# ===================================================================================================== end to end (slice 2)
HISTORY = "/v1/societies/{society}/units/{unit}/visits"


def _history(
    world: World, who: Session, unit: uuid.UUID, society: uuid.UUID | None = None, **params: Any
) -> Any:
    sid = society or world.objects("mh").society
    return world.call(who, "GET", HISTORY.format(society=sid, unit=unit), params=params)


@pytest.mark.parametrize(("who", "block", "label", "status"), NON_RESIDENT_OWNERS)
def test_http_non_resident_owner_is_denied_the_tenants_visitor_history(
    world: World, who: str, block: str, label: str, status: int
) -> None:
    """AT-02 end to end: the real endpoint, the real seeded memberships, the real token."""
    owner = world.login(who)
    _society, unit = _unit(world, block, label)
    r = _history(world, owner, unit)
    assert r.status_code == status, r.text
    assert r.json()["code"] == ("not_authorised" if status == 403 else "not_found")
    assert "items" not in r.json() and "Unknown sales visitor" not in r.text
    # staff-style access does not open it for an owner either: a purpose changes nothing
    again = _history(world, owner, unit, purpose="I own this flat and want to know who visits")
    assert again.status_code == status and "items" not in again.json()


def test_http_the_tenant_and_the_occupying_owner_do_read_the_history_of_their_unit(
    world: World,
) -> None:
    """The control: the SAME endpoint answers 200 to the people who live in the unit, with the seeded visits of that unit."""
    _soc, b205 = _unit(world, "B", "205")
    priya = world.login("priya")  # tenant of Meera's flat
    r = _history(world, priya, b205)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["view"] == "household" and body["unit_id"] == str(b205)
    assert [i["visitor_alias"] for i in body["items"]] == [
        "Unknown sales visitor"
    ]  # the denied request seeded for her flat
    assert body["items"][0]["state"] == "cancelled" and body["items"][0]["entry_observed"] is False
    assert "visitor_contact_token" not in r.text
    # Dev (tenant, move-out disputed: occupancy continues) keeps the history of A-305, Smita (non-resident owner) does not have it
    _s, a305 = _unit(world, "A", "305")
    assert _history(world, world.login("dev"), a305).status_code == 200
    assert _history(world, world.login("smita"), a305).status_code == 403
    # Ganesh lives in A-203 as owner and sees the seeded visits of his household (and only those)
    _s, a203 = _unit(world, "A", "203")
    ganesh = _history(world, world.login("ganesh"), a203, limit=100)
    aliases = {i["visitor_alias"] for i in ganesh.json()["items"]}
    assert ganesh.status_code == 200 and {"Vikas (cousin)", "Courier parcel"} <= aliases
    assert "Unknown sales visitor" not in aliases and "Grocery Basket delivery" not in aliases
    # a delegated family member of the same unit reads it too
    assert _history(world, world.login("rekha"), a203).status_code == 200


def test_http_everyone_else_gets_nothing(world: World) -> None:
    _soc, b205 = _unit(world, "B", "205")
    _s, a203 = _unit(world, "A", "203")
    # another household of the same society, a member of ANOTHER society, a person with no standing at all
    assert _history(world, world.login("neha"), b205).status_code == 404
    assert _history(world, world.login("neha"), a203).status_code == 404
    assert _history(world, world.login("farhan"), b205).status_code == 404
    assert _history(world, world.login("vikram"), b205).status_code == 404
    ka_secretary_in_mh = _history(
        world, world.login("ka.secretary"), a203, purpose="Cross-society curiosity"
    )
    assert ka_secretary_in_mh.status_code == 403  # she is only a non-resident owner in this society
    # a unit id of ANOTHER society used under my society's path is simply unknown
    ka_unit = world.objects("ka").ref.unit("Tower 1", "101")
    assert _history(world, world.login("ganesh"), ka_unit).status_code == 404
    # society roles without a purpose get no read; the treasurer and the auditor never do (PRD 5.1/5.2)
    secretary = world.login("mh.secretary")
    assert _history(world, secretary, b205).status_code == 400
    ok = _history(world, secretary, b205, purpose="Complaint review by the committee")
    assert ok.status_code == 200 and ok.json()["view"] == "full"
    for who in ("mh.treasurer", "mh.auditor"):
        assert (
            _history(world, world.login(who), b205, purpose="Looking at visitors").status_code
            == 403
        ), who
    guard = world.login("mh.guard1")
    assert _history(world, guard, b205).status_code == 400  # the guard names the gate
    gate = visit_gate(world)
    assert (
        _history(world, guard, b205, gate_id=str(gate)).json()["items"] == []
    )  # the only visit there is closed (denied)


def visit_gate(world: World) -> uuid.UUID:
    return uuid.UUID(
        str(world.admin_rows("SELECT id FROM gates ORDER BY created_at, id LIMIT 1")[0][0])
    )


def test_http_owner_keeps_financial_rights_after_the_history_denial(world: World) -> None:
    """Denied the tenant's visitors, still the liable owner: the unit record stays readable and the liability facts stay hers."""
    meera = world.login("ka.secretary")
    mh = world.objects("mh")
    unit = mh.ref.unit("B", "205")
    assert _history(world, meera, unit).status_code == 403
    record = world.call(meera, "GET", f"/v1/societies/{mh.society}/units/{unit}")
    assert record.status_code == 200 and record.json()["id"] == str(unit)
    owner_m = world.membership_of(mh.society, "ka.secretary", "B", "205", "owner")
    row = world.admin_rows(
        "SELECT billing_liable, voting_entitled, lives_in_unit FROM memberships WHERE id = %s",
        (owner_m,),
    )[0]
    assert row == (True, True, False)


def test_visitor_history_route_is_registered_and_never_lists_the_non_resident_owner(
    world: World,
) -> None:
    """Replaces the slice 1 tripwire: the endpoint exists, and OWNER_NR is in none of the roles of the gate history permissions."""
    paths = sorted(
        route.path
        for route in iter_api_routes(world.app)
        if route.path.endswith("/units/{unit_id}/visits")
    )
    assert paths == ["/v1/societies/{society_id}/units/{unit_id}/visits"]
    permissions = world.app.state.permissions
    for action in (
        "gate.history.read",
        "gate.invitation.create",
        "gate.request.decide",
        GATE_HISTORY,
    ):
        permission = permissions.get(action)
        assert permission is not None and "owner_nr" not in permission.roles, action
    assert permissions.get("gate.history.read").roles >= matrix.roles_for("gate_ops", "read_own")
