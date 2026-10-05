"""AT-02 (M0): a non-resident owner asks for the visitor history of their tenant -> denied; the owner's financial rights stay.

PRD 16: "Non-resident owner requests tenant visitor history. Required outcome: Denied; owner's financial rights intact."
PRD 5.1/5.2: ownership, occupancy and billing liability are independent (INV-04); the "Gate operations" row gives OWNER_NR
``N`` and OWNER_OCC / TENANT / FAMILY ``O`` (own unit); the "Bill runs" row gives OWNER_NR ``O (bills)``.

WHAT RUNS TODAY, AND WHAT DOES NOT (read this before trusting the green mark):

* The visitor-history ENDPOINT does not exist yet (slice 2: visitor request, decision and observation). So the denial is
  proven at the PERMISSION-SERVICE level: the real registry (``app.state.permissions``, PRD 5.2 as data), the real
  database-backed grant resolver and the real ``decide()`` that every ``require(...)`` route calls, fed by the REAL seeded
  memberships. ``gate.history`` in the task wording is the PRD 5.2 "Gate operations" capability, own-unit read
  (``matrix.gate_ops.read_own``): there is no separate ``gate.history`` permission string.
* The owner's financial rights are asserted at the same level (``matrix.bill_runs.read_own``,
  ``matrix.unit_register.read_own``, ``matrix.audit_log.read_own``) AND end to end through the endpoints that exist: the
  ownership record of the unit (``GET /units/{id}``), the unit register scope, and the stored liability/voting facts.
* ``test_visitor_history_route_is_not_built_yet`` is a tripwire. When slice 2 adds the endpoint it FAILS until the HTTP-level
  assertions (owner_nr -> 403 ``not_authorised`` on the tenant's unit; tenant and owner_occ -> 200; a stranger -> 404) are
  added, so the permission-level proof can never silently stand in for the end-to-end one.
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


def test_visitor_history_route_is_not_built_yet(world: World) -> None:
    """TRIPWIRE. No gate / visitor route exists in slice 1. When slice 2 adds one this test fails: add the HTTP-level AT-02
    assertions for it (owner_nr -> 403 not_authorised; tenant, owner_occ -> 200; stranger -> 404) and update this list."""
    found = sorted(
        route.path
        for route in iter_api_routes(world.app)
        if any(word in route.path.lower() for word in ("visit", "gate", "guest", "pass"))
    )
    assert found == [], f"visitor/gate routes now exist, extend AT-02 end to end: {found}"
