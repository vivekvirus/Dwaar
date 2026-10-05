# ruff: noqa: PT018, PT012, F811
"""The database-backed GrantResolver: memberships + role grants, validity, verification state, MFA, forged claims, isolation."""

from __future__ import annotations

import uuid

import pytest

from tests.integration.identity._support import IdentityHarness, Person


def register(idh: IdentityHarness, who: Person, society: uuid.UUID, **params: str):  # type: ignore[no-untyped-def]
    params.setdefault("purpose", "authz test")
    return idh.client().get(
        f"/v1/societies/{society}/memberships", params=params, headers=who.headers
    )


@pytest.mark.req("IAM-08", "INV-01")
def test_role_claims_in_the_jwt_are_ignored(idh: IdentityHarness) -> None:
    # REQ: IAM-08 INV-01
    soc = idh.society()
    tenant = idh.login(1)
    idh.seed_membership(soc.id, tenant.id, soc.units["A-101"], "tenant")
    issuer = idh.rt.issuer
    forged = issuer.mint(
        tenant.id, uuid.UUID(tenant.session_id), ttl_seconds=300,
        extra_claims={"roles": ["secretary", "platform_admin"], "role": "secretary", "society_id": str(soc.id),
                      "scope": "*", "permissions": ["*"], "realm_access": {"roles": ["secretary"]}},
    )  # fmt: skip
    headers = {"Authorization": f"Bearer {forged}"}
    c = idh.client()
    # the register is secretary-only in full; a tenant sees only their own row, whatever the token says
    r = c.get(f"/v1/societies/{soc.id}/memberships", params={"purpose": "forged"}, headers=headers)
    assert r.status_code == 200 and {i["person_id"] for i in r.json()["items"]} == {str(tenant.id)}
    assert (
        c.get(
            f"/v1/societies/{soc.id}/role-grants", params={"purpose": "forged"}, headers=headers
        ).status_code
        == 403
    )
    roles = c.get("/v1/me", headers=headers).json()["societies"][0]["roles"]
    assert [x["role"] for x in roles] == ["tenant"]


@pytest.mark.req("IAM-01", "IAM-08")
def test_grants_follow_verification_state_and_dates(idh: IdentityHarness) -> None:
    # REQ: IAM-01 IAM-08
    soc = idh.society()
    u = soc.units["A-101"]
    cases = {
        "pending": ("pending", None, False),
        "rejected": ("rejected", None, False),
        "reverification": ("reverification", None, False),
        "verified": ("verified", None, True),
        "disputed": ("disputed", None, True),  # a dispute never removes occupancy (IAM-05)
        "ended": ("verified", "2020-01-01", False),  # started 2019-01-01, ended 2020-01-01
    }
    for i, (name, (state, ended, expect)) in enumerate(cases.items()):
        p = idh.login(10 + i)
        idh.seed_membership(
            soc.id,
            p.id,
            u,
            "tenant",
            verification=state,
            effective_from="2019-01-01" if ended else None,
            effective_to=ended,
        )
        r = register(idh, p, soc.id)
        assert (r.status_code == 200) is expect, name
        if not expect:
            assert r.status_code == 404, (
                name
            )  # no standing: indistinguishable from a society that does not exist


@pytest.mark.req("IAM-01", "INV-04")
def test_ownership_occupancy_and_role_are_independent(idh: IdentityHarness) -> None:
    # REQ: IAM-01 INV-04
    soc = idh.society()
    resident_owner, absent_owner, joint = idh.login(20), idh.login(21), idh.login(22)
    idh.seed_membership(soc.id, resident_owner.id, soc.units["A-101"], "owner", lives=True)
    idh.seed_membership(soc.id, absent_owner.id, soc.units["A-102"], "owner", lives=False)
    idh.seed_membership(soc.id, joint.id, soc.units["A-101"], "joint_owner", lives=False)
    c = idh.client()

    def roles(p: Person) -> list[str]:
        return [
            r["role"] for r in c.get("/v1/me", headers=p.headers).json()["societies"][0]["roles"]
        ]

    assert roles(resident_owner) == ["owner_occ"]
    assert roles(absent_owner) == ["owner_nr"]
    assert roles(joint) == ["owner_nr"]
    cols = idh.admin_rows(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'memberships' AND table_schema = 'public'"
    )
    names = {r[0] for r in cols}
    assert {
        "lives_in_unit",
        "billing_liable",
        "voting_entitled",
        "kind",
    } <= names  # separate relationships, separate columns


@pytest.mark.req("INV-01", "ARCH-01")
def test_membership_in_a_does_not_reach_society_b_or_its_object_ids(idh: IdentityHarness) -> None:
    # REQ: INV-01 ARCH-01
    a, b = idh.society("A"), idh.society("B")
    sec_a, sec_b, tenant_a, tenant_b = idh.login(30), idh.login(31), idh.login(32), idh.login(33)
    idh.seed_grant(a.id, sec_a.id, "secretary")
    idh.elevate_session(sec_a)
    idh.seed_grant(b.id, sec_b.id, "secretary")
    idh.seed_membership(a.id, tenant_a.id, a.units["A-101"], "tenant")
    mem_b = idh.seed_membership(
        b.id, tenant_b.id, b.units["A-101"], "tenant", verification="pending"
    )
    c = idh.client()
    assert register(idh, sec_a, a.id).status_code == 200
    # the secretary of A names society B: 404, whether or not B exists
    assert register(idh, sec_a, b.id).status_code == 404
    assert register(idh, sec_a, uuid.uuid4()).status_code == 404
    # ... and B's membership id under A's path
    for method, path in [
        ("GET", f"/v1/societies/{a.id}/memberships/{mem_b}/holds"),
        ("POST", f"/v1/societies/{a.id}/memberships/{mem_b}/holds"),
        ("POST", f"/v1/societies/{a.id}/memberships/{mem_b}/dispute"),
    ]:
        r = c.request(
            method, path, json={"reason": "cross society probe attempt"}, headers=sec_a.headers
        )
        assert r.status_code == 404, (method, path, r.text)
    # owner-confirm with B's membership id: tenant_a is not an owner anywhere
    r = c.post(
        f"/v1/memberships/{mem_b}/owner-confirm",
        json={"decision": "confirm"},
        headers=tenant_a.headers,
    )
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    # A's tenant cannot read B's register or B's membership even by id guessing
    assert register(idh, tenant_a, b.id).status_code == 404
    # a unit id of B used to apply under A is refused by the composite foreign key, as a plain 404
    applicant = idh.login(34)
    r = c.post(
        f"/v1/societies/{a.id}/memberships",
        json={"unit_id": str(b.units["A-101"]), "kind": "tenant"},
        headers=applicant.headers,
    )
    assert r.status_code == 404


@pytest.mark.req("INV-01")
def test_resident_grant_is_limited_to_their_own_unit(idh: IdentityHarness) -> None:
    # REQ: INV-01
    soc = idh.society()
    t1, t2 = idh.login(40), idh.login(41)
    idh.seed_membership(soc.id, t1.id, soc.units["A-101"], "tenant")
    idh.seed_membership(soc.id, t2.id, soc.units["A-102"], "tenant")
    r = register(idh, t1, soc.id, unit_id=str(soc.units["A-102"]))
    assert r.status_code == 404  # another household's unit
    r = register(idh, t1, soc.id)
    assert [i["unit_id"] for i in r.json()["items"]] == [str(soc.units["A-101"])]


@pytest.mark.req("IAM-03", "IAM-08")
def test_elevated_roles_need_a_fresh_mfa_step_up(idh: IdentityHarness) -> None:
    # REQ: IAM-03 IAM-08
    soc = idh.society()
    sec = idh.login(50)
    idh.seed_grant(soc.id, sec.id, "secretary")
    c = idh.client()
    r = register(idh, sec, soc.id)
    assert r.status_code == 403  # standing, but the elevated role is not active without MFA
    me = c.get("/v1/me", headers=sec.headers).json()
    role = me["societies"][0]["roles"][0]
    assert (
        role["role"] == "secretary"
        and role["requires_mfa"]
        and not role["mfa_satisfied"]
        and not role["active"]
    )
    idh.elevate_session(sec)
    assert register(idh, sec, soc.id).status_code == 200
    # a stale step-up stops counting
    with idh.db.admin_conn() as conn:
        conn.execute("UPDATE iam.auth_sessions SET mfa_verified_at = now() - interval '9 hours'")
    assert register(idh, sec, soc.id).status_code == 403
    # a different session of the same person has no step-up either
    other = idh.login(sec.phone, device="other")
    assert register(idh, other, soc.id).status_code == 403


@pytest.mark.req("IAM-02")
def test_expired_grant_stops_working_and_revokes_the_elevated_session(idh: IdentityHarness) -> None:
    # REQ: IAM-02
    soc = idh.society()
    sec = idh.login(60)
    gid = idh.seed_grant(soc.id, sec.id, "committee", expires="1 hour")
    idh.elevate_session(sec)
    plain = idh.login(sec.phone, device="plain")  # a session that never stepped up
    assert register(idh, sec, soc.id).status_code == 200
    with idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "UPDATE role_grants SET expires_at = now() - interval '1 second' WHERE id = %s", (gid,)
        )
    # the very next request with the elevated session is refused outright: its privilege is gone, so is the session
    assert register(idh, sec, soc.id).status_code == 401
    assert idh.admin_rows(
        "SELECT revoked_reason FROM iam.auth_sessions WHERE id = %s", (sec.session_id,)
    ) == [("privilege_expired",)]
    # the non-elevated session of the same person survives (it never used the privilege) but has no access
    assert idh.client().get("/v1/me", headers=plain.headers).status_code == 200
    assert register(idh, plain, soc.id).status_code == 404


@pytest.mark.req("IAM-02")
def test_future_dated_grant_is_inactive_and_window_is_enforced(idh: IdentityHarness) -> None:
    # REQ: IAM-02
    soc = idh.society()
    guard = idh.login(61)
    with idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "INSERT INTO role_grants (society_id, person_id, role, issued_by, reason, not_before, expires_at)"
            " VALUES (%s, %s, 'guard', %s, 'night shift later', now() + interval '1 day', now() + interval '2 days')",
            (soc.id, guard.id, idh.system_person()),
        )
    r = idh.client().get("/v1/me", headers=guard.headers).json()
    assert r["societies"][0]["roles"][0]["valid_now"] is False
    assert register(idh, guard, soc.id).status_code == 404
    with pytest.raises(Exception, match="role_grants_window_check"), idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "INSERT INTO role_grants (society_id, person_id, role, issued_by, reason, not_before, expires_at)"
            " VALUES (%s, %s, 'guard', %s, 'backwards window', now() + interval '2 days', now() + interval '1 day')",
            (soc.id, guard.id, idh.system_person()),
        )


@pytest.mark.req("IAM-08", "INV-01")
def test_revoking_a_grant_is_effective_on_the_next_request(idh: IdentityHarness) -> None:
    # REQ: IAM-08 INV-01
    soc = idh.society()
    guard = idh.login(62)
    sec = idh.login(63)
    idh.seed_grant(soc.id, sec.id, "secretary")
    idh.elevate_session(sec)
    gid = idh.seed_grant(soc.id, guard.id, "guard")
    assert register(idh, guard, soc.id).status_code == 200
    r = idh.client().post(
        f"/v1/societies/{soc.id}/role-grants/{gid}/revoke",
        json={"reason": "left the agency"},
        headers=sec.headers,
    )
    assert r.status_code == 200, r.text
    assert register(idh, guard, soc.id).status_code == 404


@pytest.mark.req("INV-01")
def test_unit_scoped_role_grant_covers_only_that_unit(idh: IdentityHarness) -> None:
    # REQ: INV-01
    soc = idh.society()
    tech = idh.login(64)
    idh.seed_grant(soc.id, tech.id, "technician", unit=soc.units["A-101"])
    me = idh.client().get("/v1/me", headers=tech.headers).json()
    role = me["societies"][0]["roles"][0]
    assert role["role"] == "technician" and role["unit_id"] == str(soc.units["A-101"])


@pytest.mark.req("IAM-02")
def test_background_sweep_revokes_elevated_sessions_of_expired_grants_without_any_request(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-02 (the worker role runs the same sweep, so expiry does not wait for the person's next request)
    soc = idh.society()
    sec = idh.login(70)
    gid = idh.seed_grant(soc.id, sec.id, "treasurer", expires="1 hour")
    idh.elevate_session(sec)
    with idh.db.worker_conn() as conn:
        assert conn.execute("SELECT iam.sweep_expired_grants()").fetchone() == (
            0,
        )  # nothing expired yet
    with idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "UPDATE role_grants SET expires_at = now() - interval '1 second' WHERE id = %s", (gid,)
        )
    with idh.db.worker_conn() as conn:
        assert conn.execute("SELECT iam.sweep_expired_grants()").fetchone() == (1,)
    assert idh.admin_rows(
        "SELECT revoked_reason FROM iam.auth_sessions WHERE id = %s", (sec.session_id,)
    ) == [("privilege_expired",)]
    with idh.db.worker_conn() as conn:
        assert conn.execute("SELECT iam.sweep_expired_grants()").fetchone() == (0,)  # idempotent
