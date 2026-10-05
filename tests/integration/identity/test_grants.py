# ruff: noqa: PT018, PT012, F811
"""IAM-02, IAM-03, IAM-13: role grants carry scope/issuer/expiry/reason, are not self-grantable, never come from sign-up."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from tests.integration.identity._support import IdentityHarness, phone, staff


def iso(delta: timedelta) -> str:
    return (datetime.now(UTC) + delta).isoformat()


def grant(idh: IdentityHarness, who, society: uuid.UUID, body: dict, key: str | None = None):  # type: ignore[no-untyped-def]
    headers = {**who.headers, "Idempotency-Key": key or f"grant-{uuid.uuid4()}"}
    return idh.client().post(f"/v1/societies/{society}/role-grants", json=body, headers=headers)


@pytest.mark.req("IAM-02", "IAM-03")
def test_issue_a_grant_with_scope_issuer_expiry_and_reason(idh: IdentityHarness) -> None:
    # REQ: IAM-02 IAM-03
    soc = idh.society()
    s = staff(idh, soc.id, 1)
    guard = idh.login(2)
    idh.seed_membership(
        soc.id, guard.id, soc.units["A-101"], "staff", lives=False
    )  # known to the society
    r = grant(idh, s.secretary, soc.id, {
        "person_id": str(guard.id), "role": "guard", "reason": "Night shift guard, gate 1", "expires_at": iso(timedelta(days=30)),
    })  # fmt: skip
    assert r.status_code == 201, r.text
    out = r.json()
    assert (
        out["role"] == "guard"
        and out["issued_by"] == str(s.secretary.id)
        and out["scope"] == {"kind": "society"}
    )
    row = idh.admin_rows(
        "SELECT issued_by, reason, expires_at IS NOT NULL, scope FROM role_grants WHERE role = 'guard'"
    )[0]
    assert row[0] == s.secretary.id and row[1] == "Night shift guard, gate 1" and row[2] is True
    assert (
        idh.audit_ops("role_grant.issue")[0][4] == "Night shift guard, gate 1"
    )  # audit carries the reason
    assert idh.admin_rows(
        "SELECT count(*) FROM outbox WHERE event_type = 'identity.role_granted'"
    ) == [(1,)]
    # the guard now has the role, computed server-side
    me = idh.client().get("/v1/me", headers=guard.headers).json()
    roles = [x for x in me["societies"][0]["roles"] if x["source"] == "role_grant"]
    assert (
        roles[0]["role"] == "guard"
        and roles[0]["expires_at"] is not None
        and roles[0]["active"] is True
    )
    # list shows it, with its purpose logged
    c = idh.client()
    lst = c.get(
        f"/v1/societies/{soc.id}/role-grants",
        params={"purpose": "quarterly access review"},
        headers=s.secretary.headers,
    )
    assert lst.status_code == 200 and any(i["role"] == "guard" for i in lst.json()["items"])
    assert (
        c.get(f"/v1/societies/{soc.id}/role-grants", headers=s.secretary.headers).status_code == 400
    )
    assert idh.audit_ops("read.role_grants")[0][3]["purpose"] == "quarterly access review"


@pytest.mark.req("IAM-03")
def test_a_grant_can_never_be_self_issued(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    soc = idh.society()
    s = staff(idh, soc.id, 10)
    r = grant(
        idh,
        s.secretary,
        soc.id,
        {"person_id": str(s.secretary.id), "role": "treasurer", "reason": "I deserve this role"},
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "self_grant_same_person"
    # the database says the same, to every role
    with pytest.raises(Exception, match="role_grants_no_self_grant"), idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "INSERT INTO role_grants (society_id, person_id, role, issued_by, reason) VALUES (%s, %s, 'treasurer', %s, 'self grant')",
            (soc.id, s.secretary.id, s.secretary.id),
        )


@pytest.mark.req("IAM-03", "IAM-13")
def test_platform_roles_and_unknown_roles_are_not_assignable_through_the_api(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-03 IAM-13
    soc = idh.society()
    s = staff(idh, soc.id, 20)
    target = idh.login(21)
    idh.seed_membership(soc.id, target.id, soc.units["A-101"], "tenant")
    for role in ("org_admin", "plat_support", "platform_admin", "owner_occ", "tenant", "nonsense"):
        r = grant(idh, s.secretary, soc.id, {
            "person_id": str(target.id), "role": role, "reason": "trying to escalate", "expires_at": iso(timedelta(days=1)),
        })  # fmt: skip
        assert r.status_code == 422 and r.json()["details"]["reason"] == "role_not_assignable", role
    assert idh.admin_rows(
        "SELECT count(*) FROM role_grants WHERE role IN ('org_admin','plat_support')"
    ) == [(0,)]
    # the database also requires a second, distinct approver for platform support
    with (
        pytest.raises(Exception, match="role_grants_support_approval"),
        idh.db.owner_conn() as conn,
    ):
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "INSERT INTO role_grants (society_id, person_id, role, issued_by, reason, expires_at, approved_by)"
            " VALUES (%s, %s, 'plat_support', %s, 'jit support', now() + interval '1 hour', %s)",
            (soc.id, target.id, s.secretary.id, s.secretary.id),
        )


@pytest.mark.req("IAM-02", "IAM-03")
def test_time_bound_roles_need_an_expiry_and_a_sane_window(idh: IdentityHarness) -> None:
    # REQ: IAM-02 IAM-03
    soc = idh.society()
    s = staff(idh, soc.id, 30)
    ca = idh.login(31)
    idh.seed_membership(soc.id, ca.id, soc.units["A-101"], "owner")
    base = {"person_id": str(ca.id), "role": "auditor", "reason": "Statutory audit FY 2025-26"}
    assert grant(idh, s.secretary, soc.id, base).json()["details"]["reason"] == "expiry_required"
    assert (
        grant(idh, s.secretary, soc.id, {**base, "expires_at": iso(timedelta(days=-1))}).json()[
            "details"
        ]["reason"]
        == "expiry_out_of_range"
    )
    assert (
        grant(idh, s.secretary, soc.id, {**base, "expires_at": iso(timedelta(days=900))}).json()[
            "details"
        ]["reason"]
        == "expiry_out_of_range"
    )
    assert (
        grant(idh, s.secretary, soc.id, {**base, "expires_at": iso(timedelta(days=60))}).status_code
        == 201
    )
    short = {"person_id": str(ca.id), "role": "guard", "reason": "x"}
    assert (
        grant(idh, s.secretary, soc.id, short).status_code == 400
    )  # reason too short for the schema
    elevated_short = {"person_id": str(ca.id), "role": "committee", "reason": "short"}
    assert (
        grant(idh, s.secretary, soc.id, elevated_short).json()["details"]["reason"]
        == "reason_required"
    )  # elevated: 10+


@pytest.mark.req("IAM-03", "IAM-13")
def test_only_a_secretary_with_mfa_can_grant_and_strangers_are_not_enumerable(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-03 IAM-13 INV-01
    soc = idh.society()
    s = staff(idh, soc.id, 40)
    tenant, stranger, target = idh.login(41), idh.login(42), idh.login(43)
    idh.seed_membership(soc.id, tenant.id, soc.units["A-101"], "tenant")
    body = {"person_id": str(target.id), "role": "guard", "reason": "needs gate access"}
    assert grant(idh, tenant, soc.id, body).status_code == 403
    assert grant(idh, s.committee, soc.id, body).status_code == 403
    assert grant(idh, stranger, soc.id, body).status_code == 404
    # a person unknown to THIS society and a random id both answer 404 (no person enumeration)
    assert grant(idh, s.secretary, soc.id, body).status_code == 404
    assert (
        grant(idh, s.secretary, soc.id, {**body, "person_id": str(uuid.uuid4())}).status_code == 404
    )
    # without a fresh MFA step-up even the secretary is refused
    with idh.db.admin_conn() as conn:
        conn.execute(
            "UPDATE iam.auth_sessions SET mfa_verified_at = NULL WHERE id = %s",
            (s.secretary.session_id,),
        )
    assert grant(idh, s.secretary, soc.id, {**body, "person_id": str(tenant.id)}).status_code == 403
    # exactly one of person_id / person_phone
    idh.elevate_session(s.secretary)
    assert (
        grant(
            idh, s.secretary, soc.id, {"role": "guard", "reason": "needs gate access"}
        ).status_code
        == 400
    )
    both = {**body, "person_phone": phone(9)}
    assert grant(idh, s.secretary, soc.id, both).status_code == 400


@pytest.mark.req("IAM-02", "IAM-06")
def test_grant_by_phone_introduces_a_staff_person_without_disclosing_existence(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-02 IAM-06
    soc = idh.society()
    s = staff(idh, soc.id, 50)
    known = idh.login(51)
    a = grant(
        idh,
        s.secretary,
        soc.id,
        {"person_phone": known.phone, "role": "guard", "reason": "Day shift guard"},
    )
    b = grant(
        idh,
        s.secretary,
        soc.id,
        {"person_phone": phone(5999), "role": "guard", "reason": "Day shift guard"},
    )
    assert a.status_code == b.status_code == 201
    assert {k for k in a.json() if k != "person_id"} == {k for k in b.json() if k != "person_id"}
    newbie = idh.login(5999)  # later proves control of the number: the grant is waiting
    roles = idh.client().get("/v1/me", headers=newbie.headers).json()["societies"][0]["roles"]
    assert roles[0]["role"] == "guard"


@pytest.mark.req("IAM-02")
def test_revoke_requires_a_reason_and_is_final(idh: IdentityHarness) -> None:
    # REQ: IAM-02
    soc = idh.society()
    s = staff(idh, soc.id, 60)
    g = idh.login(61)
    idh.seed_membership(soc.id, g.id, soc.units["A-101"], "staff", lives=False)
    gid = grant(
        idh,
        s.secretary,
        soc.id,
        {"person_id": str(g.id), "role": "guard", "reason": "Day shift guard"},
    ).json()["grant_id"]
    c = idh.client()
    url = f"/v1/societies/{soc.id}/role-grants/{gid}/revoke"
    assert c.post(url, json={"reason": "x"}, headers=s.secretary.headers).status_code == 400
    ok = c.post(url, json={"reason": "Left the security agency"}, headers=s.secretary.headers)
    assert ok.status_code == 200 and ok.json()["revoked"] is True
    again = c.post(url, json={"reason": "Left the security agency"}, headers=s.secretary.headers)
    assert again.status_code == 422 and again.json()["details"]["reason"] == "already_revoked"
    assert idh.audit_ops("role_grant.revoke")[0][4] == "Left the security agency"
    # unknown grant ids, and another society's, are plain 404s
    other = idh.society("Other")
    assert (
        c.post(
            f"/v1/societies/{other.id}/role-grants/{gid}/revoke",
            json={"reason": "wrong society probe"},
            headers=s.secretary.headers,
        ).status_code
        == 404
    )
    assert (
        c.post(
            f"/v1/societies/{soc.id}/role-grants/{uuid.uuid4()}/revoke",
            json={"reason": "no such grant id"},
            headers=s.secretary.headers,
        ).status_code
        == 404
    )
    # a revoked grant stays revoked and its history is immutable
    with pytest.raises(Exception, match=r"immutable|stays revoked"), idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute("UPDATE role_grants SET role = 'treasurer' WHERE id = %s", (gid,))


@pytest.mark.req("IAM-02", "INV-02")
def test_grant_creation_is_idempotent_and_payload_bound(idh: IdentityHarness) -> None:
    # REQ: IAM-02 INV-02
    soc = idh.society()
    s = staff(idh, soc.id, 70)
    g = idh.login(71)
    idh.seed_membership(soc.id, g.id, soc.units["A-101"], "staff", lives=False)
    body = {"person_id": str(g.id), "role": "guard", "reason": "Day shift guard"}
    key = f"grant-{uuid.uuid4()}"
    first = grant(idh, s.secretary, soc.id, body, key)
    replay = grant(idh, s.secretary, soc.id, body, key)
    assert (
        first.status_code == replay.status_code == 201
        and replay.headers["idempotent-replayed"] == "true"
    )
    assert first.json()["grant_id"] == replay.json()["grant_id"]
    assert idh.admin_rows("SELECT count(*) FROM role_grants WHERE role = 'guard'") == [(1,)]
    mismatch = grant(
        idh,
        s.secretary,
        soc.id,
        {**body, "role": "guard_sup", "reason": "Different payload!!"},
        key,
    )
    assert mismatch.status_code == 409 and mismatch.json()["code"] == "duplicate_payload_mismatch"
    no_key = idh.client(auto_key=False).post(
        f"/v1/societies/{soc.id}/role-grants", json=body, headers=s.secretary.headers
    )
    assert no_key.status_code == 400


@pytest.mark.req("IAM-03")
def test_maker_checker_helper_is_reusable() -> None:
    # REQ: IAM-03
    from dwaar_api.modules.identity.makerchecker import require_distinct
    from dwaar_common.errors import PolicyViolation

    a, b = uuid.uuid4(), uuid.uuid4()
    require_distinct(a, b)
    require_distinct(a, None, b)
    with pytest.raises(PolicyViolation) as err:
        require_distinct(a, b, a, what="bill_run")
    assert err.value.details == {"reason": "bill_run_same_person"}
