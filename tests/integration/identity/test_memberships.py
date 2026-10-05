# ruff: noqa: PT018, PT012, F811
"""IAM-01, IAM-13: memberships carry type/unit/dates/verification/evidence; applying never grants anything; register views."""

from __future__ import annotations

import pytest

from tests.integration.identity._support import IdentityHarness, apply_for, phone, staff


@pytest.mark.req("IAM-01", "IAM-13")
def test_applying_creates_a_pending_membership_and_a_case_and_no_access(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-01 IAM-13
    soc = idh.society()
    p = idh.login(1)
    out = apply_for(
        idh, p, soc.id, soc.units["A-101"], "tenant", evidence_ref="doc:rent-agreement-2026"
    )
    assert out["verification"] == "pending" and out["case_state"] == "requested"
    c = idh.client()
    assert (
        c.get(
            f"/v1/societies/{soc.id}/memberships", params={"purpose": "mine"}, headers=p.headers
        ).status_code
        == 404
    )
    me = c.get("/v1/me", headers=p.headers).json()["societies"][0]
    assert me["roles"][0]["active"] is False and me["roles"][0]["valid_now"] is False
    m = me["memberships"][0]
    assert (m["kind"], m["verification"], m["case"]["state"], m["unit_id"]) == (
        "tenant", "pending", "requested", str(soc.units["A-101"]),
    )  # fmt: skip
    assert idh.admin_rows("SELECT count(*) FROM role_grants") == [(0,)]
    ev = idh.admin_rows("SELECT evidence_ref FROM memberships")
    assert ev == [("doc:rent-agreement-2026",)]


@pytest.mark.req("IAM-13")
def test_no_sign_up_path_can_assign_platform_committee_or_any_role(idh: IdentityHarness) -> None:
    # REQ: IAM-13
    soc = idh.society()
    p = idh.login(2)
    c = idh.client()
    url = f"/v1/societies/{soc.id}/memberships"
    base = {"unit_id": str(soc.units["A-101"])}
    for extra in (
        {"kind": "committee"}, {"kind": "secretary"}, {"kind": "platform_admin"},
        {"kind": "owner", "role": "secretary"}, {"kind": "owner", "roles": ["committee"]},
        {"kind": "owner", "verification": "verified"}, {"kind": "owner", "society_id": str(soc.id)},
        {"kind": "owner", "is_primary_approver": True}, {"kind": "tenant", "scope": {"kind": "society"}},
    ):  # fmt: skip
        r = c.post(url, json={**base, **extra}, headers=p.headers)
        assert r.status_code == 400 and r.json()["code"] == "invalid_schema", extra
    assert idh.admin_rows("SELECT count(*) FROM role_grants") == [(0,)]
    assert idh.admin_rows("SELECT count(*) FROM memberships") == [(0,)]
    # staff memberships are made by the society, not by the applicant
    r = c.post(url, json={**base, "kind": "staff"}, headers=p.headers)
    assert (
        r.status_code == 422 and r.json()["details"]["reason"] == "staff_are_added_by_the_society"
    )
    # even a society-wide claim as owner stays a pending claim: the claimant has no owner powers
    apply_for(idh, p, soc.id, soc.units["A-101"], "owner")
    other = idh.login(3)
    tenancy = apply_for(idh, other, soc.id, soc.units["A-101"], "tenant")
    r = c.post(
        f"/v1/memberships/{tenancy['membership_id']}/owner-confirm",
        json={"decision": "confirm"},
        headers=p.headers,
    )
    assert r.status_code == 404  # an unverified "owner" cannot confirm anyone
    assert idh.admin_rows("SELECT count(*) FROM role_grants") == [(0,)]


@pytest.mark.req("IAM-13", "IAM-03")
def test_otp_login_and_membership_requests_never_write_a_grant_or_a_role(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-13 IAM-03
    soc = idh.society()
    p = idh.login(4)
    apply_for(idh, p, soc.id, soc.units["A-102"], "family")
    assert idh.admin_rows("SELECT count(*) FROM role_grants") == [(0,)]
    assert idh.admin_rows(
        "SELECT count(*) FROM iam.person_access_index WHERE source_kind = 'role_grant'"
    ) == [(0,)]
    # and the application role cannot write role_grants outside the grant API's society context
    with (
        pytest.raises(Exception, match=r"row-level security|permission denied"),
        idh.db.app_conn() as conn,
    ):
        conn.execute(
            "INSERT INTO role_grants (society_id, person_id, role, issued_by, reason) VALUES (%s, %s, 'committee', %s, 'forged')",
            (soc.id, p.id, idh.system_person()),
        )


@pytest.mark.req("IAM-01")
def test_duplicate_live_claim_is_refused_but_a_rejected_one_can_be_retried(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-01
    soc = idh.society()
    p = idh.login(5)
    first = apply_for(idh, p, soc.id, soc.units["A-101"], "tenant")
    r = idh.client().post(
        f"/v1/societies/{soc.id}/memberships",
        json={"unit_id": str(soc.units["A-101"]), "kind": "tenant"},
        headers=p.headers,
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "already_exists"
    with idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "UPDATE memberships SET verification = 'rejected' WHERE id = %s",
            (first["membership_id"],),
        )
    again = apply_for(idh, p, soc.id, soc.units["A-101"], "tenant")
    assert again["membership_id"] != first["membership_id"]


@pytest.mark.req("IAM-01", "IAM-06")
def test_secretary_adds_a_member_by_phone_without_disclosing_whether_the_person_exists(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-01 IAM-06
    soc = idh.society()
    s = staff(idh, soc.id, 10)
    known = idh.login(20)
    c = idh.client()
    url = f"/v1/societies/{soc.id}/memberships"
    a = c.post(
        url,
        json={"unit_id": str(soc.units["A-101"]), "kind": "owner", "person_phone": known.phone},
        headers=s.secretary.headers,
    )
    b = c.post(
        url,
        json={"unit_id": str(soc.units["A-102"]), "kind": "owner", "person_phone": phone(555)},
        headers=s.secretary.headers,
    )
    assert a.status_code == b.status_code == 201
    assert set(a.json()) == set(b.json())  # same shape; no person id, no "existing person" hint
    # the known person finds the pending membership at their next call; a stranger number became a stub person
    mine = c.get("/v1/me", headers=known.headers).json()["societies"][0]["memberships"]
    assert [m["verification"] for m in mine] == ["pending"]
    stub = idh.login(555)
    assert (
        c.get("/v1/me", headers=stub.headers).json()["societies"][0]["memberships"][0]["kind"]
        == "owner"
    )
    # only someone with the secretary permission may do this
    tenant = idh.login(21)
    idh.seed_membership(soc.id, tenant.id, soc.units["B-201"], "tenant")
    r = c.post(
        url,
        json={"unit_id": str(soc.units["B-201"]), "kind": "family", "person_phone": phone(556)},
        headers=tenant.headers,
    )
    assert r.status_code == 403
    r = c.post(
        url,
        json={"unit_id": str(soc.units["B-201"]), "kind": "family", "person_phone": phone(556)},
        headers=s.committee.headers,
    )
    assert r.status_code == 403  # committee is read-mostly


@pytest.mark.req("IAM-04", "IAM-01")
def test_member_register_views_and_privileged_read_logging(idh: IdentityHarness) -> None:
    # REQ: IAM-04 IAM-01 (PRD 5.2 unit and member register)
    soc = idh.society()
    s = staff(idh, soc.id, 30)
    guard = idh.login(40)
    idh.seed_grant(soc.id, guard.id, "guard")
    t = idh.login(41)
    mid = idh.seed_membership(soc.id, t.id, soc.units["A-101"], "tenant")
    with idh.db.admin_conn() as conn:
        conn.execute(
            "UPDATE iam.persons SET display_name = 'Anita Kulkarni' WHERE id = %s", (t.id,)
        )
    c = idh.client()
    url = f"/v1/societies/{soc.id}/memberships"
    full = c.get(url, params={"purpose": "annual member audit"}, headers=s.secretary.headers).json()
    row = next(i for i in full["items"] if i["id"] == str(mid))
    assert (
        row["display_name"] == "Anita Kulkarni"
        and row["person_id"] == str(t.id)
        and row["masked"] is False
    )
    masked = c.get(url, params={"purpose": "gate duty"}, headers=guard.headers).json()
    mrow = next(i for i in masked["items"] if i["id"] == str(mid))
    assert mrow["display_name"] == "A. K." and mrow["person_id"] is None and mrow["masked"] is True
    own = c.get(url, headers=t.headers).json()  # a resident needs no purpose for their OWN rows
    assert [i["id"] for i in own["items"]] == [str(mid)]
    # a privileged read without a purpose is refused
    assert c.get(url, headers=s.secretary.headers).status_code == 400
    assert c.get(url, params={"purpose": "x"}, headers=s.secretary.headers).status_code == 400
    # the audit rows carry purpose and scope, never member data
    rows = idh.audit_ops("read.membership_register")
    assert len(rows) == 2
    diffs = [r[3] for r in rows]
    assert {d["purpose"] for d in diffs} == {"annual member audit", "gate duty"}
    assert {d["scope"]["view"] for d in diffs} == {"full", "masked"}
    assert all("Kulkarni" not in str(r) for r in rows)
    assert all(r[1] == soc.id for r in rows)


@pytest.mark.req("IAM-01")
def test_register_pagination_is_cursor_based_and_bounded(idh: IdentityHarness) -> None:
    # REQ: IAM-01
    soc = idh.society(units=tuple(f"U-{i}" for i in range(5)))
    s = staff(idh, soc.id, 50)
    for i, label in enumerate(sorted(soc.units)):
        p = idh.login(60 + i)
        idh.seed_membership(soc.id, p.id, soc.units[label], "tenant")
    c = idh.client()
    url = f"/v1/societies/{soc.id}/memberships"
    seen: list[str] = []
    after = None
    for _ in range(5):
        params = {"purpose": "paging check", "limit": "2", **({"after": after} if after else {})}
        page = c.get(url, params=params, headers=s.secretary.headers).json()
        seen += [i["id"] for i in page["items"]]
        after = page["next_after"]
        if after is None:
            break
    assert len(seen) == len(set(seen)) == 5
    assert (
        c.get(
            url, params={"purpose": "too big", "limit": "101"}, headers=s.secretary.headers
        ).status_code
        == 400
    )


@pytest.mark.req("IAM-06", "IAM-01")
def test_membership_requests_are_rate_limited_per_person(idh: IdentityHarness) -> None:
    # REQ: IAM-06 IAM-01
    idh.tune(membership_request_capacity=2)
    soc = idh.society()
    p = idh.login(70)
    c = idh.client()
    codes = []
    for unit in ("A-101", "A-102", "B-201"):
        codes.append(
            c.post(
                f"/v1/societies/{soc.id}/memberships",
                json={"unit_id": str(soc.units[unit]), "kind": "family"},
                headers=p.headers,
            ).status_code
        )
    assert codes == [201, 201, 429]


@pytest.mark.req("IAM-01", "INV-02")
def test_membership_request_needs_an_idempotency_key_and_a_retry_never_duplicates(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-01 INV-02 (PRD 12: command creation is keyed by actor, society, endpoint and payload hash)
    soc = idh.society()
    p = idh.login(80)
    c = idh.client(auto_key=False)
    url = f"/v1/societies/{soc.id}/memberships"
    body = {"unit_id": str(soc.units["A-101"]), "kind": "tenant"}
    assert c.post(url, json=body, headers=p.headers).status_code == 400  # no key
    headers = {**p.headers, "Idempotency-Key": "retry-me-0001"}
    first = c.post(url, json=body, headers=headers)
    replay = c.post(
        url, json=body, headers=headers
    )  # e.g. the app retried after a dropped response
    assert first.status_code == replay.status_code == 201
    assert replay.headers["idempotent-replayed"] == "true"
    assert first.json()["membership_id"] == replay.json()["membership_id"]
    assert idh.admin_rows("SELECT count(*) FROM memberships") == [(1,)]
    assert idh.admin_rows("SELECT count(*) FROM verification_cases") == [(1,)]
    other = {"unit_id": str(soc.units["A-102"]), "kind": "tenant"}
    mismatch = c.post(url, json=other, headers=headers)
    assert mismatch.status_code == 409 and mismatch.json()["code"] == "duplicate_payload_mismatch"
