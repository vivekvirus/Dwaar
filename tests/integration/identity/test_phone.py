# ruff: noqa: PT018, PT012, F811
"""IAM-11: recycled phone numbers inherit nothing; a number change revokes sessions and re-opens verification."""

from __future__ import annotations

import pytest

from dwaar_common.crypto import build_aad
from tests.integration.identity._support import IdentityHarness, advance, phone, staff

pytestmark = pytest.mark.req("IAM-11")


def me(idh: IdentityHarness, access: str) -> int:
    return idh.client().get("/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code


def test_a_recycled_number_does_not_inherit_the_old_holders_memberships(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-11
    soc = idh.society()
    old = idh.login(1)
    idh.seed_membership(soc.id, old.id, soc.units["A-101"], "owner")
    c = idh.client()
    assert c.get(f"/v1/societies/{soc.id}/memberships", headers=old.headers).status_code == 200
    # the carrier recycles the number after the old holder stopped using it long ago
    with idh.db.admin_conn() as conn:
        conn.execute(
            "UPDATE iam.persons SET phone_verified_at = now() - interval '200 days' WHERE id = %s",
            (old.id,),
        )
    new_holder = idh.login(old.phone, device="new-phone")
    assert new_holder.id != old.id  # a NEW person, not the old one
    assert c.get("/v1/me", headers=new_holder.headers).json()["societies"] == []
    assert (
        c.get(f"/v1/societies/{soc.id}/memberships", headers=new_holder.headers).status_code == 404
    )
    # the old person lost the number and every session; their memberships still belong to THEM
    assert me(idh, old.access) == 401
    assert c.post("/v1/auth/refresh", json={"refresh_token": old.refresh}).status_code == 401
    status, released = idh.admin_rows(
        "SELECT status, phone_token LIKE 'released:%%' FROM iam.persons WHERE id = %s", (old.id,)
    )[0]
    assert (status, released) == ("phone_released", True)
    assert idh.admin_rows("SELECT count(*) FROM memberships WHERE person_id = %s", (old.id,)) == [
        (1,)
    ]
    assert idh.audit_ops("auth.phone_recycled")


def test_an_active_number_is_not_treated_as_recycled(idh: IdentityHarness) -> None:
    # REQ: IAM-11
    soc = idh.society()
    p = idh.login(2)
    idh.seed_membership(soc.id, p.id, soc.units["A-101"], "tenant")
    with idh.db.admin_conn() as conn:
        conn.execute(
            "UPDATE iam.persons SET phone_verified_at = now() - interval '30 days' WHERE id = %s",
            (p.id,),
        )
    again = idh.login(p.phone, device="same-person")
    assert again.id == p.id
    assert (
        idh.client().get(f"/v1/societies/{soc.id}/memberships", headers=again.headers).status_code
        == 200
    )


def test_dormancy_threshold_is_configuration(idh: IdentityHarness) -> None:
    # REQ: IAM-11 INV-10
    idh.tune(phone_dormancy_days=7)
    p = idh.login(3)
    with idh.db.admin_conn() as conn:
        conn.execute(
            "UPDATE iam.persons SET phone_verified_at = now() - interval '10 days' WHERE id = %s",
            (p.id,),
        )
    assert idh.login(p.phone, device="later").id != p.id


def test_number_change_revokes_old_sessions_and_reopens_verification(idh: IdentityHarness) -> None:
    # REQ: IAM-11
    soc = idh.society()
    s = staff(idh, soc.id, 10)
    p = idh.login(4)
    other_device = idh.login(p.phone, device="tablet")
    mid = idh.seed_membership(
        soc.id, p.id, soc.units["A-101"], "tenant", owner_decision="confirmed"
    )
    c = idh.client()
    new_number = phone(4444)
    assert (
        c.post("/v1/auth/phone/change/request", json={"phone": new_number}).status_code == 401
    )  # needs a session
    r = c.post("/v1/auth/phone/change/request", json={"phone": new_number}, headers=p.headers)
    assert r.status_code == 202
    code = idh.otp(new_number, c)
    bad = c.post(
        "/v1/auth/phone/change/confirm",
        json={"phone": new_number, "code": "000000"},
        headers=p.headers,
    )
    assert bad.status_code == 401
    # someone else cannot complete a change started by this person
    intruder = idh.login(5)
    stolen = c.post(
        "/v1/auth/phone/change/confirm",
        json={"phone": new_number, "code": code},
        headers=intruder.headers,
    )
    assert stolen.status_code == 401
    # (the challenge was spent by that attempt; the real person asks again)
    assert (
        c.post(
            "/v1/auth/phone/change/request", json={"phone": new_number}, headers=p.headers
        ).status_code
        == 202
    )
    code = idh.otp(new_number, c)
    ok = c.post(
        "/v1/auth/phone/change/confirm", json={"phone": new_number, "code": code}, headers=p.headers
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["sessions_revoked"] is True and ok.json()["reverification_required_in"] == [
        str(soc.id)
    ]
    # all old sessions are dead, on every device
    assert me(idh, p.access) == 401 and me(idh, other_device.access) == 401
    assert c.post("/v1/auth/refresh", json={"refresh_token": p.refresh}).status_code == 401
    # signing in with the NEW number reaches the same person, but the memberships are back under review
    fresh = idh.login(new_number)
    assert fresh.id == p.id
    body = c.get("/v1/me", headers=fresh.headers).json()["societies"][0]
    assert body["memberships"][0]["verification"] == "reverification"
    assert (
        body["memberships"][0]["case"]["kind"] == "reverification"
        and body["memberships"][0]["case"]["state"] == "evidence_pending"
    )
    assert body["roles"][0]["valid_now"] is False
    assert c.get(f"/v1/societies/{soc.id}/memberships", headers=fresh.headers).status_code == 404
    # the OLD number no longer reaches this person
    again = idh.login(p.phone, device="whoever-holds-it-now")
    assert again.id != p.id
    # the vault holds the new number (encrypted) and the token moved
    enc = idh.admin_rows("SELECT phone_enc FROM iam.person_vault WHERE person_id = %s", (p.id,))[0][
        0
    ]
    assert new_number not in enc
    assert idh.rt.config.cipher.decrypt(enc, build_aad("person_vault", "phone", p.id)) == new_number
    # the society re-verifies (a human decision) and the grants come back
    case = body["memberships"][0]["case"]["id"]
    assert (
        advance(
            idh, fresh, soc.id, case, "submit_evidence", evidence_ref="doc:aadhaar-masked"
        ).status_code
        == 200
    )
    assert advance(idh, s.secretary, soc.id, case, "verify").json()["state"] == "verified"
    assert c.get(f"/v1/societies/{soc.id}/memberships", headers=fresh.headers).status_code == 200
    assert idh.audit_ops("auth.phone_changed") and idh.audit_ops("membership.reverify")
    assert idh.admin_rows("SELECT verification FROM memberships WHERE id = %s", (mid,)) == [
        ("verified",)
    ]


def test_number_change_to_a_number_that_belongs_to_someone_else_is_a_generic_conflict(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-11 IAM-06
    a, b = idh.login(20), idh.login(21)
    c = idh.client()
    c.post("/v1/auth/phone/change/request", json={"phone": b.phone}, headers=a.headers)
    code = idh.otp(b.phone, c)
    r = c.post(
        "/v1/auth/phone/change/confirm", json={"phone": b.phone, "code": code}, headers=a.headers
    )
    assert (
        r.status_code == 409 and r.json()["code"] == "stale_version"
    )  # does not say "that number is taken"
    assert me(idh, a.access) == 200  # nothing changed, nothing revoked
    assert idh.admin_rows(
        "SELECT count(*) FROM iam.persons WHERE phone_token LIKE 'released:%%'"
    ) == [(0,)]
