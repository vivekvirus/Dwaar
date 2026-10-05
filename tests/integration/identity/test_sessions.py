# ruff: noqa: PT018, PT012, F811
"""IAM-08: short-lived access tokens, rotating refresh tokens with reuse detection, device list, revocation."""

from __future__ import annotations

import datetime as dt
import uuid

import jwt
import pytest

from tests.integration.identity._support import IdentityHarness

pytestmark = pytest.mark.req("IAM-08")


def me(idh: IdentityHarness, access: str) -> int:
    return idh.client().get("/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code


def test_access_token_is_short_lived_and_carries_only_standard_claims(idh: IdentityHarness) -> None:
    # REQ: IAM-08 IAM-14
    p = idh.login(1)
    claims = jwt.decode(p.access, options={"verify_signature": False})
    assert set(claims) == {"sub", "iss", "aud", "exp", "iat", "jti", "sid", "simulation"}
    assert (
        claims["simulation"] is True
        and claims["sub"] == str(p.id)
        and claims["sid"] == p.session_id
    )
    assert claims["exp"] - claims["iat"] == idh.rt.config.access_ttl_seconds <= 900
    header = jwt.get_unverified_header(p.access)
    assert header["alg"] == "EdDSA" and header["kid"] and header["typ"] == "at+jwt"
    assert not {"roles", "role", "society_id", "scope", "permissions"} & set(claims)


def test_refresh_rotates_and_the_old_token_is_single_use(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    p = idh.login(2)
    c = idh.client()
    r1 = c.post("/v1/auth/refresh", json={"refresh_token": p.refresh})
    assert r1.status_code == 200
    body = r1.json()
    assert body["refresh_token"] != p.refresh and body["access_token"] != p.access
    assert body["session_id"] == p.session_id  # same session (family), new token
    assert me(idh, body["access_token"]) == 200
    r2 = c.post("/v1/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert r2.status_code == 200


def test_reuse_of_a_rotated_refresh_token_revokes_the_whole_family(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    p = idh.login(3)
    c = idh.client()
    newer = c.post("/v1/auth/refresh", json={"refresh_token": p.refresh}).json()
    assert me(idh, newer["access_token"]) == 200
    stolen_replay = c.post(
        "/v1/auth/refresh", json={"refresh_token": p.refresh}
    )  # the OLD token again
    assert stolen_replay.status_code == 401 and stolen_replay.json()["code"] == "unauthenticated"
    # the legitimate newest token is dead too, and so is every access token of that session
    assert (
        c.post("/v1/auth/refresh", json={"refresh_token": newer["refresh_token"]}).status_code
        == 401
    )
    assert me(idh, newer["access_token"]) == 401
    assert me(idh, p.access) == 401
    assert idh.admin_rows(
        "SELECT revoked_reason FROM iam.auth_sessions WHERE id = %s", (p.session_id,)
    ) == [("refresh_reuse",)]
    assert idh.audit_ops("auth.refresh_reuse_detected")


def test_refresh_reuse_only_kills_that_session_not_the_other_devices(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    phone_a = idh.login(4, device="phone")
    c = idh.client()
    c.post("/v1/auth/otp/request", json={"phone": phone_a.phone})
    other = idh.login(phone_a.phone, device="tablet")
    c.post("/v1/auth/refresh", json={"refresh_token": phone_a.refresh})
    assert c.post("/v1/auth/refresh", json={"refresh_token": phone_a.refresh}).status_code == 401
    assert me(idh, other.access) == 200


def test_revoking_a_session_makes_its_access_token_unusable_immediately(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-08
    first = idh.login(5, device="phone")
    second = idh.login(first.phone, device="tablet")
    c = idh.client()
    listed = c.get("/v1/auth/sessions", headers=second.headers).json()["sessions"]
    assert {s["device_id"] for s in listed} == {"phone", "tablet"}
    assert [s["device_id"] for s in listed if s["current"]] == ["tablet"]
    assert me(idh, first.access) == 200
    r = c.delete(f"/v1/auth/sessions/{first.session_id}", headers=second.headers)
    assert r.status_code == 204
    assert (
        me(idh, first.access) == 401
    )  # well before exp: revocation is a database fact, not a token claim
    assert c.post("/v1/auth/refresh", json={"refresh_token": first.refresh}).status_code == 401
    assert me(idh, second.access) == 200


def test_cannot_revoke_or_see_someone_elses_session(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    a, b = idh.login(6), idh.login(7)
    c = idh.client()
    r = c.delete(f"/v1/auth/sessions/{a.session_id}", headers=b.headers)
    assert r.status_code == 404
    assert c.delete(f"/v1/auth/sessions/{uuid.uuid4()}", headers=b.headers).status_code == 404
    assert me(idh, a.access) == 200
    assert all(
        s["device_id"] for s in c.get("/v1/auth/sessions", headers=b.headers).json()["sessions"]
    )
    assert len(c.get("/v1/auth/sessions", headers=b.headers).json()["sessions"]) == 1


def test_logout_and_revoke_others(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    one = idh.login(8, device="one")
    two = idh.login(one.phone, device="two")
    three = idh.login(one.phone, device="three")
    c = idh.client()
    assert c.delete("/v1/auth/sessions", headers=three.headers).json() == {"revoked": 2}
    assert me(idh, one.access) == me(idh, two.access) == 401 and me(idh, three.access) == 200
    assert c.post("/v1/auth/logout", headers=three.headers).status_code == 204
    assert me(idh, three.access) == 401


def test_token_without_a_live_session_is_refused_even_if_validly_signed(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-08
    p = idh.login(9)
    issuer = idh.rt.issuer
    forged_sid = issuer.mint(
        p.id, uuid.uuid4(), ttl_seconds=300
    )  # right person, signed by us, no such session
    assert me(idh, forged_sid) == 401
    other = idh.login(19)
    assert (
        me(idh, issuer.mint(p.id, uuid.UUID(other.session_id), ttl_seconds=300)) == 401
    )  # someone else's session


def test_expired_and_overlong_tokens_are_refused(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    p = idh.login(20)
    issuer = idh.rt.issuer
    assert me(idh, issuer.mint(p.id, uuid.UUID(p.session_id), ttl_seconds=-120)) == 401
    assert (
        me(idh, issuer.mint(p.id, uuid.UUID(p.session_id), ttl_seconds=86_400)) == 401
    )  # exp - iat above the cap
    assert me(idh, issuer.mint(p.id, uuid.UUID(p.session_id), ttl_seconds=600)) == 200


def test_refresh_token_expiry_and_garbage(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    p = idh.login(21)
    c = idh.client()
    with idh.db.admin_conn() as conn:
        conn.execute("UPDATE iam.refresh_tokens SET expires_at = now() - interval '1 second'")
    assert c.post("/v1/auth/refresh", json={"refresh_token": p.refresh}).status_code == 401
    assert c.post("/v1/auth/refresh", json={"refresh_token": "x" * 40}).status_code == 401
    assert c.post("/v1/auth/refresh", json={}).status_code == 400


def test_device_list_is_bounded(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    idh.tune(max_sessions_per_person=3)
    first = idh.login(22, device="d0")
    for i in range(1, 5):
        idh.login(first.phone, device=f"d{i}")
    live = idh.admin_rows("SELECT count(*) FROM iam.auth_sessions WHERE revoked_at IS NULL")
    assert live == [(3,)]
    assert me(idh, first.access) == 401  # the oldest device was dropped


def test_session_ttl_is_absolute(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    p = idh.login(23)
    with idh.db.admin_conn() as conn:
        conn.execute("UPDATE iam.auth_sessions SET expires_at = now() - interval '1 second'")
    assert me(idh, p.access) == 401


def test_token_time_claims_are_utc_and_close_to_now(idh: IdentityHarness) -> None:
    # REQ: IAM-08
    p = idh.login(24)
    claims = jwt.decode(p.access, options={"verify_signature": False})
    now = dt.datetime.now(dt.UTC).timestamp()
    assert abs(claims["iat"] - now) < 30
