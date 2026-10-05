# ruff: noqa: PT018, PT012, F811
"""IAM-03: TOTP step-up for elevated roles (maintained library pyotp), replay refused, factor secret encrypted."""

from __future__ import annotations

import time

import pyotp
import pytest

from tests.integration.identity._support import IdentityHarness

pytestmark = pytest.mark.req("IAM-03")


def test_enrol_confirm_and_step_up_unlock_an_elevated_role(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    soc = idh.society()
    sec = idh.login(1)
    idh.seed_grant(soc.id, sec.id, "secretary")
    c = idh.client()
    url = f"/v1/societies/{soc.id}/role-grants"
    assert c.get(url, params={"purpose": "audit"}, headers=sec.headers).status_code == 403
    secret = idh.enrol_totp(sec)
    assert c.get("/v1/me", headers=sec.headers).json()["mfa"] == {
        "enrolled": True, "confirmed": False, "session_verified": False, "required_for_roles": True,
    }  # fmt: skip
    bad = c.post("/v1/auth/mfa/totp/confirm", json={"code": "000000"}, headers=sec.headers)
    assert bad.status_code == 401
    code = idh.totp_code(sec)
    ok = c.post("/v1/auth/mfa/totp/confirm", json={"code": code}, headers=sec.headers)
    assert ok.status_code == 200 and ok.json()["session_elevated"] is True
    assert c.get(url, params={"purpose": "audit"}, headers=sec.headers).status_code == 200
    # a SECOND session needs its own step-up with a fresh code (a TOTP step is single use)
    other = idh.login(sec.phone, device="laptop")
    assert c.get(url, params={"purpose": "audit"}, headers=other.headers).status_code == 403
    again = c.post("/v1/auth/mfa/verify", json={"code": code}, headers=other.headers)
    assert again.status_code == 401  # same time step as the confirmation: replay refused
    fresh = c.post(
        "/v1/auth/mfa/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
        headers=other.headers,
    )
    assert fresh.status_code == 200
    assert c.get(url, params={"purpose": "audit"}, headers=other.headers).status_code == 200


def test_verify_before_confirm_and_without_enrolment_is_refused(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    p = idh.login(2)
    c = idh.client()
    r = c.post("/v1/auth/mfa/verify", json={"code": "123456"}, headers=p.headers)
    assert r.status_code == 422 and r.json()["details"]["reason"] == "mfa_not_enrolled"
    idh.enrol_totp(p)
    r = c.post("/v1/auth/mfa/verify", json={"code": idh.totp_code(p)}, headers=p.headers)
    assert r.status_code == 422 and r.json()["details"]["reason"] == "mfa_not_confirmed"


def test_secret_is_encrypted_at_rest_and_never_returned_again(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    p = idh.login(3)
    secret = idh.enrol_totp(p)
    stored = idh.admin_rows("SELECT secret_enc FROM iam.mfa_factors")[0][0]
    assert secret not in stored and stored.startswith("v1:")
    me = idh.client().get("/v1/me", headers=p.headers).text
    assert secret not in me
    again = idh.client().post("/v1/auth/mfa/totp/enrol", headers=p.headers)
    assert (
        again.status_code == 201 and again.json()["secret"] != secret
    )  # unconfirmed: replaced, not stacked


def test_confirmed_factor_is_not_silently_replaced(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    p = idh.login(4)
    idh.enrol_totp(p)
    c = idh.client()
    assert (
        c.post(
            "/v1/auth/mfa/totp/confirm", json={"code": idh.totp_code(p)}, headers=p.headers
        ).status_code
        == 200
    )
    r = c.post("/v1/auth/mfa/totp/enrol", headers=p.headers)
    assert r.status_code == 422 and r.json()["details"]["reason"] == "mfa_already_enrolled"


def test_mfa_attempts_are_rate_limited(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    p = idh.login(5)
    idh.enrol_totp(p)
    c = idh.client()
    codes = [
        c.post("/v1/auth/mfa/totp/confirm", json={"code": "000000"}, headers=p.headers).status_code
        for _ in range(7)
    ]
    assert codes[:5] == [401] * 5 and codes[-1] == 429


def test_wrong_codes_are_audited_without_the_code(idh: IdentityHarness) -> None:
    # REQ: IAM-03 IAM-04
    p = idh.login(6)
    idh.enrol_totp(p)
    idh.client().post("/v1/auth/mfa/totp/confirm", json={"code": "654321"}, headers=p.headers)
    rows = idh.audit_ops("auth.mfa_failed")
    assert len(rows) == 1 and "654321" not in str(rows[0])
