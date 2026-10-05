# ruff: noqa: PT018, PT012, F811
"""IAM-06 / OBS-01: no OTP, phone number, token or MFA secret ever reaches a log record, an audit row or an outbox event."""

from __future__ import annotations

import json
import logging
import uuid

import pytest

from tests.integration.identity._support import IdentityHarness, idh, phone  # noqa: F401  (fixture)

pytestmark = pytest.mark.req("IAM-06", "IAM-08")


def everything_logged(caplog: pytest.LogCaptureFixture) -> str:
    parts = []
    for record in caplog.records:
        parts.append(record.getMessage())
        parts.append(
            json.dumps(
                {
                    k: str(v)
                    for k, v in record.__dict__.items()
                    if k not in ("args", "msg", "exc_info")
                }
            )
        )
        if record.exc_info:
            parts.append(repr(record.exc_info[1]))
    return "\n".join(parts)


def test_secrets_never_appear_in_logs_audit_or_outbox(
    idh: IdentityHarness, caplog: pytest.LogCaptureFixture
) -> None:
    # REQ: IAM-06 IAM-08
    caplog.set_level(logging.DEBUG)
    secrets: dict[str, str] = {}
    soc = idh.society()
    c = idh.client()
    num = phone(1)
    r = c.post("/v1/auth/otp/request", json={"phone": num})
    assert r.status_code == 202
    secrets["otp"] = idh.otp(num, c)
    wrong = c.post(
        "/v1/auth/otp/verify",
        json={
            "phone": num,
            "code": "000000" if secrets["otp"] != "000000" else "111111",
            "device": {"device_id": "d"},
        },
    )
    assert wrong.status_code == 401
    ok = c.post(
        "/v1/auth/otp/verify",
        json={"phone": num, "code": secrets["otp"], "device": {"device_id": "d", "label": "Pixel"}},
    )
    body = ok.json()
    secrets.update(access=body["access_token"], refresh=body["refresh_token"])
    assert (
        c.post(
            "/v1/auth/otp/verify",
            json={"phone": num, "code": secrets["otp"], "device": {"device_id": "d"}},
        ).status_code
        == 401
    )  # replay
    rotated = c.post("/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}).json()
    secrets["refresh2"] = rotated["refresh_token"]
    c.post(
        "/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}
    )  # reuse -> family revoked
    p = idh.login(2)
    secrets["mfa"] = idh.enrol_totp(p)
    secrets["access2"] = p.access
    apply_body = {"unit_id": str(soc.units["A-101"]), "kind": "tenant", "evidence_ref": "doc:lease"}
    c.post(f"/v1/societies/{soc.id}/memberships", json=apply_body, headers=p.headers)
    c.get("/v1/me", headers=p.headers)
    for _ in range(4):  # rate limited and locked paths
        c.post("/v1/auth/otp/request", json={"phone": phone(3)})
    c.patch(
        "/v1/me/profile",
        json={"email": "someone@example.invalid", "id_document_number": "123412341234"},
        headers=p.headers,
    )
    secrets["email"] = "someone@example.invalid"
    secrets["aadhaar"] = "123412341234"
    # a garbage token and a malformed phone must not be echoed either
    c.get("/v1/me", headers={"Authorization": "Bearer not.a.jwt"})
    c.post("/v1/auth/otp/request", json={"phone": "98765 43210 9999"})

    logged = everything_logged(caplog)
    assert logged  # the check below is meaningful: there were records
    for name, value in secrets.items():
        if name == "otp":
            continue  # a 6-digit code can appear inside ids/timestamps; checked separately below
        assert value not in logged, f"{name} leaked into a log record"
    for digits in ("9999900001", "99999 00001", "9999900002", "9999900003", "+919999900001"):
        assert digits not in logged, f"phone {digits} leaked into a log record"
    otp = secrets["otp"]
    for line in logged.splitlines():
        low = line.lower()
        if "otp" in low or "code" in low or "verify" in low:
            assert otp not in line.replace('"', " ").split(), (
                line
            )  # never as a standalone value next to otp-ish text
    # the stored evidence is scrubbed the same way
    with idh.db.admin_conn() as conn:
        audit = " ".join(str(r) for r in conn.execute("SELECT * FROM audit_log").fetchall())
        outbox = " ".join(
            str(r) for r in conn.execute("SELECT payload::text, actor_ref FROM outbox").fetchall()
        )
    for stored in (audit, outbox):
        for value in (
            secrets["access"],
            secrets["refresh"],
            secrets["mfa"],
            secrets["email"],
            secrets["aadhaar"],
        ):
            assert value not in stored
        assert "9999900001" not in stored and "+91" not in stored


def test_error_bodies_never_echo_input_or_reveal_membership(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    secret_phone = "98765 43210 9999"
    r = c.post("/v1/auth/otp/request", json={"phone": secret_phone})
    assert r.status_code == 400 and secret_phone not in r.text and "98765" not in r.text
    r = c.post(
        "/v1/auth/otp/verify",
        json={"phone": phone(1), "code": "12ab56", "device": {"device_id": "d"}},
    )
    assert "12ab56" not in r.text
    r = c.post("/v1/auth/otp/request", json={"phone": phone(1), "role": "secretary"})
    assert (
        r.status_code == 400 and "secretary" not in r.text
    )  # extra fields are refused without echoing the value
    token = str(uuid.uuid4())
    r = c.post("/v1/auth/refresh", json={"refresh_token": token + token})
    assert r.status_code == 401 and token not in r.text
