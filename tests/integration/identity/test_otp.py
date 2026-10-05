"""IAM-06: phone OTP with rate limits, expiry, abuse protection; no membership disclosure; plaintext never kept."""

from __future__ import annotations

import pytest

from tests.integration.identity._support import IdentityHarness, phone

pytestmark = pytest.mark.req("IAM-06")


def verify(c, num: str, code: str, device: str = "d1"):  # type: ignore[no-untyped-def]
    return c.post(
        "/v1/auth/otp/verify",
        json={"phone": num, "code": code, "device": {"device_id": device, "label": "Phone"}},
    )


def test_request_response_is_identical_for_known_and_unknown_numbers(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    known = idh.login(1)  # +9199999 00001 now belongs to a person
    c = idh.client()
    r_known = c.post("/v1/auth/otp/request", json={"phone": known.phone})
    r_unknown = c.post("/v1/auth/otp/request", json={"phone": phone(777)})
    assert r_known.status_code == r_unknown.status_code == 202
    assert r_known.json() == r_unknown.json()  # same body, same fields, same values
    assert set(r_known.headers) >= {"cache-control"}
    assert {k for k in r_known.headers if k.startswith("x-")} == {k for k in r_unknown.headers if k.startswith("x-")}


def test_phone_with_membership_and_phone_without_are_indistinguishable(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    soc = idh.society()
    member = idh.login(2)
    idh.seed_membership(soc.id, member.id, soc.units["A-101"], "owner")
    c = idh.client()
    a = c.post("/v1/auth/otp/request", json={"phone": member.phone})
    b = c.post("/v1/auth/otp/request", json={"phone": phone(778)})
    assert (a.status_code, a.json()) == (b.status_code, b.json())
    wrong_a = verify(c, member.phone, "000000")
    wrong_b = verify(c, phone(778), "000000")
    assert wrong_a.status_code == wrong_b.status_code == 401
    ja, jb = wrong_a.json(), wrong_b.json()
    assert {k: v for k, v in ja.items() if k != "request_id"} == {k: v for k, v in jb.items() if k != "request_id"}


def test_request_is_rate_limited_per_phone_and_the_limit_is_the_same_for_unknown_numbers(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    idh.tune(otp_request_capacity=3)
    idh.login(3)  # used one request of its own bucket
    c = idh.client()
    assert c.post("/v1/auth/otp/request", json={"phone": phone(779)}).status_code == 202  # same one request used
    for num in (phone(3), phone(779)):
        codes = [c.post("/v1/auth/otp/request", json={"phone": num}).status_code for _ in range(5)]
        # the harness allows a burst of 3 per number; known and unknown numbers hit 429 at the same point
        assert codes == [202, 202, 429, 429, 429]
    limited = c.post("/v1/auth/otp/request", json={"phone": phone(779)})
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1
    assert limited.json()["code"] == "rate_limited"


def test_per_ip_limit_applies_across_numbers(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    idh.tune(ip_capacity=4, ip_refill_seconds=3600)
    c = idh.client()
    statuses = [c.post("/v1/auth/otp/request", json={"phone": phone(800 + i)}).status_code for i in range(7)]
    assert statuses[:4] == [202] * 4
    assert 429 in statuses[4:]


def test_wrong_code_expired_code_and_replay_are_all_the_same_401(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    num = phone(10)
    c.post("/v1/auth/otp/request", json={"phone": num})
    code = idh.otp(num, c)
    wrong = "000000" if code != "000000" else "111111"
    r_wrong = verify(c, num, wrong)
    ok = verify(c, num, code)
    replay = verify(c, num, code)
    assert r_wrong.status_code == 401 and ok.status_code == 200 and replay.status_code == 401
    assert r_wrong.json()["code"] == replay.json()["code"] == "unauthenticated"
    assert r_wrong.json()["message"] == replay.json()["message"]
    # expiry
    c.post("/v1/auth/otp/request", json={"phone": phone(11)})
    code2 = idh.otp(phone(11), c)
    with idh.db.admin_conn() as conn:
        conn.execute("UPDATE iam.otp_challenges SET expires_at = now() - interval '1 second'")
    expired = verify(c, phone(11), code2)
    assert expired.status_code == 401 and expired.json()["code"] == "unauthenticated"


def test_attempts_are_capped_and_the_right_code_is_refused_after_lockout(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    num = phone(12)
    c.post("/v1/auth/otp/request", json={"phone": num})
    code = idh.otp(num, c)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert verify(c, num, wrong).status_code == 401
    assert verify(c, num, code).status_code == 401  # locked: even the correct code is refused now
    assert idh.audit_ops("auth.otp_locked")


def test_a_new_request_supersedes_the_old_code(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    num = phone(13)
    c.post("/v1/auth/otp/request", json={"phone": num})
    first = idh.otp(num, c)
    c.post("/v1/auth/otp/request", json={"phone": num})
    second = idh.otp(num, c)
    if first != second:
        assert verify(c, num, first).status_code == 401
    assert verify(c, num, second).status_code == 200


def test_otp_proves_control_of_a_number_not_ownership_or_tenancy(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    soc = idh.society()
    owner = idh.login(14)
    idh.seed_membership(soc.id, owner.id, soc.units["A-101"], "owner")
    newcomer = idh.login(15)  # proves control of THEIR number only
    me = idh.client().get("/v1/me", headers=newcomer.headers).json()
    assert me["societies"] == []  # no memberships, no roles inherited from anywhere
    r = idh.client().get(f"/v1/societies/{soc.id}/memberships", params={"purpose": "check"}, headers=newcomer.headers)
    assert r.status_code == 404


def test_plaintext_otp_is_never_stored(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    num = phone(16)
    c.post("/v1/auth/otp/request", json={"phone": num})
    code = idh.otp(num, c)
    rows = idh.admin_rows("SELECT code_hash, phone_token FROM iam.otp_challenges")
    for code_hash, token in rows:
        assert code not in code_hash and num not in token and code != code_hash
        assert len(code_hash) == 64
    payload = idh.admin_rows("SELECT payload_enc FROM iam.otp_deliveries")[0][0]
    assert code not in payload and num not in payload and payload.startswith("v1:")  # envelope ciphertext
    assert verify(c, num, code).status_code == 200
    # after consumption the delivery payload is gone too
    assert idh.admin_rows("SELECT payload_enc, state FROM iam.otp_deliveries")[0] == (None, "purged")
    dump = " ".join(str(r) for t in ("iam.persons", "iam.person_vault", "iam.auth_sessions", "audit_log")
                    for r in idh.admin_rows(f"SELECT * FROM {t}"))  # noqa: S608
    assert num not in dump  # the plain number is only ever in the encrypted vault


def test_invalid_numbers_are_rejected_before_anything_is_sent(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    for bad in ("12345678", "+15551234567", "99999", "abcdefghij"):
        r = c.post("/v1/auth/otp/request", json={"phone": bad})
        assert r.status_code == 400 and r.json()["code"] == "invalid_schema"
    assert idh.admin_rows("SELECT count(*) FROM iam.otp_challenges") == [(0,)]


def test_delivery_uses_a_dlt_template_and_is_labelled_simulated(idh: IdentityHarness) -> None:
    # REQ: IAM-06
    c = idh.client()
    c.post("/v1/auth/otp/request", json={"phone": phone(17)})
    template, state, sim = idh.admin_rows("SELECT template_id, state, simulation FROM iam.otp_deliveries")[0]
    assert template.startswith("SIM-DLT-") and state == "simulated_sent" and sim is True
    dev = c.get("/v1/dev/otp", params={"phone": phone(17)}).json()
    assert dev["simulation"] is True and "DEV-ONLY" in dev["warning"]
    assert dev["phone_masked"].endswith("0017") and "9999900017" not in dev["phone_masked"]
