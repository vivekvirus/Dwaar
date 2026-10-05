# ruff: noqa: PT018, PT012, F811
"""IAM-14: standard OIDC/JWT through a maintained library; labelled simulator only in local/test; real OIDC verifier path."""

from __future__ import annotations

import uuid

import jwt
import pytest

from dwaar_api.core.authn import OidcIdentityProvider
from dwaar_api.core.config import ConfigError
from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import TestIssuer, make_settings
from tests.integration.identity._support import (
    SHIM_PACKAGE,
    IdentityHarness,
    identity_harness,
    phone,
)

pytestmark = pytest.mark.req("IAM-14")


def test_simulator_serves_oidc_discovery_and_jwks_and_tokens_verify_against_them(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-14 IAM-08
    c = idh.client()
    disc = c.get("/.well-known/openid-configuration")
    assert disc.status_code == 200
    doc = disc.json()
    assert doc["simulation"] is True and "SIMULATOR" in doc["description"]
    assert doc["issuer"] == idh.rt.config.sim_issuer and doc["jwks_uri"].endswith(
        "/.well-known/jwks.json"
    )
    assert doc["id_token_signing_alg_values_supported"] == ["EdDSA"]
    jwks = c.get("/.well-known/jwks.json").json()
    assert [k["kty"] for k in jwks["keys"]] == ["OKP"] and jwks["keys"][0]["use"] == "sig"
    assert "d" not in jwks["keys"][0]  # public key only
    person = idh.login(1)
    key = jwt.PyJWKSet.from_dict(jwks)[jwks["keys"][0]["kid"]].key
    claims = jwt.decode(
        person.access, key, algorithms=["EdDSA"], audience="dwaar-api", issuer=doc["issuer"]
    )
    assert claims["sub"] == str(person.id) and claims["simulation"] is True
    assert uuid.UUID(claims["jti"]) and claims["sid"] == person.session_id
    # surfaced everywhere the client could look
    assert c.get("/v1/me", headers=person.headers).json()["simulation"] is True


def test_algorithm_confusion_and_tampering_are_rejected(idh: IdentityHarness) -> None:
    # REQ: IAM-14
    p = idh.login(2)
    c = idh.client()
    header, payload, _sig = p.access.split(".")
    for forged in (f"{header}.{payload}.", f"{header}.{payload}.AAAA", p.access[:-4] + "AAAA"):
        assert c.get("/v1/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_token = jwt.encode(
        {
            "sub": str(p.id),
            "iss": idh.rt.config.sim_issuer,
            "aud": "dwaar-api",
            "iat": 1,
            "exp": 2**31,
        },
        key=None,
        algorithm="none",
    )
    assert c.get("/v1/me", headers={"Authorization": f"Bearer {none_token}"}).status_code == 401
    hs = jwt.encode(
        {
            "sub": str(p.id),
            "sid": p.session_id,
            "iss": idh.rt.config.sim_issuer,
            "aud": "dwaar-api",
        },
        "secret" * 8,
        algorithm="HS256",
    )
    assert c.get("/v1/me", headers={"Authorization": f"Bearer {hs}"}).status_code == 401


def test_no_simulator_surface_and_no_issuer_in_staging(
    db: DbHandle, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REQ: IAM-14 IAM-06
    from dwaar_common.crypto import generate_key, key_to_b64

    monkeypatch.setenv("DWAAR_PII_KEYS", f"k1={key_to_b64(generate_key())}")
    monkeypatch.setenv("DWAAR_PII_ACTIVE_KEY_ID", "k1")
    monkeypatch.setenv("DWAAR_PHONE_HMAC_KEY", key_to_b64(generate_key()))
    settings = make_settings(
        db, env="staging", oidc_issuer_url="https://idp.example.invalid", oidc_jwks_url="https://idp.example.invalid/jwks",
        cors_origins="https://app.example.invalid",
    )  # fmt: skip
    database = Database.from_settings(settings)
    try:
        app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
        provider = app.state.identity_provider
        assert isinstance(provider, OidcIdentityProvider) and provider.simulation is False
        assert app.state.identity.issuer is None
        from fastapi.testclient import TestClient

        c = TestClient(app, raise_server_exceptions=False)
        for path in (
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/openapi.json",
            "/docs",
        ):
            assert c.get(path).status_code == 404, path
        assert c.get("/v1/dev/otp", params={"phone": phone(1)}).status_code == 404
        # OTP requests are accepted (delivery is the SMS gateway's job, which is blocked-external), labelled not-simulated
        r = c.post("/v1/auth/otp/request", json={"phone": phone(1)})
        assert r.status_code == 202 and r.json()["simulation"] is False
        with db.admin_conn() as conn:
            row = conn.execute("SELECT state, simulation FROM iam.otp_deliveries").fetchone()
        assert row == ("pending", False)  # waits for a real gateway; nothing pretends it was sent
        # a real IdP issues tokens; without that integration the exchange says so instead of minting its own
        enc = None
        with db.admin_conn() as conn:
            enc = conn.execute("SELECT payload_enc, id FROM iam.otp_deliveries").fetchone()
        import json

        from dwaar_api.modules.identity import crypto

        payload = json.loads(
            app.state.identity.config.cipher.decrypt(enc[0], crypto.delivery_aad(enc[1]))
        )
        v = c.post(
            "/v1/auth/otp/verify",
            json={
                "phone": phone(1),
                "code": payload["params"]["otp"],
                "device": {"device_id": "d"},
            },
        )
        assert v.status_code == 503 and v.json()["code"] == "dependency_unavailable"
    finally:
        database.dispose()


def test_identity_module_refuses_to_start_without_real_keys_outside_local_and_test(
    db: DbHandle, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REQ: ARCH-02 SEC-02
    for var in ("DWAAR_PII_KEYS", "DWAAR_PII_ACTIVE_KEY_ID", "DWAAR_PHONE_HMAC_KEY"):
        monkeypatch.delenv(var, raising=False)
    settings = make_settings(
        db, env="staging", oidc_issuer_url="https://idp.example.invalid", oidc_jwks_url="https://idp.example.invalid/jwks",
        cors_origins="https://app.example.invalid",
    )  # fmt: skip
    database = Database.from_settings(settings)
    try:
        with pytest.raises(ConfigError, match="DWAAR_PII_KEYS"):
            create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    finally:
        database.dispose()


def test_real_oidc_verifier_path_with_database_sessions_and_current_grants(db: DbHandle) -> None:
    # REQ: IAM-14 IAM-08 (tokens from a real-style external issuer: verified by the core JwtVerifier, then the DB decides)
    issuer = TestIssuer()
    settings = make_settings(db)
    database = Database.from_settings(settings)
    try:
        provider = OidcIdentityProvider(issuer.verifier(), name="external-test", simulation=False)
        app = create_app(
            settings, database=database, modules_package=SHIM_PACKAGE, identity_provider=provider
        )
        from dataclasses import replace

        from fastapi.testclient import TestClient

        app.state.identity.config = replace(app.state.identity.config, ip_capacity=1000)
        app.state.identity.auth.config = app.state.identity.config
        c = TestClient(app, raise_server_exceptions=False)
        # sign in through our OTP endpoints (the delivery queue is readable by the labelled dev endpoint in test env)
        c.post("/v1/auth/otp/request", json={"phone": phone(5)})
        code = c.get("/v1/dev/otp", params={"phone": phone(5)}).json()["otp"]
        login = c.post(
            "/v1/auth/otp/verify",
            json={"phone": phone(5), "code": code, "device": {"device_id": "d1"}},
        ).json()
        sid = login["session_id"]
        # the simulator's own token is NOT accepted: the configured issuer is the external one
        assert (
            c.get(
                "/v1/me", headers={"Authorization": f"Bearer {login['access_token']}"}
            ).status_code
            == 401
        )
        # find the person id from the database (the external IdP would put it in sub)
        with db.admin_conn() as conn:
            person_id = conn.execute(
                "SELECT person_id FROM iam.auth_sessions WHERE id = %s", (sid,)
            ).fetchone()[0]
        good = issuer.mint(person_id, session_id=sid)
        r = c.get("/v1/me", headers={"Authorization": f"Bearer {good}"})
        assert (
            r.status_code == 200 and r.json()["simulation"] is True
        )  # config flag of the module, not of the token
        assert (
            c.get(
                "/v1/me",
                headers={
                    "Authorization": f"Bearer {issuer.mint(person_id, session_id=str(uuid.uuid4()))}"
                },
            ).status_code
            == 401
        )
        assert (
            c.get(
                "/v1/me", headers={"Authorization": f"Bearer {issuer.mint(person_id)}"}
            ).status_code
            == 401
        )  # no sid claim
        wrong_audience = issuer.mint(person_id, session_id=sid, audience="someone-else")
        assert (
            c.get("/v1/me", headers={"Authorization": f"Bearer {wrong_audience}"}).status_code
            == 401
        )
        # revocation applies to externally issued tokens as well
        c.delete(f"/v1/auth/sessions/{sid}", headers={"Authorization": f"Bearer {good}"})
        assert c.get("/v1/me", headers={"Authorization": f"Bearer {good}"}).status_code == 401
    finally:
        database.dispose()


def test_harness_builds_independent_apps(db: DbHandle) -> None:
    # REQ: IAM-14
    with identity_harness(db) as one, identity_harness(db) as two:
        a = one.login(1)
        assert (
            two.client().get("/v1/me", headers=a.headers).status_code == 401
        )  # a different (ephemeral) issuer key
