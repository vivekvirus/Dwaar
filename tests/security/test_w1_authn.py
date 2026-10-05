"""Regression tests from W1 verification and fix round 1: JWT verifier, JWKS handling, role-claim trust,
token lifetime and the revocation store (IAM-14, IAM-08, INV-01). Fixed in round 1: F15, F16."""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import base64
import datetime as dt
import http.server
import json
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_api.core.authn import JwtVerifier, RemoteJwks
from dwaar_common.errors import Unauthenticated
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    AUDIENCE,
    ISSUER,
    OUTSIDER,
    RESIDENT_A,
    SOCIETY_A,
    CoreHarness,
    TestIssuer,
    core_harness,
)

pytestmark = pytest.mark.req("IAM-14", "IAM-08", "INV-01")

PERSON = uuid.UUID("0192f300-0000-7000-8000-0000000000c1")


@pytest.fixture(scope="module")
def issuer() -> TestIssuer:
    return TestIssuer()


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


def _b64(data: dict[str, Any] | bytes) -> str:
    raw = data if isinstance(data, bytes) else json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _claims(**kw: Any) -> dict[str, Any]:
    now = int(dt.datetime.now(dt.UTC).timestamp())
    base: dict[str, Any] = {
        "sub": str(PERSON),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 600,
    }
    base.update(kw)
    return base


def _rejected(verifier: JwtVerifier, token: str) -> bool:
    try:
        verifier.verify(token)
    except Unauthenticated:
        return True
    return False


# ------------------------------------------------------------------------------------------------
# header games
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "extra_header",
    [
        {"jku": "https://attacker.invalid/jwks.json"},
        {"x5u": "https://attacker.invalid/cert.pem"},
        {"x5c": ["AAAA"]},
        {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}},
        {"kid": ["a", "b"]},
        {"kid": {"$ne": None}},
        {"kid": 1},
        {"kid": ""},
        {"kid": "../../etc/passwd"},
        {"kid": "x" * 10_000},
        {"kid": "test-key-1\x00evil"},
    ],
)
def test_attacker_controlled_key_headers_never_select_a_key(
    issuer: TestIssuer, extra_header: dict[str, Any]
) -> None:
    attacker = Ed25519PrivateKey.generate()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": issuer.kid, **extra_header}
    signing_input = f"{_b64(header)}.{_b64(_claims())}".encode()
    forged = f"{signing_input.decode()}.{_b64(attacker.sign(signing_input))}"
    assert _rejected(issuer.verifier(), forged)


def test_unknown_critical_header_extension_is_rejected(issuer: TestIssuer) -> None:
    """RFC 7515 4.1.11: a verifier MUST reject a JWS whose crit lists an extension it does not understand."""
    token = jwt.encode(
        _claims(),
        issuer.private_key,
        algorithm="EdDSA",
        headers={"kid": issuer.kid, "crit": ["x-evil"], "x-evil": 1},
    )
    assert _rejected(issuer.verifier(), token)


# ------------------------------------------------------------------------------------------------
# time claims
# ------------------------------------------------------------------------------------------------
def test_expiry_and_nbf_skew_boundaries(issuer: TestIssuer) -> None:
    verifier = issuer.verifier(leeway_seconds=30)
    now = int(dt.datetime.now(dt.UTC).timestamp())
    assert not _rejected(verifier, issuer.mint(PERSON, extra={"exp": now - 20}))  # inside leeway
    assert _rejected(verifier, issuer.mint(PERSON, extra={"exp": now - 40}))
    assert not _rejected(verifier, issuer.mint(PERSON, nbf_offset=20))
    assert _rejected(verifier, issuer.mint(PERSON, nbf_offset=40))
    assert _rejected(
        verifier, issuer.mint(PERSON, extra={"iat": now + 3600})
    )  # issued in the future


@pytest.mark.parametrize("bad_exp", [None, True, [1], {"a": 1}, 1e400, float("nan")])
def test_malformed_time_claims_are_rejected(issuer: TestIssuer, bad_exp: Any) -> None:
    claims = _claims()
    claims["exp"] = bad_exp
    token = f"{_b64({'alg': 'EdDSA', 'kid': issuer.kid})}.{_b64(json.dumps(claims, allow_nan=True).encode())}"
    token += "." + _b64(issuer.private_key.sign(token.encode()))
    assert _rejected(issuer.verifier(), token)


def test_access_token_lifetime_is_capped_by_the_verifier(issuer: TestIssuer) -> None:
    """IAM-08 demands short-lived access tokens, but the verifier accepts whatever exp the issuer signs:
    a misconfigured or compromised IdP (or a leaked long-lived token) is valid for years."""
    ten_years = 10 * 365 * 86400
    token = issuer.mint(PERSON, ttl=ten_years)
    assert _rejected(issuer.verifier(), token), "a 10 year access token verified"


# ------------------------------------------------------------------------------------------------
# audience / issuer / subject
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "aud", [[], [""], "", ["other"], 123, [AUDIENCE.upper()], AUDIENCE + " ", [None]]
)
def test_bad_audiences_are_rejected(issuer: TestIssuer, aud: Any) -> None:
    assert _rejected(issuer.verifier(), issuer.mint(PERSON, audience=aud))


@pytest.mark.parametrize(
    "iss", ["", ISSUER + "/", ISSUER.upper(), "https://issuer.test.invalid.evil.example"]
)
def test_bad_issuers_are_rejected(issuer: TestIssuer, iss: Any) -> None:
    assert _rejected(issuer.verifier(), issuer.mint(PERSON, extra={"iss": iss}))


@pytest.mark.parametrize("sub", ["", None, 12, [str(PERSON)], {"id": 1}, True])
def test_bad_subjects_are_rejected(issuer: TestIssuer, sub: Any) -> None:
    assert _rejected(issuer.verifier(), issuer.mint(PERSON, extra={"sub": sub}))


# ------------------------------------------------------------------------------------------------
# role claims are never trusted
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "extra",
    [
        {"role": "committee"},
        {"roles": ["committee", "admin"]},
        {"realm_access": {"roles": ["committee"]}},
        {"app_metadata": {"role": "committee", "society_id": str(SOCIETY_A)}},
        {"society_id": str(SOCIETY_A), "actor_role": "committee"},
        {"scope": "probe.write probe.read admin"},
        {"https://dwaar.example/roles": ["committee"]},
    ],
)
def test_role_and_society_claims_in_the_token_grant_nothing(
    core: CoreHarness, extra: dict[str, Any]
) -> None:
    client = core.client()
    for person in (OUTSIDER, RESIDENT_A):
        resp = client.get(f"/v1/probe/{SOCIETY_A}/things", headers=core.auth(person, extra=extra))
        assert resp.status_code in (403, 404), (person, resp.status_code)
    resp = client.get(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(OUTSIDER, extra=extra), "X-Society-Id": str(SOCIETY_A)},
    )
    assert resp.status_code in (403, 404)


def test_default_app_has_no_session_store_so_revocation_silently_does_nothing(db: DbHandle) -> None:
    """Fail-open default (F16): ``create_app`` used to leave ``session_store=None`` outside local/test, so
    revocation silently did nothing (IAM-08). It now refuses to start without a store in staging/production
    and only local/test may run without one."""
    from dwaar_api.core.authn import InMemorySessionStore
    from dwaar_api.core.config import ConfigError
    from dwaar_api.core.db import Database
    from dwaar_api.main import create_app
    from tests.integration.core._support import make_settings

    settings = make_settings(
        db,
        env="staging",
        oidc_issuer_url="https://issuer.example",
        oidc_jwks_url="https://issuer.example/jwks",
        cors_origins="https://admin.example",
    )
    database = Database.from_settings(settings)
    try:
        with pytest.raises(ConfigError, match="session store"):
            create_app(settings, database=database, modules_package=None)
        store = InMemorySessionStore()
        app = create_app(settings, database=database, modules_package=None, session_store=store)
        assert app.state.session_store is store
        local = create_app(make_settings(db), database=database, modules_package=None)
        assert local.state.session_store is None  # local/test only
    finally:
        database.dispose()


# ------------------------------------------------------------------------------------------------
# JWKS fetch behaviour
# ------------------------------------------------------------------------------------------------
class _CountingJwks(http.server.BaseHTTPRequestHandler):
    body = b"{}"
    hits = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def counting_jwks(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, type[_CountingJwks]]]:
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    handler = type("H", (_CountingJwks,), {"hits": 0})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/jwks", handler
    finally:
        server.shutdown()
        server.server_close()


def test_unauthenticated_random_kids_do_not_trigger_one_jwks_fetch_per_request(
    issuer: TestIssuer, counting_jwks: tuple[str, type[_CountingJwks]]
) -> None:
    """RemoteJwks (PyJWKClient) refreshes the whole JWKS whenever a kid is not cached. An attacker needs no
    credentials: any token with alg=EdDSA and a fresh random kid costs the API one outbound HTTP fetch to the
    identity provider (amplification / IdP-outage lever / latency on every login path)."""
    url, handler = counting_jwks
    handler.body = json.dumps(issuer.jwks).encode()
    verifier = JwtVerifier(
        issuer=ISSUER, audience=AUDIENCE, jwks=RemoteJwks(url, timeout_seconds=2)
    )
    assert not _rejected(verifier, issuer.mint(PERSON))  # warm the cache
    warm = handler.hits
    attacker = Ed25519PrivateKey.generate()
    for _ in range(30):
        junk = jwt.encode(_claims(), attacker, algorithm="EdDSA", headers={"kid": uuid.uuid4().hex})
        assert _rejected(verifier, junk)
    assert handler.hits - warm <= 2, (
        f"{handler.hits - warm} JWKS fetches for 30 unauthenticated junk tokens"
    )
