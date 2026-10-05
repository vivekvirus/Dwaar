"""Token verification (IAM-14): PyJWT + JWKS, exp/nbf/aud/iss enforced, algorithm allow-list, no 'none'.

Real signed tokens from a throwaway Ed25519 issuer; every rejection is the SAME bare 401 (no oracle).
"""

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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_api.core.authn import (
    InMemorySessionStore,
    JwtVerifier,
    OidcIdentityProvider,
    RemoteJwks,
    StaticJwks,
)
from dwaar_api.core.config import ConfigError
from dwaar_api.main import create_app
from dwaar_common.errors import DependencyUnavailable, Unauthenticated
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    AUDIENCE,
    COMMITTEE_A,
    ISSUER,
    PROBE_PACKAGE,
    SOCIETY_A,
    CoreHarness,
    TestIssuer,
    core_harness,
    make_settings,
)

pytestmark = pytest.mark.req("IAM-14", "IAM-08", "INV-01")

PERSON = uuid.UUID("0192f300-0000-7000-8000-0000000000c1")


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


@pytest.fixture(scope="module")
def issuer() -> TestIssuer:
    return TestIssuer()


@pytest.fixture(scope="module")
def verifier(issuer: TestIssuer) -> JwtVerifier:
    return issuer.verifier(leeway_seconds=5)


def b64(data: dict[str, Any] | bytes) -> str:
    raw = data if isinstance(data, bytes) else json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def claims(**kw: Any) -> dict[str, Any]:
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


def assert_rejected(verifier: JwtVerifier, token: str) -> None:
    with pytest.raises(Unauthenticated) as exc:
        verifier.verify(token)
    assert exc.value.status == 401
    assert exc.value.code == "unauthenticated"
    assert exc.value.details == {}  # nothing about WHY


# -------------------------------------------------------------------------------- the happy path
def test_valid_token_verifies(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    verified = verifier.verify(issuer.mint(PERSON))
    assert verified.claims["sub"] == str(PERSON)
    assert verified.algorithm == "EdDSA"
    assert verified.key_id == issuer.kid


def test_audience_may_be_a_list_containing_ours(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    assert verifier.verify(issuer.mint(PERSON, audience=["other-api", AUDIENCE])).claims[
        "sub"
    ] == str(PERSON)


# -------------------------------------------------------------------------------- algorithm attacks
def test_alg_none_is_rejected(verifier: JwtVerifier) -> None:
    unsigned = f"{b64({'alg': 'none', 'typ': 'JWT', 'kid': 'test-key-1'})}.{b64(claims())}."
    assert_rejected(verifier, unsigned)
    assert_rejected(verifier, unsigned + "AAAA")
    for spelling in ("None", "NONE", "nOnE"):
        assert_rejected(verifier, f"{b64({'alg': spelling, 'kid': 'test-key-1'})}.{b64(claims())}.")


def test_alg_none_cannot_even_be_configured(issuer: TestIssuer) -> None:
    for algorithms in (("none",), ("HS256",), ("EdDSA", "HS512"), ()):
        with pytest.raises(ConfigError):
            JwtVerifier(
                issuer=ISSUER,
                audience=AUDIENCE,
                jwks=StaticJwks(issuer.jwks),
                algorithms=algorithms,
            )


def test_hmac_key_confusion_is_rejected(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    """Classic attack: sign with HS256 using the PUBLIC key bytes as the shared secret."""
    public = issuer.private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    forged = jwt.encode(claims(), public, algorithm="HS256", headers={"kid": issuer.kid})
    assert_rejected(verifier, forged)


def test_wrong_algorithm_for_the_key_is_rejected(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        claims(), rsa_key, algorithm="RS256", headers={"kid": issuer.kid}
    )  # RS256 is allowed...
    assert_rejected(verifier, forged)  # ...but the kid points at an Ed25519 key


def test_algorithm_outside_the_allow_list_is_rejected(issuer: TestIssuer) -> None:
    only_es256 = issuer.verifier(algorithms=("ES256",))
    assert_rejected(
        only_es256, issuer.mint(PERSON)
    )  # a perfectly valid EdDSA token, but EdDSA is not allowed here


# -------------------------------------------------------------------------------- claims
def test_expired_token_is_rejected_beyond_leeway(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    assert_rejected(verifier, issuer.mint(PERSON, ttl=-120))
    assert verifier.verify(issuer.mint(PERSON, ttl=-2)).claims["sub"]  # within the 5 s test leeway
    strict = issuer.verifier(leeway_seconds=0)
    assert_rejected(strict, issuer.mint(PERSON, ttl=-2))


def test_not_yet_valid_token_is_rejected(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    assert_rejected(verifier, issuer.mint(PERSON, nbf_offset=300))
    assert verifier.verify(issuer.mint(PERSON, nbf_offset=-10)).claims["sub"]


def test_wrong_audience_and_issuer_are_rejected(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    assert_rejected(verifier, issuer.mint(PERSON, audience="some-other-api"))
    assert_rejected(verifier, issuer.mint(PERSON, audience=["a", "b"]))
    assert_rejected(verifier, issuer.mint(PERSON, issuer="https://evil.example"))
    assert_rejected(verifier, issuer.mint(PERSON, issuer=ISSUER + "/"))  # no prefix/suffix matching


@pytest.mark.parametrize("missing", ["exp", "sub", "iss", "aud"])
def test_required_claims_must_be_present(
    issuer: TestIssuer, verifier: JwtVerifier, missing: str
) -> None:
    assert_rejected(verifier, issuer.mint(PERSON, omit=(missing,)))


def test_empty_subject_is_rejected(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    assert_rejected(verifier, issuer.mint("", ttl=600))


# -------------------------------------------------------------------------------- signature / keys
def test_tampered_payload_and_signature_are_rejected(
    issuer: TestIssuer, verifier: JwtVerifier
) -> None:
    token = issuer.mint(PERSON)
    header, payload, signature = token.split(".")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["sub"] = str(uuid.UUID(int=1))  # become somebody else
    assert_rejected(verifier, f"{header}.{b64(body)}.{signature}")
    flipped = signature[:-2] + ("AA" if signature[-2:] != "AA" else "BB")
    assert_rejected(verifier, f"{header}.{payload}.{flipped}")
    assert_rejected(verifier, f"{header}.{payload}.")
    assert_rejected(verifier, f"{header}.{payload}")


def test_token_signed_by_an_attacker_key_is_rejected_even_with_our_kid(
    issuer: TestIssuer, verifier: JwtVerifier
) -> None:
    attacker = Ed25519PrivateKey.generate()
    assert_rejected(verifier, issuer.mint(PERSON, private_key=attacker))
    assert_rejected(verifier, issuer.mint(PERSON, private_key=attacker, kid="attacker-key"))


def test_unknown_or_missing_kid_is_rejected(issuer: TestIssuer, verifier: JwtVerifier) -> None:
    assert_rejected(verifier, issuer.mint(PERSON, kid="no-such-key"))
    no_kid = jwt.encode(claims(), issuer.private_key, algorithm="EdDSA")
    assert_rejected(verifier, no_kid)


def test_embedded_jwk_and_jku_headers_are_ignored(
    issuer: TestIssuer, verifier: JwtVerifier
) -> None:
    attacker = Ed25519PrivateKey.generate()
    from jwt.algorithms import OKPAlgorithm

    attacker_jwk = json.loads(OKPAlgorithm.to_jwk(attacker.public_key()))
    attacker_jwk["kid"] = "attacker"
    forged = jwt.encode(
        claims(),
        attacker,
        algorithm="EdDSA",
        headers={"jwk": attacker_jwk, "kid": "attacker", "jku": "https://evil.example/jwks"},
    )
    assert_rejected(verifier, forged)


@pytest.mark.parametrize(
    "token",
    ["", "abc", "a.b", "a.b.c.d", "....", " . . ", "eyJ.eyJ.sig", "x" * 9000, "a.b.c" + "\x00"],
)
def test_malformed_tokens_are_rejected(verifier: JwtVerifier, token: str) -> None:
    assert_rejected(verifier, token)


# -------------------------------------------------------------------------------- over HTTP
def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_http_every_rejection_is_the_same_401_body(core: CoreHarness) -> None:
    url = f"/v1/probe/{SOCIETY_A}/whoami"
    attacker = Ed25519PrivateKey.generate()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cases = {
        "no header": {},
        "basic scheme": {"Authorization": "Basic dXNlcjpwYXNz"},
        "empty bearer": {"Authorization": "Bearer "},
        "garbage": bearer("garbage"),
        "expired": bearer(core.issuer.mint(COMMITTEE_A, ttl=-3600)),
        "wrong aud": bearer(core.issuer.mint(COMMITTEE_A, audience="x")),
        "wrong iss": bearer(core.issuer.mint(COMMITTEE_A, issuer="https://evil.example")),
        "attacker key": bearer(core.issuer.mint(COMMITTEE_A, private_key=attacker)),
        "alg none": bearer(
            f"{b64({'alg': 'none', 'kid': core.issuer.kid})}.{b64(claims(sub=str(COMMITTEE_A)))}."
        ),
        "wrong alg": bearer(
            jwt.encode(
                claims(sub=str(COMMITTEE_A)),
                rsa_key,
                algorithm="RS256",
                headers={"kid": core.issuer.kid},
            )
        ),
    }
    bodies = []
    with core.client() as client:
        for label, headers in cases.items():
            res = client.get(url, headers=headers)
            assert res.status_code == 401, label
            assert res.headers["www-authenticate"] == "Bearer", label
            body = res.json()
            assert body["code"] == "unauthenticated", label
            assert body["request_id"] == res.headers["x-request-id"], label
            bodies.append({k: v for k, v in body.items() if k != "request_id"})
        ok = client.get(url, headers=core.auth(COMMITTEE_A))
    assert ok.status_code == 200
    assert all(b == bodies[0] for b in bodies)  # no way to tell WHY from outside
    assert bodies[0]["details"] == {}


def test_revoked_session_and_revoked_subject_are_rejected(core: CoreHarness) -> None:
    url = f"/v1/probe/{SOCIETY_A}/whoami"
    sessions: InMemorySessionStore = core.sessions
    with core.client() as client:
        token = core.issuer.mint(COMMITTEE_A, session_id="sess-1")
        assert client.get(url, headers=bearer(token)).status_code == 200
        sessions.revoke_session("sess-1")
        assert client.get(url, headers=bearer(token)).status_code == 401
        other = core.issuer.mint(COMMITTEE_A, session_id="sess-2")
        assert client.get(url, headers=bearer(other)).status_code == 200
        sessions.revoke_subject_before(
            str(COMMITTEE_A), dt.datetime.now(dt.UTC) + dt.timedelta(seconds=5)
        )
        assert (
            client.get(url, headers=bearer(other)).status_code == 401
        )  # everything issued before the cut-off


def test_app_without_an_identity_provider_refuses_everyone(db: DbHandle) -> None:
    from dwaar_api.core.db import Database

    database = Database.from_settings(make_settings(db))
    try:
        app = create_app(make_settings(db), database=database, modules_package=PROBE_PACKAGE)
        from fastapi.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as client:
            res = client.get(
                f"/v1/probe/{SOCIETY_A}/whoami", headers=bearer(TestIssuer().mint(COMMITTEE_A))
            )
        assert res.status_code == 401  # fails closed, not open
    finally:
        database.dispose()


def test_simulator_identity_provider_is_refused_outside_local_and_test(db: DbHandle) -> None:
    settings = make_settings(
        db,
        env="staging",
        oidc_issuer_url="https://idp.example.invalid",
        oidc_jwks_url="https://idp.example.invalid/jwks",
        cors_origins="https://admin.example.invalid",
    )
    provider = OidcIdentityProvider(TestIssuer().verifier(), simulation=True)
    from dwaar_api.core.db import Database

    database = Database.from_settings(settings)
    try:
        with pytest.raises(ConfigError, match="simulator"):
            create_app(
                settings,
                database=database,
                identity_provider=provider,
                modules_package=PROBE_PACKAGE,
            )
    finally:
        database.dispose()


def test_subject_must_map_to_a_person(issuer: TestIssuer) -> None:
    provider = OidcIdentityProvider(issuer.verifier())
    with pytest.raises(Unauthenticated):
        provider.authenticate(issuer.mint("auth0|not-a-uuid"))
    mapped = uuid.UUID(int=99)
    provider = OidcIdentityProvider(
        issuer.verifier(), subject_mapper=lambda sub, _c: mapped if sub == "auth0|abc" else None
    )
    assert provider.authenticate(issuer.mint("auth0|abc")).person_id == mapped
    with pytest.raises(Unauthenticated):
        provider.authenticate(issuer.mint("auth0|other"))


def test_principal_never_carries_roles_from_the_token(issuer: TestIssuer) -> None:
    provider = OidcIdentityProvider(issuer.verifier(), simulation=True)
    principal = provider.authenticate(
        issuer.mint(
            PERSON,
            extra={
                "role": "platform_admin",
                "roles": ["committee"],
                "society_id": str(SOCIETY_A),
                "scope": "admin",
            },
        )
    )
    assert principal.simulation is True
    assert not hasattr(principal, "role")
    assert not hasattr(principal, "roles")
    assert not hasattr(principal, "society_id")


# -------------------------------------------------------------------------------- remote JWKS
class _JwksHandler(http.server.BaseHTTPRequestHandler):
    body: bytes = b"{}"
    status: int = 200

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def jwks_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, type[_JwksHandler]]]:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    handler = type("Handler", (_JwksHandler,), {})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/jwks", handler
    finally:
        server.shutdown()
        server.server_close()


def test_remote_jwks_verification_and_outage_is_503_not_a_bypass(
    issuer: TestIssuer, jwks_server: tuple[str, type[_JwksHandler]]
) -> None:
    url, handler = jwks_server
    handler.body = json.dumps(issuer.jwks).encode()
    verifier = JwtVerifier(
        issuer=ISSUER, audience=AUDIENCE, jwks=RemoteJwks(url, timeout_seconds=2)
    )
    assert verifier.verify(issuer.mint(PERSON)).claims["sub"] == str(PERSON)
    assert_rejected(verifier, issuer.mint(PERSON, private_key=Ed25519PrivateKey.generate()))
    assert_rejected(verifier, issuer.mint(PERSON, kid="rotated-away"))
    dead = JwtVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=RemoteJwks("http://127.0.0.1:1/jwks", timeout_seconds=1),
    )
    with pytest.raises(
        DependencyUnavailable
    ):  # cannot verify => the caller is told to retry, never let in
        dead.verify(issuer.mint(PERSON))
