"""OPEN findings from W1 verification: JWT verifier, JWKS handling, role-claim trust (IAM-14, IAM-08, INV-01).

Not collected by ``make test``; run explicitly with
``uv run --no-sync pytest tests/security/verify_w1_authn.py -p no:cacheprovider``.

A FAILING test asserts the secure behaviour and marks a defect that is NOT fixed yet (not part of fix round 1).
When one is fixed, move it to ``tests/security/test_w1_authn.py``. Tests for fixed findings live in
``tests/security/test_w1_*.py``.
"""

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
from jwt.algorithms import OKPAlgorithm

from dwaar_api.core.authn import JwtVerifier, RemoteJwks, StaticJwks
from dwaar_common.errors import Unauthenticated
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    AUDIENCE,
    COMMITTEE_A,
    ISSUER,
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


def test_jwks_key_with_an_encryption_use_is_not_accepted_for_signatures() -> None:
    """A JWKS entry marked use=enc (or key_ops without verify) must not be usable to verify signatures."""
    key = Ed25519PrivateKey.generate()
    jwk = json.loads(OKPAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "enc-key", "use": "enc"})
    verifier = JwtVerifier(issuer=ISSUER, audience=AUDIENCE, jwks=StaticJwks({"keys": [jwk]}))
    token = jwt.encode(_claims(), key, algorithm="EdDSA", headers={"kid": "enc-key"})
    assert _rejected(verifier, token), "key marked use=enc verified a signature"


# ------------------------------------------------------------------------------------------------
# time claims
# ------------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------------
# audience / issuer / subject
# ------------------------------------------------------------------------------------------------


def test_session_revocation_is_not_bypassed_by_an_alternative_spelling_of_the_subject(
    core: CoreHarness,
) -> None:
    """``sub`` is parsed with uuid.UUID(), which accepts hex, braces and urn forms, but session revocation is
    keyed on the raw ``sub`` string. A token whose sub is a different spelling of the same person survives
    ``revoke_subject_before``."""
    now = dt.datetime.now(dt.UTC)
    core.sessions.revoke_subject_before(str(COMMITTEE_A), now + dt.timedelta(minutes=1))
    client = core.client()
    plain = client.get(f"/v1/probe/{SOCIETY_A}/things", headers=core.auth(COMMITTEE_A))
    spelled = client.get(
        f"/v1/probe/{SOCIETY_A}/things",
        headers=core.auth(COMMITTEE_A.hex),  # type: ignore[arg-type]
    )
    assert plain.status_code == 401
    assert spelled.status_code == 401, "revoked person still authenticated via sub spelling"


# ------------------------------------------------------------------------------------------------
# role claims are never trusted
# ------------------------------------------------------------------------------------------------


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


def test_malformed_jwks_documents_fail_closed_not_500(
    issuer: TestIssuer, counting_jwks: tuple[str, type[_CountingJwks]]
) -> None:
    from dwaar_common.errors import DwaarError

    url, handler = counting_jwks
    verifier = JwtVerifier(
        issuer=ISSUER, audience=AUDIENCE, jwks=RemoteJwks(url, timeout_seconds=2)
    )
    for body in (
        b"not json",
        b"[]",
        b'{"keys": "x"}',
        b'{"keys": [{"kty": "oct", "k": "AAAA", "kid": "test-key-1"}]}',
        b"\xff\xfe",
    ):
        handler.body = body
        with pytest.raises(DwaarError):
            verifier.verify(issuer.mint(PERSON))
