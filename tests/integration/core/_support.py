"""Shared helpers and fixtures for the API-core tests (imported by tests/integration/core and tests/security)."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import OKPAlgorithm

from dwaar_api.core.authn import (
    InMemorySessionStore,
    JwtVerifier,
    OidcIdentityProvider,
    StaticJwks,
)
from dwaar_api.core.authz import Grant, InMemoryGrantResolver
from dwaar_api.core.config import Settings
from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from tests._harness.pgfixtures import DbHandle

SOCIETY_A = uuid.UUID("0192f300-0000-7000-8000-00000000000a")
SOCIETY_B = uuid.UUID("0192f300-0000-7000-8000-00000000000b")
UNIT_1 = uuid.UUID("0192f300-0000-7000-8000-0000000000a1")
UNIT_2 = uuid.UUID("0192f300-0000-7000-8000-0000000000a2")
COMMITTEE_A = uuid.UUID("0192f300-0000-7000-8000-0000000000c1")
RESIDENT_A = uuid.UUID("0192f300-0000-7000-8000-0000000000e1")
RESIDENT_A2 = uuid.UUID("0192f300-0000-7000-8000-0000000000e2")
COMMITTEE_B = uuid.UUID("0192f300-0000-7000-8000-0000000000c2")
OUTSIDER = uuid.UUID("0192f300-0000-7000-8000-0000000000f1")

ISSUER = "https://issuer.test.invalid"
AUDIENCE = "dwaar-api"
PROBE_PACKAGE = "tests.integration.core.probe_modules"

PROBE_DDL = """
CREATE TABLE probe_things (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL,
    name text NOT NULL,
    phone text,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
SELECT dwaar_enable_society_rls('probe_things');
"""


def create_probe_table(db: DbHandle) -> None:
    with db.owner_conn() as conn:
        conn.execute(PROBE_DDL)  # type: ignore[call-overload]


class TestIssuer:
    """A throwaway Ed25519 OIDC issuer: a real JWKS and real signed JWTs, no simulator shortcuts."""

    __test__ = False

    def __init__(self, kid: str = "test-key-1") -> None:
        self.kid = kid
        self.private_key = Ed25519PrivateKey.generate()
        jwk = json.loads(OKPAlgorithm.to_jwk(self.private_key.public_key()))
        jwk.update({"kid": kid, "alg": "EdDSA", "use": "sig"})
        self.jwks: dict[str, Any] = {"keys": [jwk]}

    def mint(
        self,
        person_id: uuid.UUID | str,
        *,
        ttl: int = 600,
        issuer: str = ISSUER,
        audience: str | list[str] = AUDIENCE,
        nbf_offset: int | None = None,
        kid: str | None = None,
        extra: dict[str, Any] | None = None,
        private_key: Ed25519PrivateKey | None = None,
        session_id: str | None = None,
        omit: tuple[str, ...] = (),
    ) -> str:
        now = dt.datetime.now(dt.UTC)
        claims: dict[str, Any] = {
            "sub": str(person_id),
            "iss": issuer,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int(now.timestamp()) + ttl,
        }
        if nbf_offset is not None:
            claims["nbf"] = int(now.timestamp()) + nbf_offset
        if session_id:
            claims["sid"] = session_id
        claims.update(extra or {})
        for name in omit:
            claims.pop(name, None)
        return jwt.encode(
            claims,
            private_key or self.private_key,
            algorithm="EdDSA",
            headers={"kid": kid or self.kid},
        )

    def verifier(self, **kwargs: Any) -> JwtVerifier:
        return JwtVerifier(issuer=ISSUER, audience=AUDIENCE, jwks=StaticJwks(self.jwks), **kwargs)


def make_settings(db: DbHandle, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "env": "test",
        "database_url": db.app_dsn,
        "database_worker_url": db.worker_dsn,
        "cursor_signing_key": "test-cursor-key-for-pytest-only",
    }
    values.update(overrides)
    return Settings.model_validate(values)


@dataclass
class CoreHarness:
    db: DbHandle
    settings: Settings
    issuer: TestIssuer
    resolver: InMemoryGrantResolver
    sessions: InMemorySessionStore
    database: Database
    app: FastAPI

    def client(self, **kwargs: Any) -> TestClient:
        kwargs.setdefault("raise_server_exceptions", False)
        return TestClient(self.app, **kwargs)

    def auth(self, person_id: uuid.UUID, **mint: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.issuer.mint(person_id, **mint)}"}


def build_harness(db: DbHandle, *, with_probe_table: bool = True) -> CoreHarness:
    if with_probe_table:
        create_probe_table(db)
    settings = make_settings(db)
    issuer = TestIssuer()
    resolver = InMemoryGrantResolver()
    resolver.add(COMMITTEE_A, Grant("committee", SOCIETY_A))
    resolver.add(COMMITTEE_B, Grant("committee", SOCIETY_B))
    resolver.add(RESIDENT_A, Grant("resident", SOCIETY_A, unit_id=UNIT_1, person_id=RESIDENT_A))
    resolver.add(RESIDENT_A2, Grant("resident", SOCIETY_A, unit_id=UNIT_2, person_id=RESIDENT_A2))
    sessions = InMemorySessionStore()
    database = Database.from_settings(settings)
    provider = OidcIdentityProvider(issuer.verifier(), name="test-oidc", simulation=True)
    app = create_app(
        settings,
        database=database,
        identity_provider=provider,
        session_store=sessions,
        grant_resolver=resolver,
        modules_package=PROBE_PACKAGE,
    )
    return CoreHarness(db, settings, issuer, resolver, sessions, database, app)


@contextlib.contextmanager
def core_harness(db: DbHandle) -> Iterator[CoreHarness]:
    """A migrated clone database + the probe module + a fake grant resolver + a real JWT issuer."""
    harness = build_harness(db)
    try:
        yield harness
    finally:
        harness.database.dispose()


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness
