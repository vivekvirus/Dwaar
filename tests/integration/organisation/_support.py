"""Harness for the organisation tests: real Postgres, the real module, real signed JWTs.

Grants come from a ``GrantSeeder``. The default seeder fills the core's ``InMemoryGrantResolver``; when the identity
module ships a database-backed resolver, add a factory to ``RESOLVER_FACTORIES`` below and every test in this
directory runs against real memberships/role grants too (the ``resolver_kind`` fixture is parametrised from it).
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import uuid
from collections.abc import Callable, Iterator
from typing import Any, Protocol

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from dwaar_api.core.authn import InMemorySessionStore, OidcIdentityProvider
from dwaar_api.core.authz import Grant, GrantResolver, InMemoryGrantResolver
from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_api.modules.organisation.packs import load_packs
from dwaar_common.crypto import EnvelopeCipher, KeyRing, generate_key
from dwaar_common.ids import uuid7
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import TestIssuer, make_settings

SHIM_PACKAGE = "tests.integration.organisation.shim_modules"
PLATFORM_HOME = uuid.UUID(
    "0192f300-0000-7000-8000-0000000000ee"
)  # a "home" scope for platform operators only

PLATFORM = uuid.UUID("0192f300-0000-7000-8000-0000000000a0")
SECRETARY = uuid.UUID("0192f300-0000-7000-8000-0000000000a1")
TREASURER = uuid.UUID("0192f300-0000-7000-8000-0000000000a2")
COMMITTEE = uuid.UUID("0192f300-0000-7000-8000-0000000000a3")
ESTATE_MGR = uuid.UUID("0192f300-0000-7000-8000-0000000000a4")
GUARD = uuid.UUID("0192f300-0000-7000-8000-0000000000a5")
AUDITOR = uuid.UUID("0192f300-0000-7000-8000-0000000000a6")
OWNER_OCC = uuid.UUID("0192f300-0000-7000-8000-0000000000a7")
OWNER_NR = uuid.UUID("0192f300-0000-7000-8000-0000000000a8")
TENANT = uuid.UUID("0192f300-0000-7000-8000-0000000000a9")
FAMILY = uuid.UUID("0192f300-0000-7000-8000-0000000000aa")
OUTSIDER = uuid.UUID("0192f300-0000-7000-8000-0000000000ab")
SECRETARY_B = uuid.UUID("0192f300-0000-7000-8000-0000000000b1")
ORG_ADMIN = uuid.UUID("0192f300-0000-7000-8000-0000000000b2")

#: persons -> PRD role code used for the staff-like roles; resident roles are unit-scoped.
STAFF_ROLES = {
    SECRETARY: "secretary",
    TREASURER: "treasurer",
    COMMITTEE: "committee",
    ESTATE_MGR: "estate_mgr",
    GUARD: "guard",
    AUDITOR: "auditor",
}
RESIDENT_ROLES = {
    OWNER_OCC: "owner_occ",
    OWNER_NR: "owner_nr",
    TENANT: "tenant",
    FAMILY: "family",
}


class GrantSeeder(Protocol):
    """Creates a CURRENT grant for a person. Adapters for a database-backed resolver implement this protocol."""

    def grant(
        self,
        person: uuid.UUID,
        role: str,
        society: uuid.UUID,
        *,
        unit: uuid.UUID | None = None,
        own_person: bool = False,
        expires_at: dt.datetime | None = None,
        not_before: dt.datetime | None = None,
    ) -> None: ...

    def revoke_all(self, person: uuid.UUID) -> None: ...


class MemorySeeder:
    def __init__(self, resolver: InMemoryGrantResolver) -> None:
        self.resolver = resolver

    def grant(
        self,
        person: uuid.UUID,
        role: str,
        society: uuid.UUID,
        *,
        unit: uuid.UUID | None = None,
        own_person: bool = False,
        expires_at: dt.datetime | None = None,
        not_before: dt.datetime | None = None,
    ) -> None:
        self.resolver.add(
            person,
            Grant(
                role,
                society,
                unit_id=unit,
                person_id=person if own_person else None,
                not_before=not_before,
                expires_at=expires_at,
            ),
        )

    def revoke_all(self, person: uuid.UUID) -> None:
        self.resolver.clear(person)


@dataclasses.dataclass(frozen=True)
class ResolverBundle:
    resolver: GrantResolver
    seeder: GrantSeeder


def _memory_factory(db: DbHandle) -> ResolverBundle:
    resolver = InMemoryGrantResolver()
    return ResolverBundle(resolver, MemorySeeder(resolver))


#: name -> factory(db). Add the identity module's real grant resolver here when it exists.
RESOLVER_FACTORIES: dict[str, Callable[[DbHandle], ResolverBundle]] = {"memory": _memory_factory}


@pytest.fixture(params=sorted(RESOLVER_FACTORIES))
def resolver_kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@dataclasses.dataclass
class OrgHarness:
    db: DbHandle
    app: FastAPI
    issuer: TestIssuer
    seeder: GrantSeeder
    database: Database
    cipher: EnvelopeCipher
    legal_pack_id: uuid.UUID  # maharashtra-chs, unapproved as shipped
    approved_pack_id: uuid.UUID  # same content, approved WITH evidence (inserted by the owner role)
    tax_pack_id: uuid.UUID
    _client: TestClient | None = None

    def client(self) -> TestClient:
        if self._client is None:
            self._client = TestClient(self.app, raise_server_exceptions=False)
        return self._client

    def auth(self, person: uuid.UUID) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.issuer.mint(person)}"}

    def call(
        self,
        method: str,
        path: str,
        person: uuid.UUID | None,
        *,
        json: Any = None,
        content: bytes | None = None,
        key: str | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        merged = dict(self.auth(person)) if person is not None else {}
        if key is not None:
            merged["Idempotency-Key"] = key
        merged.update(headers or {})
        return self.client().request(
            method, path, headers=merged, json=json, content=content, params=params
        )

    # ------------------------------------------------------------------ setup helpers
    def make_platform_admin(self) -> None:
        self.seeder.grant(PLATFORM, "platform_admin", PLATFORM_HOME)

    def society_payload(self, name: str = "Alpha Heights CHS", **over: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "name": name,
            "legal_entity": {
                "name": f"{name} Co-op Housing Society Ltd",
                "entity_type": "chs",
                "registration_no": "TEST/CHS/0001",
                "pan": "ABCDE1234F",
                "tan": "PUNE12345A",
                "gstin": "27ABCDE1234F1Z5",
            },
            "legal_pack_id": str(self.legal_pack_id),
            "tax_pack_id": str(self.tax_pack_id),
            "city": "Pune",
            "state": "Maharashtra",
        }
        body.update(over)
        return body

    def create_society(self, name: str = "Alpha Heights CHS", **over: Any) -> dict[str, Any]:
        self.make_platform_admin()
        resp = self.call("POST", "/v1/societies", PLATFORM, json=self.society_payload(name, **over))
        assert resp.status_code == 201, resp.text
        body: dict[str, Any] = resp.json()
        return body

    def seed_staff(self, society: uuid.UUID) -> None:
        for person, role in STAFF_ROLES.items():
            self.seeder.grant(person, role, society)

    def seed_residents(self, society: uuid.UUID, unit: uuid.UUID) -> None:
        for person, role in RESIDENT_ROLES.items():
            self.seeder.grant(person, role, society, unit=unit)

    def create_block(
        self, society: uuid.UUID, name: str = "A", floors: int = 10, **over: Any
    ) -> dict[str, Any]:
        resp = self.call(
            "POST",
            f"/v1/societies/{society}/blocks",
            SECRETARY,
            json={"name": name, "floors": floors, "has_lift": True, **over},
            key=f"blk-{uuid7()}",
        )
        assert resp.status_code == 201, resp.text
        body: dict[str, Any] = resp.json()
        return body

    def create_unit(
        self, society: uuid.UUID, block: str, label: str = "101", floor: int = 1, **over: Any
    ) -> dict[str, Any]:
        resp = self.call(
            "POST",
            f"/v1/societies/{society}/units",
            SECRETARY,
            json={
                "block_id": block,
                "label": label,
                "floor": floor,
                "carpet_area_sqft": "650.50",
                "builtup_area_sqft": "780.25",
                "undivided_interest_pct": "0.125000",
                "construction_cost_paise": 450000000,
                **over,
            },
            key=f"unit-{uuid7()}",
        )
        assert resp.status_code == 201, resp.text
        body: dict[str, Any] = resp.json()
        return body

    # ------------------------------------------------------------------ database peeks (owner role, per-society ctx)
    def rows(
        self, society: uuid.UUID, sql: str, params: tuple[Any, ...] = ()
    ) -> list[tuple[Any, ...]]:
        """Read as ``dwaar_app`` with the society context (RLS applies, exactly like production)."""
        with self.db.app_conn(society) as conn:
            return conn.execute(sql, params).fetchall()  # type: ignore[call-overload]


def _seed_packs(db: DbHandle) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    # load_packs speaks SQLAlchemy; drive it with a SQLAlchemy connection as the owner role
    engine = create_engine(db.owner_dsn.replace("postgresql://", "postgresql+psycopg://", 1))
    try:
        with engine.begin() as conn:
            load_packs(conn)
            legal = conn.execute(
                text("SELECT id FROM legal_packs WHERE pack_key = 'maharashtra-chs'")
            ).scalar_one()
            tax = conn.execute(
                text("SELECT id FROM tax_packs WHERE pack_key = 'gst-rwa'")
            ).scalar_one()
            approved = conn.execute(
                text(
                    "INSERT INTO legal_packs (pack_key, jurisdiction, entity_type, version, title, pack_status,"
                    " enabled, rules, legal_sources, content_hash, approved_by, approved_at, effective_from)"
                    " SELECT 'test-approved-chs', jurisdiction, entity_type, '2026.1.0-test', 'Approved test pack',"
                    " 'approved', true, rules, legal_sources, content_hash, 'Test Counsel (fixture)', now(),"
                    " DATE '2026-01-01' FROM legal_packs WHERE pack_key = 'maharashtra-chs' RETURNING id"
                )
            ).scalar_one()
    finally:
        engine.dispose()
    return uuid.UUID(str(legal)), uuid.UUID(str(approved)), uuid.UUID(str(tax))


@contextlib.contextmanager
def org_harness(db: DbHandle, kind: str = "memory") -> Iterator[OrgHarness]:
    legal, approved, tax = _seed_packs(db)
    settings = make_settings(db)
    issuer = TestIssuer()
    bundle = RESOLVER_FACTORIES[kind](db)
    database = Database.from_settings(settings)
    provider = OidcIdentityProvider(issuer.verifier(), name="test-oidc", simulation=True)
    app = create_app(
        settings,
        database=database,
        identity_provider=provider,
        session_store=InMemorySessionStore(),
        grant_resolver=bundle.resolver,
        modules_package=SHIM_PACKAGE,
    )
    cipher = EnvelopeCipher(KeyRing({"t1": generate_key()}, "t1"))
    app.state.pii_cipher = cipher
    harness = OrgHarness(db, app, issuer, bundle.seeder, database, cipher, legal, approved, tax)
    try:
        yield harness
    finally:
        database.dispose()


@pytest.fixture
def org(db: DbHandle, resolver_kind: str) -> Iterator[OrgHarness]:
    with org_harness(db, resolver_kind) as harness:
        yield harness
