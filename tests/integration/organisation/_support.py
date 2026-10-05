"""Harness for the organisation tests: real Postgres, the real module, real signed JWTs.

Grants come from a ``GrantSeeder``. Two resolver kinds run every test in this directory (the ``resolver_kind`` fixture
is parametrised from ``RESOLVER_FACTORIES``):

* ``memory``: the core's ``InMemoryGrantResolver`` filled directly.
* ``pg``: the identity module's REAL ``PgGrantResolver`` over real ``memberships`` and ``role_grants`` rows (the access
  index triggers of migrations 0133/0134 run exactly as in production). Elevated roles need a fresh MFA step-up in the
  session, so the seeder also creates an ``iam.auth_sessions`` row with ``mfa_verified_at`` set for such a person and
  ``OrgHarness.auth`` puts that session id in the token (``sid``); nothing else about the token matters.

``platform_admin`` has no database representation (``role_grants.role`` does not allow it; platform roles are issued out
of band, ADR-0011), so in the ``pg`` kind it is overlaid from an in-memory list: a documented test-only shim.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import uuid
from collections.abc import Callable, Iterator, Sequence
from typing import Any, Protocol

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
from sqlalchemy import create_engine, text

from dwaar_api.core.authn import InMemorySessionStore, OidcIdentityProvider, Principal
from dwaar_api.core.authz import Grant, GrantResolver, InMemoryGrantResolver
from dwaar_api.core.config import Settings
from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_api.modules.identity.config import IdentityConfig
from dwaar_api.modules.identity.glue import PgGrantResolver
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
    #: session id to put in a person's token (``sid``), or None. Real resolver: the MFA-verified session of an elevated person.
    session_for: Callable[[uuid.UUID], str | None] = lambda _person: None


def _memory_factory(db: DbHandle, database: Database, settings: Settings) -> ResolverBundle:
    resolver = InMemoryGrantResolver()
    return ResolverBundle(resolver, MemorySeeder(resolver))


# ------------------------------------------------------------------------------------------------- real resolver
#: org-test role -> (membership kind, lives_in_unit); everything else is a role grant
_MEMBERSHIP_ROLES = {
    "owner_occ": ("owner", True),
    "owner_nr": ("owner", False),
    "tenant": ("tenant", True),
    "family": ("family", True),
}
_ELEVATED = frozenset(
    {"secretary", "treasurer", "committee", "estate_mgr", "guard_sup", "auditor", "org_admin"}
)
_TIME_BOUND = frozenset({"auditor", "vendor_tech", "plat_support"})


class PlatformOverlayResolver:
    """The real resolver plus the in-memory ``platform_admin`` overlay (that role is not a database row)."""

    def __init__(self, inner: GrantResolver, overlay: InMemoryGrantResolver) -> None:
        self._inner = inner
        self._overlay = overlay

    def resolve(
        self, principal: Principal, *, society_hint: uuid.UUID | None, fresh: bool
    ) -> Sequence[Grant]:
        return (
            *self._inner.resolve(principal, society_hint=society_hint, fresh=fresh),
            *self._overlay.resolve(principal, society_hint=society_hint, fresh=fresh),
        )


class PgSeeder:
    """Writes real persons, memberships and role grants (owner role with the society context, as the identity tests do)."""

    def __init__(self, db: DbHandle) -> None:
        self.db = db
        self.overlay = InMemoryGrantResolver()
        self._persons: set[uuid.UUID] = set()
        self._sessions: dict[uuid.UUID, str] = {}
        self._issuer: uuid.UUID | None = None

    def _person(self, person: uuid.UUID) -> None:
        if person in self._persons:
            return
        with self.db.admin_conn() as conn:
            conn.execute(
                "INSERT INTO iam.persons (id, display_name, phone_token) VALUES (%s, %s, %s)"
                " ON CONFLICT DO NOTHING",
                (person, f"Org test person {str(person)[-4:]}", f"orgtest-{person}"),
            )
            conn.execute(
                "INSERT INTO iam.person_vault (person_id, phone_enc) VALUES (%s, 'x')"
                " ON CONFLICT DO NOTHING",
                (person,),
            )
        self._persons.add(person)

    def _issuer_person(self) -> uuid.UUID:
        if self._issuer is None:
            self._issuer = uuid7()
            self._person(self._issuer)
        return self._issuer

    def _mfa_session(self, person: uuid.UUID) -> None:
        if person in self._sessions:
            return
        sid = uuid7()
        with self.db.admin_conn() as conn:
            conn.execute(
                "INSERT INTO iam.auth_sessions (id, person_id, device_id, expires_at, mfa_verified_at)"
                " VALUES (%s, %s, 'org-test', now() + interval '1 day', now())",
                (sid, person),
            )
        self._sessions[person] = str(sid)

    def _ensure_unit(self, society: uuid.UUID, unit: uuid.UUID) -> None:
        """A membership needs a real unit (composite FK). Tests that grant on a made-up unit id get a placeholder one."""
        with self.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
            if conn.execute("SELECT 1 FROM units WHERE id = %s", (unit,)).fetchone() is not None:
                return
            block = conn.execute(
                "INSERT INTO blocks (id, society_id, name, floors) VALUES (%s, %s, 'AUTO-SEED', 5)"
                " ON CONFLICT (society_id, name) DO UPDATE SET name = excluded.name RETURNING id",
                (uuid7(), society),
            ).fetchone()
            assert block is not None
            conn.execute(
                "INSERT INTO units (id, society_id, block_id, label, floor) VALUES (%s, %s, %s, %s, 1)",
                (unit, society, block[0], f"AUTO-{str(unit)[:8]}"),
            )

    def session_for(self, person: uuid.UUID) -> str | None:
        return self._sessions.get(person)

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
        if role == "platform_admin":
            self.overlay.add(person, Grant(role, society))
            return
        self._person(person)
        if role in _ELEVATED:
            self._mfa_session(person)
        if role in _MEMBERSHIP_ROLES:
            kind, lives = _MEMBERSHIP_ROLES[role]
            if unit is None or expires_at is not None or not_before is not None:
                raise ValueError("resident roles need a unit and take no validity window here")
            self._ensure_unit(society, unit)
            with self.db.owner_conn() as conn:
                conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
                conn.execute(
                    "INSERT INTO memberships (id, society_id, person_id, unit_id, kind, verification,"
                    " lives_in_unit, created_by) VALUES (%s, %s, %s, %s, %s, 'verified', %s, %s)",
                    (uuid7(), society, person, unit, kind, lives, person),
                )
            return
        issued = min(
            dt.datetime.now(dt.UTC) - dt.timedelta(hours=1),
            (expires_at or dt.datetime.max.replace(tzinfo=dt.UTC)) - dt.timedelta(days=1),
        )
        if role in _TIME_BOUND and expires_at is None:
            expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=300)
        scope = {"kind": "unit", "unit_id": str(unit)} if unit else {"kind": "society"}
        with self.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
            conn.execute(
                "INSERT INTO role_grants (id, society_id, person_id, role, scope, issued_by, reason,"
                " issued_at, not_before, expires_at) VALUES (%s, %s, %s, %s, %s, %s, 'seeded for tests', %s, %s, %s)",
                (uuid7(), society, person, role, Jsonb(scope), self._issuer_person(), issued, not_before, expires_at),
            )  # fmt: skip

    def revoke_all(self, person: uuid.UUID) -> None:
        self.overlay.clear(person)
        with self.db.admin_conn() as conn:
            societies = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT society_ref FROM iam.person_access_index WHERE person_id = %s",
                    (person,),
                ).fetchall()
            ]
        issuer = self._issuer_person()
        for society in societies:
            with self.db.owner_conn() as conn:
                conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
                conn.execute(
                    "UPDATE role_grants SET revoked_at = now(), revoked_by = %s, revoke_reason = 'test revoke_all'"
                    " WHERE person_id = %s AND revoked_at IS NULL",
                    (issuer, person),
                )
                conn.execute(
                    "UPDATE memberships SET verification = 'rejected' WHERE person_id = %s",
                    (person,),
                )


def _pg_factory(db: DbHandle, database: Database, settings: Settings) -> ResolverBundle:
    seeder = PgSeeder(db)
    real = PgGrantResolver(database, IdentityConfig.from_environment(settings))
    return ResolverBundle(PlatformOverlayResolver(real, seeder.overlay), seeder, seeder.session_for)


#: name -> factory(db, database, settings).
RESOLVER_FACTORIES: dict[str, Callable[[DbHandle, Database, Settings], ResolverBundle]] = {
    "memory": _memory_factory,
    "pg": _pg_factory,
}


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
    session_for: Callable[[uuid.UUID], str | None] = lambda _person: None
    _client: TestClient | None = None

    def client(self) -> TestClient:
        if self._client is None:
            self._client = TestClient(self.app, raise_server_exceptions=False)
        return self._client

    def auth(self, person: uuid.UUID) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.issuer.mint(person, session_id=self.session_for(person))}"
        }

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
    database = Database.from_settings(settings)
    bundle = RESOLVER_FACTORIES[kind](db, database, settings)
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
    harness = OrgHarness(
        db, app, issuer, bundle.seeder, database, cipher, legal, approved, tax, bundle.session_for
    )
    try:
        yield harness
    finally:
        database.dispose()


@pytest.fixture
def org(db: DbHandle, resolver_kind: str) -> Iterator[OrgHarness]:
    with org_harness(db, resolver_kind) as harness:
        yield harness
