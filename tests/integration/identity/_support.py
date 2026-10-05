"""Harness for the identity tests: real Postgres, the real module, real signed JWTs, real OTP flow.

* ``idh.login(phone)`` runs the genuine OTP request + verify against the API (the dev-only simulator endpoint hands
  the code back) and returns the tokens and the person id.
* ``idh.seed_*`` write memberships and grants through the OWNER role (the only role that can build fixtures for
  other people), with the society context FORCE RLS needs. The triggers of migration 0133/0134 keep the access
  index in step exactly as in production.
* Test numbers are the reserved fictional range +91 99999 00xxx.
"""

from __future__ import annotations

import contextlib
import dataclasses
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import psycopg
import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_api.modules.identity.glue import PgGrantResolver
from dwaar_common.ids import uuid7
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings

SHIM_PACKAGE = "tests.integration.identity.shim_modules"
UA = {"User-Agent": "dwaar-identity-tests"}


def phone(n: int) -> str:
    """Reserved fictional test numbers: +91 99999 00xxx."""
    return f"+9199999{n:05d}"


@dataclass
class Society:
    id: uuid.UUID
    block: uuid.UUID
    units: dict[str, uuid.UUID]


@dataclass
class Person:
    id: uuid.UUID
    phone: str
    access: str
    refresh: str
    session_id: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access}"}


@dataclass
class IdentityHarness:
    db: DbHandle
    app: FastAPI
    database: Database
    totp: dict[uuid.UUID, str] = field(default_factory=dict)
    _pack: uuid.UUID | None = None
    _n: int = 0

    # ---------------------------------------------------------------- tuning
    @property
    def rt(self) -> Any:
        return self.app.state.identity

    def tune(self, **changes: Any) -> None:
        """Swap config values on every holder (rate limits, TTLs ...)."""
        rt = self.rt
        rt.config = dataclasses.replace(rt.config, **changes)
        rt.auth.config = rt.config
        self.app.state.grant_resolver = PgGrantResolver(self.database, rt.config)

    def client(self) -> TestClient:
        return TestClient(self.app, raise_server_exceptions=False, headers=UA)

    # ---------------------------------------------------------------- seeding (owner role)
    def _owner(self, society: uuid.UUID | None) -> contextlib.AbstractContextManager[psycopg.Connection[Any]]:
        return self.db.owner_conn() if society is None else self.db.owner_conn()

    def society(self, name: str = "Alpha Heights", units: tuple[str, ...] = ("A-101", "A-102", "B-201")) -> Society:
        sid, entity, block = uuid7(), uuid7(), uuid7()
        with self.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(sid),))
            if self._pack is None:
                self._pack = conn.execute(
                    "INSERT INTO legal_packs (pack_key, jurisdiction, entity_type, version, pack_status, content_hash,"
                    " effective_from) VALUES ('idtest', 'IN-TEST', 'any', '1', 'unapproved', %s, DATE '2026-01-01')"
                    " ON CONFLICT (pack_key, version) DO UPDATE SET title = '' RETURNING id",
                    ("sha256:" + "0" * 64,),
                ).fetchone()[0]  # type: ignore[index]
            conn.execute(
                "INSERT INTO societies (id, name, legal_entity_id, legal_pack_id, city, state)"
                " VALUES (%s, %s, %s, %s, 'Pune', 'Maharashtra')",
                (sid, name, entity, self._pack),
            )
            conn.execute(
                "INSERT INTO legal_entities (id, society_id, name, entity_type, registration_no)"
                " VALUES (%s, %s, %s, 'chs', 'REG-1')",
                (entity, sid, name),
            )
            conn.execute(
                "INSERT INTO blocks (id, society_id, name, floors) VALUES (%s, %s, 'A', 10)", (block, sid)
            )
            ids: dict[str, uuid.UUID] = {}
            for label in units:
                uid = uuid7()
                conn.execute(
                    "INSERT INTO units (id, society_id, block_id, label, floor) VALUES (%s, %s, %s, %s, 1)",
                    (uid, sid, block, label),
                )
                ids[label] = uid
        return Society(sid, block, ids)

    def seed_membership(
        self,
        society: uuid.UUID,
        person: uuid.UUID,
        unit: uuid.UUID,
        kind: str,
        *,
        verification: str = "verified",
        lives: bool = True,
        effective_to: str | None = None,
        owner_decision: str | None = None,
    ) -> uuid.UUID:
        mid = uuid7()
        with self.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
            conn.execute(
                "INSERT INTO memberships (id, society_id, person_id, unit_id, kind, verification, lives_in_unit,"
                " effective_to, owner_decision, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (mid, society, person, unit, kind, verification, lives, effective_to, owner_decision, person),
            )
        return mid

    def seed_grant(
        self,
        society: uuid.UUID,
        person: uuid.UUID,
        role: str,
        *,
        issued_by: uuid.UUID | None = None,
        expires: str | None = None,
        unit: uuid.UUID | None = None,
        approved_by: uuid.UUID | None = None,
    ) -> uuid.UUID:
        gid = uuid7()
        issuer = issued_by or self.system_person()
        scope = {"kind": "unit", "unit_id": str(unit)} if unit else {"kind": "society"}
        with self.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
            conn.execute(
                "INSERT INTO role_grants (id, society_id, person_id, role, scope, issued_by, approved_by, reason,"
                " issued_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, 'seeded for tests',"
                " now() - interval '1 hour', " + (f"now() + interval '{expires}'" if expires else "NULL") + ")",  # noqa: S608
                (gid, society, person, role, Jsonb(scope), issuer, approved_by),
            )
        return gid

    def system_person(self) -> uuid.UUID:
        """A person who exists only to be the issuer of seeded grants."""
        pid = uuid7()
        with self.db.admin_conn() as conn:
            conn.execute(
                "INSERT INTO iam.persons (id, display_name, phone_token) VALUES (%s, 'System seeder', %s)"
                " ON CONFLICT DO NOTHING",
                (pid, f"seeder-{pid}"),
            )
            conn.execute("INSERT INTO iam.person_vault (person_id, phone_enc) VALUES (%s, 'x')", (pid,))
        return pid

    # ---------------------------------------------------------------- real login
    def login(self, number: int | str, *, device: str = "dev-1", client: TestClient | None = None) -> Person:
        c = client or self.client()
        num = phone(number) if isinstance(number, int) else number
        r = c.post("/v1/auth/otp/request", json={"phone": num})
        assert r.status_code == 202, r.text
        code = self.otp(num, c)
        r = c.post(
            "/v1/auth/otp/verify",
            json={"phone": num, "code": code, "device": {"device_id": device, "label": f"Test {device}"}},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        me = c.get("/v1/me", headers={"Authorization": f"Bearer {body['access_token']}"})
        assert me.status_code == 200, me.text
        return Person(
            uuid.UUID(me.json()["person"]["id"]), num, body["access_token"], body["refresh_token"], body["session_id"]
        )

    def otp(self, num: str, client: TestClient | None = None) -> str:
        c = client or self.client()
        r = c.get("/v1/dev/otp", params={"phone": num})
        assert r.status_code == 200, r.text
        assert r.json()["simulation"] is True
        return str(r.json()["otp"])

    def elevate_session(self, person: Person) -> None:
        """Mark the person's session as MFA-verified directly (the MFA flow itself has its own tests)."""
        with self.db.admin_conn() as conn:
            conn.execute("UPDATE iam.auth_sessions SET mfa_verified_at = now() WHERE id = %s", (person.session_id,))

    def enrol_totp(self, person: Person, client: TestClient | None = None) -> str:
        c = client or self.client()
        r = c.post("/v1/auth/mfa/totp/enrol", headers=person.headers)
        assert r.status_code == 201, r.text
        secret = r.json()["secret"]
        self.totp[person.id] = secret
        return str(secret)

    def totp_code(self, person: Person, offset: int = 0) -> str:
        return pyotp.TOTP(self.totp[person.id]).at(datetime.now().timestamp() + 30 * offset)

    # ---------------------------------------------------------------- peeks (admin; diagnostics only)
    def admin_rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self.db.admin_conn() as conn:
            return conn.execute(sql, params).fetchall()  # type: ignore[call-overload,no-any-return]

    def audit_ops(self, operation_like: str) -> list[tuple[Any, ...]]:
        return self.admin_rows(
            "SELECT operation, society_id, actor_id, diff_masked, reason FROM audit_log WHERE operation LIKE %s ORDER BY at",
            (operation_like,),
        )

    def idem(self) -> dict[str, str]:
        return {"Idempotency-Key": f"test-{uuid7()}"}


@contextlib.contextmanager
def identity_harness(db: DbHandle) -> Iterator[IdentityHarness]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    h = IdentityHarness(db, app, database)
    h.tune(ip_capacity=10_000, otp_request_capacity=50, otp_verify_capacity=50)
    try:
        yield h
    finally:
        database.dispose()


@pytest.fixture
def idh(db: DbHandle) -> Iterator[IdentityHarness]:
    with identity_harness(db) as harness:
        yield harness


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
