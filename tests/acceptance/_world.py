"""The acceptance world: the REAL seed dataset in a private database, the REAL API, REAL tokens from the local simulator.

Everything the AT scenarios do goes through the same doors a client uses:

* the database is migrated by ``dwaar_api.core.migrate`` and filled by ``python -m dwaar_api.seed`` (``dwaar_api.seed.run``),
  i.e. through the real service functions, as ``dwaar_app`` with RLS context;
* the app is ``create_app`` with every discovered module (identity + organisation), the database-backed grant resolver
  and session store; nothing is stubbed;
* a person signs in with the genuine OTP flow (the labelled simulator hands the code back, ``simulation=true``), and
  elevated roles complete the TOTP step-up with the synthetic code of ``dwaar_api.seed.people``.

The few direct database peeks (``admin``) are test ORACLES (they read ids the API would hide); they are never what the
code under test uses.
"""

from __future__ import annotations

import dataclasses
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dwaar_api import seed
from dwaar_api.core.config import Settings
from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_api.seed.dataset import phone_for
from dwaar_api.seed.ids import scoped_uuid
from dwaar_api.seed.people import by_key, current_totp
from dwaar_api.seed.runtime import SeedContext, SocietyRef
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings

UA = {"User-Agent": "dwaar-acceptance"}
DATASET = (
    "dwaar-seed-v1: two synthetic societies (Maharashtra CHS 3 blocks/240 units, Karnataka association "
    "2 blocks/180 units), invented people on fictional numbers +91 99999 0nnnn, loaded by python -m dwaar_api.seed"
)


def seed_environment(db: DbHandle) -> dict[str, str]:
    """The environment the seed CLI would see for this database (DWAAR_ENV=local; real keys/config of the process kept)."""
    env = dict(os.environ)
    env.update(
        {
            "DWAAR_ENV": "local",
            "DWAAR_DATABASE_URL": db.app_dsn,
            "DWAAR_DATABASE_WORKER_URL": db.worker_dsn,
            "DWAAR_DATABASE_OWNER_URL": db.owner_dsn,
        }
    )
    return env


@dataclass
class Session:
    key: str
    person_id: uuid.UUID
    phone: str
    headers: dict[str, str]
    session_id: str


@dataclass
class SocietyObjects:
    """Every id of one society (the oracle's view): what 'object IDs of A' means in AT-01."""

    ref: SocietyRef
    memberships: list[uuid.UUID]
    cases: list[uuid.UUID]
    holds: list[uuid.UUID]
    grants: list[uuid.UUID]

    @property
    def society(self) -> uuid.UUID:
        return self.ref.id

    def all_ids(self) -> set[str]:
        ids: set[uuid.UUID] = {self.ref.id, *self.ref.blocks.values(), *self.ref.units.values()}
        ids.update(self.memberships, self.cases, self.holds, self.grants)
        return {str(i) for i in ids}


@dataclass
class World:
    db: DbHandle
    settings: Settings
    database: Database
    app: FastAPI
    client: TestClient
    seed_counts: dict[str, int]
    _sessions: dict[str, Session] = field(default_factory=dict)
    _objects: dict[str, SocietyObjects] = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------ people
    def login(self, key: str, *, step_up: bool | None = None) -> Session:
        """Genuine OTP sign-in for a seeded person; elevated holders also complete the TOTP step-up."""
        if key in self._sessions:
            return self._sessions[key]
        person = by_key()[key]
        c = self.client
        r = c.post("/v1/auth/otp/request", json={"phone": person.phone})
        assert r.status_code == 202, r.text
        r = c.get("/v1/dev/otp", params={"phone": person.phone})
        assert r.status_code == 200 and r.json()["simulation"] is True, r.text
        code = r.json()["otp"]
        r = c.post(
            "/v1/auth/otp/verify",
            json={
                "phone": person.phone,
                "code": code,
                "device": {"device_id": "acc", "label": "acceptance"},
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        headers = {"Authorization": f"Bearer {body['access_token']}"}
        me = c.get("/v1/me", headers=headers)
        assert me.status_code == 200, me.text
        assert me.json()["simulation"] is True
        session = Session(
            key, uuid.UUID(me.json()["person"]["id"]), person.phone, headers, body["session_id"]
        )
        wanted = me.json()["mfa"]["required_for_roles"] if step_up is None else step_up
        if wanted:
            v = c.post(
                "/v1/auth/mfa/verify", json={"code": current_totp(person.phone)}, headers=headers
            )
            assert v.status_code == 200, v.text
        self._sessions[key] = session
        return session

    def call(
        self,
        who: Session | None,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> Any:
        merged: dict[str, str] = dict(who.headers) if who else {}
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            merged["Idempotency-Key"] = f"acc-{uuid.uuid4()}"
        merged.update(headers or {})
        return self.client.request(
            method, path, headers=merged, json=json, params=params, content=content
        )

    # ------------------------------------------------------------------------------------------ oracle
    def society_ref(self, key: str) -> SocietyRef:
        ctx = SeedContext.create(seed_environment(self.db))
        try:
            return ctx.load_society(key)
        finally:
            ctx.close()

    def objects(self, key: str) -> SocietyObjects:
        if key not in self._objects:
            ref = self.society_ref(key)
            with self.db.owner_conn() as conn:
                conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ref.id),))

                def ids(sql: str) -> list[uuid.UUID]:
                    return [r[0] for r in conn.execute(sql).fetchall()]  # type: ignore[call-overload]

                self._objects[key] = SocietyObjects(
                    ref,
                    ids("SELECT id FROM memberships ORDER BY created_at, id"),
                    ids("SELECT id FROM verification_cases ORDER BY created_at, id"),
                    ids("SELECT id FROM membership_holds ORDER BY placed_at, id"),
                    ids("SELECT id FROM role_grants ORDER BY issued_at, id"),
                )
        return self._objects[key]

    def membership_of(
        self, society: uuid.UUID, person_key: str, block: str, label: str, kind: str
    ) -> uuid.UUID:
        ref = self.society_ref("mh" if society == self.society_ref("mh").id else "ka")
        person = scoped_uuid(f"person:{person_key}")
        with self.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
            row = conn.execute(
                "SELECT id FROM memberships WHERE person_id = %s AND unit_id = %s AND kind = %s",
                (person, ref.unit(block, label), kind),
            ).fetchone()
        assert row is not None
        return uuid.UUID(str(row[0]))

    def admin_rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self.db.admin_conn() as conn:
            return conn.execute(sql, params).fetchall()  # type: ignore[call-overload,no-any-return]

    def tune_limits(self) -> None:
        rt = self.app.state.identity
        rt.config = dataclasses.replace(
            rt.config, ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500
        )
        rt.auth.config = rt.config


def build_world(db: DbHandle, *, run_seed: bool = True) -> World:
    counts: dict[str, int] = {}
    if run_seed:
        result = seed.run(seed_environment(db), say=lambda _line: None)
        counts = result.counts
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    world = World(db, settings, database, app, client, counts)
    world.tune_limits()
    return world


# ------------------------------------------------------------------------------------------ response comparison
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def shape(response: Any, ids: set[str] | None = None) -> tuple[int, Any]:
    """(status, body) with ids and request ids blanked, so two answers can be compared for equality.

    If the answer to a REAL foreign id differs from the answer to a RANDOM id in anything but the id itself, the API is
    an existence oracle.
    """
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k != "request_id"}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            return _UUID.sub("<id>", value)
        return value

    return response.status_code, clean(body)


def leaks(response: Any, ids: set[str]) -> list[str]:
    """Which of the given ids appear anywhere in the response text (a body that echoes the CALLER's own path id is not
    a leak: callers pass only ids the caller did not send)."""
    text = response.text.lower()
    return sorted(i for i in ids if i in text)


def phone_pattern_ok(e164: str) -> bool:
    return bool(re.fullmatch(r"\+9199999\d{5}", e164))


__all__ = [
    "DATASET",
    "Session",
    "SocietyObjects",
    "World",
    "build_world",
    "leaks",
    "phone_for",
    "phone_pattern_ok",
    "seed_environment",
    "shape",
]
