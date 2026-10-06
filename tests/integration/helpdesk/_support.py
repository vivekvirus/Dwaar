"""Harness for the helpdesk and community tests: real Postgres, real identity + module, real signed JWTs, real OTP sign-in.

Everything goes through the HTTP API with real tokens. Fixtures that no API can build for another person (memberships, role
grants) are written through the OWNER role exactly like the identity tests do. ``World.svc`` opens a service-level transaction
as ``dwaar_app`` with the RLS context of a real actor so tests can drive the clocks with an explicit ``now``.
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_api.core.db import Database, RequestContext
from dwaar_api.main import create_app
from dwaar_api.modules.helpdesk.views import Actor
from dwaar_common.ids import uuid7
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.identity._support import IdentityHarness, Person, Society

HELPDESK_SHIM = "tests.integration.helpdesk.shim_modules"
COMMUNITY_SHIM = "tests.integration.community.shim_modules"
UA = {"User-Agent": "dwaar-ops-tests"}
ELEVATED = {"secretary", "treasurer", "committee", "estate_mgr", "guard_sup", "auditor"}


@dataclass
class Team:
    """The people of one society, created lazily."""

    society: Society
    people: dict[str, Person] = field(default_factory=dict)


@dataclass
class World:
    idh: IdentityHarness
    soc: Society
    client: TestClient
    database: Database
    app: Any
    _n: int = 100
    team: Team | None = None
    teams: dict[uuid.UUID, Team] = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------ calls
    def call(
        self,
        who: Person | None,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        key: str | None = None,
        headers: dict[str, str] | None = None,
        society: uuid.UUID | bool | None = True,
        content: bytes | None = None,
    ) -> Any:
        """One request. Writes get a fresh Idempotency-Key unless ``key`` is given; routes whose path has no society get
        ``X-Society-Id`` (``society=False`` omits it, a uuid names another society)."""
        merged: dict[str, str] = dict(who.headers) if who else {}
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            merged["Idempotency-Key"] = key or f"ot-{uuid.uuid4()}"
        if society is not False and not path.startswith("/v1/societies/"):
            merged["X-Society-Id"] = str(self.soc.id if society is True else society)
        merged.update(headers or {})
        return self.client.request(
            method, path, headers=merged, json=json, params=params, content=content
        )

    # ------------------------------------------------------------------------------------------ people
    def next_n(self) -> int:
        self._n += 1
        return self._n

    def person(self) -> Person:
        return self.idh.login(self.next_n(), client=self.client)

    def staff(self, role: str, *, soc: Society | None = None) -> Person:
        who = self.person()
        self.idh.seed_grant(
            (soc or self.soc).id,
            who.id,
            role,
            expires="30 days" if role in {"auditor", "vendor_tech"} else None,
        )
        if role in ELEVATED:
            self.idh.elevate_session(who)
        return who

    def resident(
        self,
        unit: uuid.UUID,
        kind: str,
        *,
        lives: bool = True,
        verification: str = "verified",
        soc: Society | None = None,
    ) -> Person:
        who = self.person()
        self.idh.seed_membership(
            (soc or self.soc).id, who.id, unit, kind, lives=lives, verification=verification
        )
        return who

    def unit(self, label: str) -> uuid.UUID:
        return self.soc.units[label]

    def add_block(
        self, name: str, labels: tuple[str, ...]
    ) -> tuple[uuid.UUID, dict[str, uuid.UUID]]:
        """A second block with units in the main society (the harness society has one block)."""
        block = uuid7()
        ids: dict[str, uuid.UUID] = {}
        with self.idh.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(self.soc.id),))
            conn.execute(
                "INSERT INTO blocks (id, society_id, name, floors) VALUES (%s, %s, %s, 10)",
                (block, self.soc.id, name),
            )
            for label in labels:
                uid = uuid7()
                conn.execute(
                    "INSERT INTO units (id, society_id, block_id, label, floor) VALUES (%s, %s, %s, %s, 1)",
                    (uid, self.soc.id, block, label),
                )
                ids[label] = uid
        return block, ids

    def second_society(self) -> Society:
        return self.idh.society("Other Towers", units=("Z-101", "Z-102"))

    # ------------------------------------------------------------------------------------------ oracles
    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        return self.idh.admin_rows(sql, params)

    def outbox(
        self, event_type: str, aggregate_id: str | uuid.UUID | None = None
    ) -> list[dict[str, Any]]:
        rows = self.rows(
            "SELECT aggregate_id, aggregate_version, payload FROM outbox WHERE event_type = %s"
            " AND (%s::uuid IS NULL OR aggregate_id = %s::uuid) ORDER BY occurred_at, aggregate_version",
            (event_type, aggregate_id, aggregate_id),
        )
        return [{"aggregate_id": r[0], "version": r[1], "payload": r[2]} for r in rows]

    def audit(self, operation: str) -> list[tuple[Any, ...]]:
        return self.rows(
            "SELECT operation, actor_id, effective_role, object_id, diff_masked, reason, approver_id FROM audit_log"
            " WHERE operation = %s ORDER BY at",
            (operation,),
        )

    def sql(self, statement: str, params: tuple[Any, ...] = ()) -> None:
        """A write through the admin role (tests only: age a ticket, move a clock)."""
        with self.idh.db.admin_conn() as conn:
            conn.execute(statement, params)  # type: ignore[call-overload]

    # ------------------------------------------------------------------------------------------ service level
    @contextlib.contextmanager
    def svc(
        self,
        person: Person | None,
        role: str,
        *,
        wide: bool = True,
        units: tuple[uuid.UUID, ...] = (),
        soc: Society | None = None,
    ) -> Iterator[tuple[Any, RequestContext, Actor]]:
        """A service-level transaction with the RLS context of a real actor (clock-controlled tests)."""
        sid = (soc or self.soc).id
        pid = person.id if person else None
        ctx = RequestContext(sid, pid, role, uuid7())
        with self.database.app_tx(ctx) as conn:
            yield conn, ctx, Actor(pid or uuid7(), role, wide, frozenset(units))


@contextlib.contextmanager
def world(db: DbHandle, shim: str, **state: Any) -> Iterator[World]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=shim)
    for key, value in state.items():
        setattr(app.state, key, value)
    idh = IdentityHarness(db, app, database)
    idh.tune(ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    soc = idh.society("Ops Heights", units=("A-101", "A-102", "A-103", "B-201", "B-202", "C-301"))
    w = World(idh, soc, client, database, app, _n=100)
    try:
        yield w
    finally:
        database.dispose()


@pytest.fixture
def hw(db: DbHandle) -> Iterator[World]:
    with world(db, HELPDESK_SHIM) as w:
        yield w


def text_of(response: Any) -> str:
    return json.dumps(response.json(), default=str)
