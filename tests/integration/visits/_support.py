"""Harness for the visits tests: real Postgres, the real identity + visits modules, real signed JWTs, real OTP sign-in.

Everything goes through the HTTP API with real tokens. Fixtures that no API can build for another person (memberships,
role grants) are written through the OWNER role exactly like the identity tests do; the triggers keep the access index in
step as in production. ``VW`` adds the visit-specific scenario helpers (gates, devices, households).
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

from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_common.signing import generate_private_key, public_key_to_b64
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.identity._support import IdentityHarness, Person, Society

SHIM_PACKAGE = "tests.integration.visits.shim_modules"
UA = {"User-Agent": "dwaar-visits-tests"}
SOCIETY_ROUTE_PREFIX = "/v1/societies/"


def new_key() -> str:
    """A fresh Ed25519 PUBLIC key in the enrolment format (the private half is thrown away: tests never sign)."""
    return public_key_to_b64(generate_private_key().public_key())


@dataclass
class Household:
    unit: uuid.UUID
    owner: Person
    tenant: Person | None = None
    family: Person | None = None
    nr_owner: Person | None = None


@dataclass
class VW:
    idh: IdentityHarness
    soc: Society
    client: TestClient
    secretary: Person
    guard: Person
    guard_sup: Person
    _n: int = 100
    gate_id: uuid.UUID | None = None
    device_id: uuid.UUID | None = None
    people: dict[str, Person] = field(default_factory=dict)

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
        society: uuid.UUID | None | bool = True,
    ) -> Any:
        """One request. Writes get a fresh Idempotency-Key unless ``key`` is given; routes without the society in the path
        get ``X-Society-Id`` (pass ``society=False`` to omit it or a uuid to name another society)."""
        merged: dict[str, str] = dict(who.headers) if who else {}
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            merged["Idempotency-Key"] = key or f"vt-{uuid.uuid4()}"
        if society is not False and not path.startswith(SOCIETY_ROUTE_PREFIX):
            merged["X-Society-Id"] = str(self.soc.id if society is True else society)
        merged.update(headers or {})
        return self.client.request(method, path, headers=merged, json=json, params=params)

    def s(self, tail: str) -> str:
        return f"/v1/societies/{self.soc.id}/{tail}"

    # ------------------------------------------------------------------------------------------ people
    def next_n(self) -> int:
        self._n += 1
        return self._n

    def person(self, name: str | None = None) -> Person:
        who = self.idh.login(self.next_n(), client=self.client)
        if name:
            self.people[name] = who
        return who

    def unit(self, label: str) -> uuid.UUID:
        return self.soc.units[label]

    def resident(
        self,
        unit: uuid.UUID,
        kind: str,
        *,
        lives: bool = True,
        delegated: bool = False,
        verification: str = "verified",
    ) -> Person:
        who = self.person()
        self.idh.seed_membership(
            self.soc.id, who.id, unit, kind, lives=lives, verification=verification
        )
        if delegated:
            self.delegate(who, unit)
        return who

    def delegate(self, who: Person, unit: uuid.UUID) -> None:
        with self.idh.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(self.soc.id),))
            conn.execute(
                "UPDATE memberships SET is_primary_approver = true WHERE person_id = %s AND unit_id = %s",
                (who.id, unit),
            )

    def household(
        self, label: str, *, tenant: bool = False, family: bool = True, nr_owner: bool = False
    ) -> Household:
        """An occupying owner, optionally a tenant, a DELEGATED family member and a non-resident co-owner."""
        unit = self.unit(label)
        owner = self.resident(unit, "owner")
        return Household(
            unit,
            owner,
            tenant=self.resident(unit, "tenant") if tenant else None,
            family=self.resident(unit, "family", delegated=True) if family else None,
            nr_owner=self.resident(unit, "owner", lives=False) if nr_owner else None,
        )

    # ------------------------------------------------------------------------------------------ gate setup
    def make_gate(self, name: str = "Main gate", kind: str = "mixed") -> uuid.UUID:
        r = self.call(self.secretary, "POST", self.s("gates"), json={"name": name, "kind": kind})
        assert r.status_code == 201, r.text
        return uuid.UUID(r.json()["id"])

    def make_device(
        self, gate: uuid.UUID | None = None, *, name: str = "Gate terminal 1"
    ) -> uuid.UUID:
        """Enrolment request by a guard, approved by the supervisor (maker != checker): an ACTIVE device."""
        r = self.call(
            self.guard,
            "POST",
            self.s("devices"),
            json={
                "kind": "terminal",
                "name": name,
                "gate_id": str(gate) if gate else None,
                "public_key": new_key(),
            },
        )
        assert r.status_code == 201, r.text
        device = r.json()
        d = self.call(
            self.guard_sup,
            "POST",
            self.s(f"devices/{device['id']}/decision"),
            json={"decision": "approve", "expected_version": device["version"]},
        )
        assert d.status_code == 200, d.text
        return uuid.UUID(device["id"])

    def setup_gate(self) -> None:
        self.gate_id = self.make_gate()
        self.device_id = self.make_device(self.gate_id)

    # ------------------------------------------------------------------------------------------ visit flows
    def notice(self, consent: bool = True) -> dict[str, Any]:
        return {"version": "visitor-notice-v1", "language": "en", "consent_given": consent}

    def request_body(self, unit: uuid.UUID, **extra: Any) -> dict[str, Any]:
        assert self.gate_id is not None
        body: dict[str, Any] = {
            "unit_id": str(unit),
            "kind": "guest",
            "visitor_alias": "Test Visitor",
            "people_count": 1,
            "gate_id": str(self.gate_id),
            "destination_confirmed": True,
            "notice": self.notice(),
        }
        body.update(extra)
        return body

    def raise_request(self, unit: uuid.UUID, **extra: Any) -> dict[str, Any]:
        r = self.call(
            self.guard, "POST", "/v1/approval-requests", json=self.request_body(unit, **extra)
        )
        assert r.status_code == 201, r.text
        body: dict[str, Any] = r.json()
        return body

    def decide(
        self,
        who: Person,
        request: dict[str, Any],
        decision: str = "approve",
        *,
        version: int | None = None,
        action: uuid.UUID | None = None,
        key: str | None = None,
    ) -> Any:
        return self.call(
            who,
            "POST",
            f"/v1/approval-requests/{request['id']}/decision",
            json={
                "decision": decision,
                "expected_version": version if version is not None else request["version"],
                "client_action_id": str(action or uuid.uuid4()),
            },
            key=key,
        )

    def approved_visit(self, unit: uuid.UUID, who: Person) -> tuple[dict[str, Any], dict[str, Any]]:
        request = self.raise_request(unit)
        r = self.decide(who, request)
        assert r.status_code == 200, r.text
        return request, r.json()

    def observe(
        self,
        visit_id: str | uuid.UUID,
        kind: str = "entry",
        *,
        seq: int | None = None,
        event_id: uuid.UUID | None = None,
        who: Person | None = None,
        **extra: Any,
    ) -> Any:
        assert self.gate_id is not None and self.device_id is not None
        self._seq = getattr(self, "_seq", 0) + 1
        body: dict[str, Any] = {
            "type": kind,
            "gate_id": str(self.gate_id),
            "device_id": str(self.device_id),
            "event_id": str(event_id or uuid.uuid4()),
            "seq": seq if seq is not None else self._seq,
            "occurred_at": extra.pop("occurred_at", None) or _now_iso(),
        }
        if kind == "exit":
            body["exit_basis"] = extra.pop("exit_basis", "observed")
        body.update(extra)
        return self.call(
            who or self.guard, "POST", f"/v1/visits/{visit_id}/observations", json=body
        )

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
            "SELECT operation, actor_id, effective_role, object_id, diff_masked, reason FROM audit_log"
            " WHERE operation = %s ORDER BY at",
            (operation,),
        )

    def sql(self, statement: str, params: tuple[Any, ...] = ()) -> None:
        """A write through the admin role (tests only: age a request, move a clock)."""
        with self.idh.db.admin_conn() as conn:
            conn.execute(statement, params)  # type: ignore[call-overload]

    def expire_request(self, request_id: str | uuid.UUID) -> None:
        self.sql(
            "UPDATE approval_requests SET expires_at = clock_timestamp() - interval '1 second' WHERE id = %s",
            (request_id,),
        )


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


@contextlib.contextmanager
def visits_world(db: DbHandle) -> Iterator[VW]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    idh = IdentityHarness(db, app, database)
    idh.tune(ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    soc = idh.society("Gate Heights", units=("A-101", "A-102", "A-103", "B-201", "B-202", "C-301"))
    secretary = idh.login(900, client=client)
    guard = idh.login(901, client=client)
    guard_sup = idh.login(902, client=client)
    idh.seed_grant(soc.id, secretary.id, "secretary")
    idh.seed_grant(soc.id, guard.id, "guard")
    idh.seed_grant(soc.id, guard_sup.id, "guard_sup")
    idh.elevate_session(secretary)
    idh.elevate_session(guard_sup)
    world = VW(idh, soc, client, secretary, guard, guard_sup, _n=100)
    try:
        yield world
    finally:
        database.dispose()


@pytest.fixture
def vw(db: DbHandle) -> Iterator[VW]:
    with visits_world(db) as world:
        yield world


def text_of(response: Any) -> str:
    return json.dumps(response.json(), default=str)
