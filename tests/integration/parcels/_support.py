"""Harness for the parcels, staff and shifts tests: real Postgres, the real identity + visits + parcels + staff + shifts modules, real signed JWTs.

Everything goes through the HTTP API with real tokens. Memberships and role grants for other people are written through the OWNER role (exactly
like the identity and visits tests do); the triggers keep the access index in step as in production. ``PW`` extends the visits world with a
SECOND society (B) with its own secretary, guard, supervisor and resident, so every society-scoped route can be probed with A's ids from B.
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.identity._support import IdentityHarness, Person, Society
from tests.integration.visits._support import UA, VW

SHIM_PACKAGE = "tests.integration.parcels.shim_modules"


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def now() -> datetime:
    return datetime.now(UTC)


ALL_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def schedule_now(span_minutes: int = 30) -> dict[str, Any]:
    """Valid hours that contain the present moment (Asia/Kolkata), whatever the time of day."""
    from zoneinfo import ZoneInfo

    local = datetime.now(ZoneInfo("Asia/Kolkata"))
    minute = local.hour * 60 + local.minute
    start, end = max(0, minute - span_minutes), min(24 * 60, minute + span_minutes)
    return {
        "days": ALL_DAYS,
        "from": f"{start // 60:02d}:{start % 60:02d}",
        "to": f"{end // 60:02d}:{end % 60:02d}",
    }


def schedule_elsewhere() -> dict[str, Any]:
    """Valid hours that do NOT contain the present moment (Asia/Kolkata)."""
    from zoneinfo import ZoneInfo

    local = datetime.now(ZoneInfo("Asia/Kolkata"))
    return {
        "days": ALL_DAYS,
        "from": "13:00" if local.hour < 12 else "01:00",
        "to": "14:00" if local.hour < 12 else "02:00",
    }


@dataclass
class Other:
    """Society B: nothing in it may ever be reachable with A's ids (and nothing of B from A)."""

    soc: Society
    secretary: Person
    guard: Person
    guard_sup: Person
    resident: Person
    unit: uuid.UUID
    gate_id: uuid.UUID | None = None


@dataclass
class PW:
    vw: VW
    other: Other
    estate_mgr: Person
    codes: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------ delegation to the visits world
    @property
    def idh(self) -> IdentityHarness:
        return self.vw.idh

    @property
    def soc(self) -> Society:
        return self.vw.soc

    @property
    def secretary(self) -> Person:
        return self.vw.secretary

    @property
    def guard(self) -> Person:
        return self.vw.guard

    @property
    def guard_sup(self) -> Person:
        return self.vw.guard_sup

    @property
    def gate_id(self) -> uuid.UUID:
        assert self.vw.gate_id is not None
        return self.vw.gate_id

    def call(self, who: Person | None, method: str, path: str, **kw: Any) -> Any:
        return self.vw.call(who, method, path, **kw)

    def call_b(self, who: Person | None, method: str, path: str, **kw: Any) -> Any:
        """The same call, but into society B (``X-Society-Id`` = B)."""
        return self.vw.call(who, method, path, society=self.other.soc.id, **kw)

    def household(self, label: str, **kw: Any) -> Any:
        return self.vw.household(label, **kw)

    def resident(self, unit: uuid.UUID, kind: str = "owner", **kw: Any) -> Person:
        return self.vw.resident(unit, kind, **kw)

    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        return self.vw.rows(sql, params)

    def sql(self, statement: str, params: tuple[Any, ...] = ()) -> None:
        self.vw.sql(statement, params)

    def outbox(
        self, event_type: str, aggregate_id: str | uuid.UUID | None = None
    ) -> list[dict[str, Any]]:
        return self.vw.outbox(event_type, aggregate_id)

    def audit(self, operation: str) -> list[tuple[Any, ...]]:
        return self.vw.audit(operation)

    # ------------------------------------------------------------------------------------------ parcels
    def expect(
        self, who: Person, unit: uuid.UUID, brand: str = "Zomart", **extra: Any
    ) -> dict[str, Any]:
        body = {
            "unit_id": str(unit), "brand": brand, "expected_from": iso(now() - timedelta(hours=1)),
            "expected_until": iso(now() + timedelta(hours=6)),
        }  # fmt: skip
        body.update(extra)
        r = self.call(who, "POST", "/v1/parcel-expectations", json=body)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def receive(
        self, unit: uuid.UUID, brand: str = "Zomart", *, who: Person | None = None, **extra: Any
    ) -> dict[str, Any]:
        body = {
            "unit_id": str(unit),
            "gate_id": str(self.gate_id),
            "brand": brand,
            "carrier": "Bluefleet",
        }
        body.update(extra)
        r = self.call(who or self.guard, "POST", "/v1/parcels", json=body)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def store(self, parcel: dict[str, Any], bin_code: str = "B-07") -> dict[str, Any]:
        r = self.call(
            self.guard, "POST", f"/v1/parcels/{parcel['id']}/store",
            json={"bin_code": bin_code, "expected_version": parcel["version"]},
        )  # fmt: skip
        assert r.status_code == 200, r.text
        out: dict[str, Any] = r.json()
        return out

    def stored_parcel(self, unit: uuid.UUID, brand: str = "Zomart") -> dict[str, Any]:
        return self.store(self.receive(unit, brand))

    def issue_token(self, who: Person, parcel: dict[str, Any]) -> tuple[dict[str, Any], str]:
        r = self.call(
            who,
            "POST",
            f"/v1/parcels/{parcel['id']}/pickup-token",
            json={"expected_version": parcel["version"]},
        )
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        return body, str(body["pickup_token"])

    def collect_body(
        self, token: str, kind: str = "recipient", person: Person | None = None
    ) -> dict[str, Any]:
        collector: dict[str, Any] = {"kind": kind}
        if person is not None:
            collector["person_id"] = str(person.id)
        return {"method": "token", "token": token, "collector": collector}

    # ------------------------------------------------------------------------------------------ staff
    def consent(
        self,
        who: Person | None = None,
        purposes: tuple[str, ...] = (
            "engagement_record",
            "attendance",
            "id_capture",
            "photo",
            "police_verification_status",
        ),
        **extra: Any,
    ) -> dict[str, Any]:
        body = {
            "language": "hi", "notice_version": "staff-notice-v1", "purposes": list(purposes), "staff_action_recorded": True,
            "notice_read_aloud": True,
        }  # fmt: skip
        body.update(extra)
        r = self.call(who or self.secretary, "POST", "/v1/staff-consents", json=body)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def register_staff(
        self,
        name: str = "Sunita Devi",
        *,
        consent: dict[str, Any] | None = None,
        phone: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        c = consent or self.consent()
        self.vw._n += 1  # noqa: SLF001 (a fresh fictional number in the reserved range)
        body = {
            "consent_id": c["id"], "display_name": name, "phone": phone or f"+9199999{60000 + self.vw._n:05d}",  # noqa: SLF001
            "staff_type": "cook",
        }  # fmt: skip
        body.update(extra)
        r = self.call(self.secretary, "POST", "/v1/staff", json=body)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def engage(
        self, who: Person, staff: dict[str, Any], unit: uuid.UUID, **extra: Any
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "staff_ref": staff["staff_ref"], "unit_id": str(unit), "duty": "cooking",
            "schedule": {"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], "from": "00:00", "to": "24:00"},
        }  # fmt: skip
        body.update(extra)
        r = self.call(who, "POST", "/v1/staff-engagements", json=body)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def issue_code(self, staff: dict[str, Any], kind: str = "code", **extra: Any) -> str:
        body = {"kind": kind, "expected_version": staff["version"], **extra}
        r = self.call(self.secretary, "POST", f"/v1/staff/{staff['id']}/credentials", json=body)
        assert r.status_code == 201, r.text
        return str(r.json().get("code") or extra.get("card_uid"))

    def check_in(self, guard: Person, code: str, direction: str = "in", **extra: Any) -> Any:
        body: dict[str, Any] = {
            "credential": {"kind": "code", "value": code}, "direction": direction, "client_event_id": str(uuid.uuid4()),
        }  # fmt: skip
        body.update(extra)
        return self.call(guard, "POST", "/v1/attendance", json=body)

    # ------------------------------------------------------------------------------------------ shifts
    def schedule(
        self,
        guard: Person,
        *,
        start: datetime | None = None,
        hours: int = 8,
        gate: uuid.UUID | None = None,
        who: Person | None = None,
    ) -> dict[str, Any]:
        s = start or (now() - timedelta(minutes=5))
        r = self.call(
            who or self.guard_sup, "POST", "/v1/shifts",
            json={"gate_id": str(gate or self.gate_id), "guard_id": str(guard.id), "planned_start": iso(s), "planned_end": iso(s + timedelta(hours=hours))},
        )  # fmt: skip
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def end_body(self, parcels: int = 0, reviewed: bool = True) -> dict[str, Any]:
        return {"checklist": {"parcels_counted": parcels, "inside_records_reviewed": reviewed}}

    def route_paths(self) -> set[str]:
        from dwaar_api.core.authz import iter_api_routes

        return {r.path for r in iter_api_routes(self.vw.client.app)}  # type: ignore[arg-type]

    def text_of(self, response: Any) -> str:
        return json.dumps(response.json(), default=str)


@contextlib.contextmanager
def parcels_world(db: DbHandle) -> Iterator[PW]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    idh = IdentityHarness(db, app, database)
    idh.tune(ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    soc = idh.society("Gate Heights", units=("A-101", "A-102", "A-103", "B-201", "B-202", "C-301"))
    secretary, guard, guard_sup = (
        idh.login(900, client=client),
        idh.login(901, client=client),
        idh.login(902, client=client),
    )
    idh.seed_grant(soc.id, secretary.id, "secretary")
    idh.seed_grant(soc.id, guard.id, "guard")
    idh.seed_grant(soc.id, guard_sup.id, "guard_sup")
    idh.elevate_session(secretary)
    idh.elevate_session(guard_sup)
    vw = VW(idh, soc, client, secretary, guard, guard_sup, _n=100)
    estate = idh.login(903, client=client)
    idh.seed_grant(soc.id, estate.id, "estate_mgr")
    idh.elevate_session(estate)
    # society B
    soc_b = idh.society("Other Heights", units=("Z-101", "Z-102"))
    b_secretary, b_guard, b_sup, b_resident = (idh.login(910 + i, client=client) for i in range(4))
    idh.seed_grant(soc_b.id, b_secretary.id, "secretary")
    idh.seed_grant(soc_b.id, b_guard.id, "guard")
    idh.seed_grant(soc_b.id, b_sup.id, "guard_sup")
    idh.elevate_session(b_secretary)
    idh.elevate_session(b_sup)
    idh.seed_membership(soc_b.id, b_resident.id, soc_b.units["Z-101"], "owner")
    other = Other(soc_b, b_secretary, b_guard, b_sup, b_resident, soc_b.units["Z-101"])
    world = PW(vw, other, estate)
    vw.setup_gate()
    # a gate in B (through its own secretary, like any society)
    r = client.post(
        f"/v1/societies/{soc_b.id}/gates", headers={**b_secretary.headers, "Idempotency-Key": f"vt-{uuid.uuid4()}"},
        json={"name": "B gate", "kind": "mixed"},
    )  # fmt: skip
    assert r.status_code == 201, r.text
    other.gate_id = uuid.UUID(r.json()["id"])
    try:
        yield world
    finally:
        database.dispose()


@pytest.fixture
def pw(db: DbHandle) -> Iterator[PW]:
    with parcels_world(db) as world:
        yield world
