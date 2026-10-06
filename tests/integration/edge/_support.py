"""Harness for the edge tests: real Postgres, the real identity + visits + edge modules, real device-signed requests.

The edge agent is played by :class:`EdgeClient`: it holds a REAL Ed25519 private key, registered through the genuine device enrolment API
(requested by a guard, approved by the supervisor), and signs every request and every event exactly as ``docs/contracts/edge-sync.md``
says. Nothing in the cloud is stubbed. Fixtures no API can build (memberships, role grants) go through the owner role like the identity
and visits tests do.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_api.modules.edge.auth import sign_request_headers
from dwaar_common.events import EdgeEvent
from dwaar_common.signing import generate_private_key, public_key_to_b64, sign_edge_event
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.identity._support import IdentityHarness
from tests.integration.visits._support import UA, VW

SHIM_PACKAGE = "tests.integration.edge.shim_modules"


def iso(moment: datetime) -> str:
    return (
        moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    )


@dataclass
class EdgeClient:
    """A device: its id, its private key and the three-header signing of every request."""

    world: EdgeWorld
    device_id: uuid.UUID
    key: Ed25519PrivateKey
    society_id: uuid.UUID
    gate_id: uuid.UUID | None
    _seq: int = 0
    seen: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------------------------------ requests
    def headers(
        self, method: str, target: str, body: bytes = b"", *, timestamp: str | None = None
    ) -> dict[str, str]:
        return sign_request_headers(
            self.key, self.device_id, method, target, body, timestamp=timestamp
        )

    def request(
        self,
        method: str,
        target: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        timestamp: str | None = None,
        sign_as: Ed25519PrivateKey | None = None,
    ) -> Any:
        signer = sign_as or self.key
        signed = sign_request_headers(
            signer, self.device_id, method, target, body, timestamp=timestamp
        )
        merged = {**signed, **(headers or {})}
        if body:
            merged.setdefault("Content-Type", "application/json")
        return self.world.client.request(method, target, headers=merged, content=body or None)

    def policy(self, after: int | None = None, **kw: Any) -> Any:
        target = "/v1/edge/policy" if after is None else f"/v1/edge/policy?after={after}"
        return self.request("GET", target, **kw)

    def me(self) -> Any:
        return self.request("GET", "/v1/edge/me")

    def sync(self, events: list[dict[str, Any]], **extra: Any) -> Any:
        return self.sync_raw(
            json.dumps({"device_id": str(self.device_id), "events": events, **extra}).encode()
        )

    def sync_raw(self, body: bytes, **kw: Any) -> Any:
        return self.request("POST", "/v1/edge/sync/batches", body=body, **kw)

    # ------------------------------------------------------------------------------------------ events
    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def event(
        self,
        type_: str,
        entity_id: uuid.UUID | str,
        *,
        seq: int | None = None,
        payload: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
        clock_uncertainty_ms: int = 50,
        event_id: uuid.UUID | None = None,
        sign: bool = True,
        signer: Ed25519PrivateKey | None = None,
        society_id: uuid.UUID | None = None,
        device_id: uuid.UUID | None = None,
        policy_version: int = 1,
        entity_version: int = 1,
    ) -> dict[str, Any]:
        base = EdgeEvent.build(
            society_id=society_id or self.society_id,
            device_id=device_id or self.device_id,
            seq=seq if seq is not None else self.next_seq(),
            entity_id=uuid.UUID(str(entity_id)),
            entity_version=entity_version,
            type=type_,
            policy_version=policy_version,
            payload=payload if payload is not None else {"decision_source": "cached_policy"},
            occurred_at=occurred_at or datetime.now(UTC),
            clock_uncertainty_ms=clock_uncertainty_ms,
            event_id=event_id,
        )
        if sign:
            base = sign_edge_event(signer or self.key, base)
        return base.to_wire()

    def entry(self, visit: uuid.UUID | str, **kw: Any) -> dict[str, Any]:
        return self.event("EntryObserved", visit, **kw)

    def exit(self, visit: uuid.UUID | str, **kw: Any) -> dict[str, Any]:
        payload = kw.pop("payload", {"exit_basis": "observed", "decision_source": "cached_policy"})
        return self.event("ExitObserved", visit, payload=payload, **kw)


@dataclass
class EdgeWorld(VW):
    database: Database | None = None
    app: Any = None

    # ------------------------------------------------------------------------------------------ devices
    def edge_device(
        self, *, kind: str = "gateway", gate: uuid.UUID | None = None, approve: bool = True,
        name: str = "Edge gateway", bind_gate: bool = True,
    ) -> EdgeClient:  # fmt: skip
        """Enrol a device with a REAL key through the API (guard requests, supervisor approves) and return its client."""
        key = generate_private_key()
        gate_id = (gate or self.gate_id) if bind_gate else None
        r = self.call(
            self.guard, "POST", self.s("devices"),
            json={
                "kind": kind, "name": f"{name} {uuid.uuid4().hex[:6]}", "gate_id": str(gate_id) if gate_id else None,
                "public_key": public_key_to_b64(key.public_key()), "simulation": True,
            },
        )  # fmt: skip
        assert r.status_code == 201, r.text
        device = r.json()
        if approve:
            d = self.call(
                self.guard_sup, "POST", self.s(f"devices/{device['id']}/decision"),
                json={"decision": "approve", "expected_version": device["version"]},
            )  # fmt: skip
            assert d.status_code == 200, d.text
        return EdgeClient(self, uuid.UUID(device["id"]), key, self.soc.id, gate_id)

    def revoke_device(self, device: EdgeClient, reason: str = "lost on site") -> None:
        r = self.call(
            self.guard_sup, "POST", self.s(f"devices/{device.device_id}/revoke"),
            json={"reason": reason, "expected_version": self.device_version(device.device_id)},
        )  # fmt: skip
        assert r.status_code == 200, r.text

    def device_version(self, device_id: uuid.UUID) -> int:
        return int(self.rows("SELECT version FROM devices WHERE id = %s", (device_id,))[0][0])

    # ------------------------------------------------------------------------------------------ visits
    def authorised_visit(self, unit: uuid.UUID | None = None) -> uuid.UUID:
        """A visit that a household APPROVED (permission window open), not yet entered."""
        unit = unit or self.soc.units["A-101"]
        household = self.households.setdefault(str(unit), self.household_for(unit))
        request = self.raise_request(unit)
        r = self.decide(household.owner, request)
        assert r.status_code == 200, r.text
        return uuid.UUID(request["visit_id"])

    def household_for(self, unit: uuid.UUID) -> Any:
        label = next(k for k, v in self.soc.units.items() if v == unit)
        return self.household(label, family=False)

    households: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------ oracles
    def count(self, table: str, where: str = "true", params: tuple[Any, ...] = ()) -> int:
        return int(self.rows(f"SELECT count(*) FROM {table} WHERE {where}", params)[0][0])  # noqa: S608

    def visit_state(self, visit: uuid.UUID) -> str:
        return str(self.rows("SELECT state FROM visits WHERE id = %s", (visit,))[0][0])

    def exceptions(self, kind: str | None = None) -> list[tuple[Any, ...]]:
        return self.rows(
            "SELECT kind, state, visit_id, evidence, reason FROM exceptions WHERE (%s::text IS NULL OR kind = %s) ORDER BY created_at",
            (kind, kind),
        )

    def age_authorisation(self, visit: uuid.UUID, minutes: int = 120) -> None:
        self.sql(
            "UPDATE visits SET authorised_until = authorised_until - make_interval(mins => %s),"
            " authorised_at = authorised_at - make_interval(mins => %s) WHERE id = %s",
            (minutes, minutes, visit),
        )


@contextlib.contextmanager
def edge_world(db: DbHandle) -> Iterator[EdgeWorld]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    idh = IdentityHarness(db, app, database)
    idh.tune(ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    soc = idh.society("Edge Heights", units=("A-101", "A-102", "A-103", "B-201", "B-202", "C-301"))
    secretary = idh.login(900, client=client)
    guard = idh.login(901, client=client)
    guard_sup = idh.login(902, client=client)
    idh.seed_grant(soc.id, secretary.id, "secretary")
    idh.seed_grant(soc.id, guard.id, "guard")
    idh.seed_grant(soc.id, guard_sup.id, "guard_sup")
    idh.elevate_session(secretary)
    idh.elevate_session(guard_sup)
    world = EdgeWorld(
        idh, soc, client, secretary, guard, guard_sup, _n=100, database=database, app=app
    )
    world.gate_id = world.make_gate()
    try:
        yield world
    finally:
        database.dispose()


@pytest.fixture
def ew(db: DbHandle) -> Iterator[EdgeWorld]:
    with edge_world(db) as world:
        yield world


def now() -> datetime:
    return datetime.now(UTC)


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)
