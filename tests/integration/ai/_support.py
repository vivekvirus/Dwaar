"""Harness for the AI tests: real Postgres, the real identity + organisation + visits (the gate) + AI modules, real signed JWTs, real OTP sign-in.

Everything goes through the HTTP API with real tokens. The model is the labelled SIMULATOR, or the COMPROMISED test double installed per test.
The ticket, notice and shift modules do not exist yet: tests register FAKES through the narrow ports (``AiRuntime.ports`` / ``AiRuntime.sources``).
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Connection

from dwaar_ai_gateway.config import GatewayConfig
from dwaar_ai_gateway.pipeline import Gateway
from dwaar_ai_gateway.providers import ProviderRegistry, SimulatorProvider
from dwaar_ai_gateway.types import Caller, SourceDoc
from dwaar_api.core.db import Database, RequestContext
from dwaar_api.main import create_app
from dwaar_api.modules.ai.ports import AiRuntime
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.identity._support import IdentityHarness, Person, Society
from tests.integration.visits._support import UA, VW

SHIM_PACKAGE = "tests.integration.ai.shim_modules"
UNITS = ("A-101", "A-102", "A-103", "B-201", "B-202", "C-301")


class FakePort:
    """A deterministic executor standing in for a module that does not exist yet (tickets, notices, shifts)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[dict[str, Any]] = []
        self.fail = False

    def execute(
        self,
        conn: Connection,
        ctx: RequestContext,
        payload: Mapping[str, Any],
        *,
        proposal_id: uuid.UUID,
        external_key: str,
    ) -> Mapping[str, Any]:
        if self.fail:
            raise RuntimeError("port exploded")
        self.calls.append(
            {
                "payload": dict(payload),
                "proposal_id": str(proposal_id),
                "external_key": external_key,
                "society": str(ctx.society_id),
                "actor": str(ctx.person_id),
            }
        )
        return {
            "id": str(uuid.uuid5(proposal_id, self.name)),
            "created": True,
            "number": len(self.calls),
        }


class FakeTickets:
    """TicketSource fake: returns what the 'ticket module' says the caller may see (the gateway re-checks it)."""

    def __init__(self) -> None:
        self.docs: list[SourceDoc] = []
        self.asked: list[list[str]] = []

    def tickets(self, caller: Caller, ticket_ids: Sequence[str]) -> Sequence[SourceDoc]:
        self.asked.append(list(ticket_ids))
        return [d for d in self.docs if d.source_id in set(ticket_ids)]


class FakeShifts:
    def __init__(self) -> None:
        self.docs: list[SourceDoc] = []

    def events(self, caller: Caller, shift_id: str) -> Sequence[SourceDoc]:
        return list(self.docs)


def install_runtime(
    app: FastAPI, provider: Any = None, *, timeout: float = 2.0, clock: Any = None
) -> AiRuntime:
    """Replace the app's AI runtime (also used by the acceptance scenarios): ``provider`` selected, ports and sources empty."""
    provider = provider or SimulatorProvider()
    cfg = GatewayConfig(environment="test", provider=provider.name, timeout_seconds=timeout)
    reg = ProviderRegistry(cfg)
    reg.register_test_double(provider)
    rt = AiRuntime(gateway=Gateway(cfg, providers=reg), clock=clock)
    app.state.ai = rt
    return rt


@dataclass
class AW:
    vw: VW
    app: FastAPI
    other: Society
    other_secretary: Person
    people: dict[str, Person] = field(default_factory=dict)
    ports: dict[str, FakePort] = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------ convenience
    @property
    def soc(self) -> Society:
        return self.vw.soc

    @property
    def rt(self) -> AiRuntime:
        rt = self.app.state.ai
        assert isinstance(rt, AiRuntime)
        return rt

    def call(self, who: Person | None, method: str, path: str, **kw: Any) -> Any:
        return self.vw.call(who, method, path, **kw)

    def install(
        self, provider: Any = None, *, timeout: float = 2.0, clock: Any = None
    ) -> AiRuntime:
        """A fresh AI runtime: ``provider`` (default: the simulator) selected, ports and sources empty."""
        return install_runtime(self.app, provider, timeout=timeout, clock=clock)

    def fake_ports(self, *names: str) -> dict[str, FakePort]:
        for n in names:
            self.ports[n] = FakePort(n)
            self.rt.ports[n] = self.ports[n]  # type: ignore[assignment]
        return self.ports

    def person(
        self,
        name: str,
        role: str | None = None,
        *,
        unit: str | None = None,
        kind: str | None = None,
        lives: bool = True,
    ) -> Person:
        who = self.vw.person(name)
        if role:
            self.vw.idh.seed_grant(
                self.soc.id, who.id, role, expires="90 days" if role == "auditor" else None
            )
            self.vw.idh.elevate_session(who)
        if unit and kind:
            self.vw.idh.seed_membership(
                self.soc.id, who.id, self.soc.units[unit], kind, lives=lives
            )
        self.people[name] = who
        return who

    def unit(self, label: str) -> uuid.UUID:
        return self.soc.units[label]

    def set_quota(self, per_day: int, society: Society | None = None) -> None:
        """The per-society daily allowance (organisation module's ``society_quotas``; the test society was not created through the API, so
        the row is written through the owner role like the other fixtures)."""
        soc = society or self.soc
        with self.vw.idh.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
            conn.execute(
                "INSERT INTO society_quotas (society_id, ai_requests_per_day) VALUES (%s, %s)"
                " ON CONFLICT (society_id) DO UPDATE SET ai_requests_per_day = EXCLUDED.ai_requests_per_day",
                (soc.id, per_day),
            )

    # ------------------------------------------------------------------------------------------ AI calls
    def ask(
        self,
        who: Person,
        feature: str,
        inputs: dict[str, Any] | None = None,
        *,
        key: str | None = None,
        language: str = "en",
        society: Any = True,
    ) -> Any:
        return self.call(
            who,
            "POST",
            "/v1/ai/proposals",
            json={"feature_id": feature, "inputs": inputs or {}, "language": language},
            key=key,
            society=society,
        )

    def confirm(
        self,
        who: Person,
        proposal: dict[str, Any],
        *,
        edits: dict[str, Any] | None = None,
        payload_hash: str | None = None,
        key: str | None = None,
        versions: Any = None,
    ) -> Any:
        body: dict[str, Any] = {"payload_hash": payload_hash or proposal["payload_hash"]}
        if edits is not None:
            body["edits"] = edits
        if versions is not None:
            body["expected_target_versions"] = versions
        return self.call(
            who, "POST", f"/v1/ai/proposals/{proposal['id']}/confirm", json=body, key=key
        )

    def draft(self, who: Person, feature: str, inputs: dict[str, Any], **kw: Any) -> dict[str, Any]:
        r = self.ask(who, feature, inputs, **kw)
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        assert body["status"] == "ok" and body["proposal"], body
        return body

    # ------------------------------------------------------------------------------------------ oracles
    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        return self.vw.rows(sql, params)

    def runs(self) -> list[dict[str, Any]]:
        cols = (
            "id",
            "feature_id",
            "provider",
            "model",
            "simulation",
            "model_called",
            "prompt_version",
            "schema_version",
            "status",
            "reason",
            "outcome",
            "input_hash",
            "diagnostics",
            "redaction_counts",
            "latency_ms",
            "cost_paise",
            "source_ids",
            "actor_role",
        )  # noqa: E501
        rows = self.rows(
            f"SELECT {', '.join(cols)} FROM ai_runs WHERE society_id = %s ORDER BY id",
            (self.soc.id,),
        )
        return [dict(zip(cols, r, strict=True)) for r in rows]

    def end_membership(self, who: Person) -> None:
        """The household membership ends NOW (the access index follows through its trigger, so the next request sees the new standing)."""
        with self.vw.idh.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(self.soc.id),))
            conn.execute(
                "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s",
                (who.id,),
            )

    def revoke_grant(self, who: Person, role: str) -> None:
        with self.vw.idh.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(self.soc.id),))
            conn.execute(
                "UPDATE role_grants SET revoked_at = now(), revoked_by = %s WHERE person_id = %s AND role = %s",
                (who.id, who.id, role),
            )

    def bump_unit(self, label: str) -> int:
        """Move a unit's version on through the real organisation API (PATCH the floor) and return the new version."""
        uid = self.unit(label)
        got = self.call(self.vw.secretary, "GET", f"/v1/societies/{self.soc.id}/units/{uid}")
        assert got.status_code == 200, got.text
        r = self.call(
            self.vw.secretary,
            "PATCH",
            f"/v1/societies/{self.soc.id}/units/{uid}",
            json={"floor": 7, "expected_version": got.json()["version"]},
        )
        assert r.status_code == 200, r.text
        return int(r.json()["version"])


@contextlib.contextmanager
def ai_world(db: DbHandle) -> Iterator[AW]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    idh = IdentityHarness(db, app, database)
    idh.tune(ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    soc = idh.society("Gate Heights", units=UNITS)
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
    other = idh.society("Lake View", units=("A-101", "A-102"))
    other_sec = idh.login(950, client=client)
    idh.seed_grant(other.id, other_sec.id, "secretary")
    idh.elevate_session(other_sec)
    vw = VW(idh, soc, client, secretary, guard, guard_sup, _n=100)
    world = AW(vw, app, other, other_sec)
    world.install()
    try:
        yield world
    finally:
        database.dispose()


@pytest.fixture
def aw(db: DbHandle) -> Iterator[AW]:
    with ai_world(db) as world:
        yield world


def body_text(response: Any) -> str:
    return json.dumps(response.json(), default=str, ensure_ascii=False)
