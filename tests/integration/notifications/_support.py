"""Harness for the notifications tests: real Postgres, the real identity + visits + notifications modules, labelled provider simulators, an injectable
clock for the cascade.

Everything a resident, guard or supervisor does goes through the HTTP API with real signed tokens. The cascade runs as the worker would run it
(``runner.run_tick`` over the worker role), with ``now`` chosen by the test (an injectable clock) and the SIMULATED providers
(``simulation = true``) scripted per test. The one thing a test moves outside the API is TIME: ``shift_request`` ages a request's creation and expiry
together in the database, because the visits service decides expiry on the database clock (the same helper style the visits tests use).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_api.core.db import Database
from dwaar_api.main import create_app
from dwaar_api.modules.notifications import runner
from dwaar_api.modules.notifications.config import NotificationsConfig
from dwaar_api.modules.notifications.devices import token_ref_for
from dwaar_api.modules.notifications.providers import ProviderSet, SimulatedProviders
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.identity._support import IdentityHarness, Person
from tests.integration.visits._support import UA, VW

SHIM_PACKAGE = "tests.integration.notifications.shim_modules"
CFG = NotificationsConfig(providers_mode="simulator", link_hosts=frozenset({"links.dwaar.example"}))


@dataclass
class NW(VW):
    database: Database | None = None
    app: Any = None
    sims: SimulatedProviders = field(default_factory=SimulatedProviders)
    cfg: NotificationsConfig = CFG
    tokens: dict[str, str] = field(default_factory=dict)

    @property
    def providers(self) -> ProviderSet:
        return ProviderSet.from_simulators(self.sims)

    def s_(self, tail: str) -> str:
        return self.s(tail)

    # ------------------------------------------------------------------------------------------ the worker, with a clock
    def tick(self, at: dt.datetime | None = None) -> runner.Report:  # type: ignore[name-defined]
        """One worker tick of this society with ``at`` as the clock (default: now)."""
        assert self.database is not None
        moment = at or dt.datetime.now(dt.UTC)
        out = runner.run_tick(
            self.database,
            self.providers,
            societies=[self.soc.id],
            clock=lambda: moment,
            cfg=self.cfg,
        )
        return out[self.soc.id]

    def created_at(self, request_id: str | uuid.UUID) -> dt.datetime:
        return self.rows("SELECT created_at FROM approval_requests WHERE id = %s", (request_id,))[
            0
        ][0]  # type: ignore[no-any-return]

    def expires_at(self, request_id: str | uuid.UUID) -> dt.datetime:
        return self.rows("SELECT expires_at FROM approval_requests WHERE id = %s", (request_id,))[
            0
        ][0]  # type: ignore[no-any-return]

    def shift_request(self, request_id: str | uuid.UUID, seconds: float) -> None:
        """Make a request ``seconds`` older: creation, expiry and any cascade move together (the database clock decides expiry)."""
        self.sql(
            "UPDATE approval_requests SET created_at = created_at - make_interval(secs => %s),"
            " expires_at = expires_at - make_interval(secs => %s) WHERE id = %s",
            (seconds, seconds, request_id),
        )
        self.sql(
            "UPDATE notification_cascades SET started_at = started_at - make_interval(secs => %s),"
            " expires_at = expires_at - make_interval(secs => %s) WHERE request_id = %s",
            (seconds, seconds, request_id),
        )

    # ------------------------------------------------------------------------------------------ people and devices
    def register_device(
        self,
        who: Person,
        name: str,
        *,
        permission: str = "granted",
        model: str = "Redmi Note 12",
        manufacturer: str = "Xiaomi",
        os_name: str = "Android",
        os_version: str = "14",
        status: int = 201,
    ) -> dict[str, Any]:
        token = f"sim-token-{name}-" + uuid.uuid4().hex
        self.tokens[name] = token
        r = self.call(
            who,
            "POST",
            self.s("push-tokens"),
            json={
                "platform": "fcm", "token": token, "device_label": name, "device_model": model, "manufacturer": manufacturer,
                "os_name": os_name, "os_version": os_version, "app_version": "1.0.0", "notification_permission": permission,
            },
        )  # fmt: skip
        assert r.status_code == status, r.text
        body: dict[str, Any] = r.json()
        return body

    def sim_device(self, name: str) -> Any:
        """The simulated phone behind a registered device name (to script it: force-stop, offline, slow ack)."""
        return self.sims.push.device(token_ref_for(self.tokens[name]))

    def set_settings(self, who: Person, unit: uuid.UUID, **body: Any) -> Any:
        payload = {
            "primary_person_id": None,
            "approver_person_ids": [],
            "alternate_person_id": None,
            "fallback_mode": "call",
        }
        payload.update(
            {
                k: (
                    [str(i) for i in v]
                    if isinstance(v, list)
                    else str(v)
                    if isinstance(v, uuid.UUID)
                    else v
                )
                for k, v in body.items()
            }
        )
        return self.call(who, "PUT", self.s(f"units/{unit}/notification-settings"), json=payload)

    def household2(self, label: str = "A-101") -> tuple[Person, Person]:
        """An occupying owner and a DELEGATED family member of the unit: primary and alternate adult."""
        h = self.household(label, family=True)
        assert h.family is not None
        return h.owner, h.family

    # ------------------------------------------------------------------------------------------ requests
    def raise_and_start(self, unit: uuid.UUID) -> dict[str, Any]:
        """A guard raises a request and the worker's first tick starts its cascade (t = 0: the first push goes out)."""
        request = self.raise_request(unit)
        self.tick(self.created_at(request["id"]))
        return request

    def count(self, table: str, where: str = "true", params: tuple[Any, ...] = ()) -> int:
        return int(self.rows(f"SELECT count(*) FROM {table} WHERE {where}", params)[0][0])  # noqa: S608

    def nrows(self, request_id: str | uuid.UUID, where: str = "true") -> list[dict[str, Any]]:
        cols = (
            "id, channel, cascade_step, recipient_role, recipient_person_id, state, failure_reason, closed_reason, provider_ref,"
            " app_received_at, displayed_at, actioned_at, expired_at, action, attempt_no, token_id"
        )
        rows = self.rows(
            f"SELECT {cols} FROM notifications WHERE request_id = %s AND {where} ORDER BY created_at, id",
            (request_id,),
        )
        keys = [c.strip() for c in cols.split(",")]
        return [dict(zip(keys, r, strict=True)) for r in rows]


@contextlib.contextmanager
def notifications_world(db: DbHandle) -> Iterator[NW]:
    settings = make_settings(db)
    database = Database.from_settings(settings)
    app = create_app(settings, database=database, modules_package=SHIM_PACKAGE)
    app.state.notifications_config = CFG
    idh = IdentityHarness(db, app, database)
    idh.tune(ip_capacity=10_000, otp_request_capacity=500, otp_verify_capacity=500)
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    soc = idh.society(
        "Notify Heights", units=("A-101", "A-102", "A-103", "B-201", "B-202", "C-301")
    )
    secretary = idh.login(900, client=client)
    guard = idh.login(901, client=client)
    guard_sup = idh.login(902, client=client)
    idh.seed_grant(soc.id, secretary.id, "secretary")
    idh.seed_grant(soc.id, guard.id, "guard")
    idh.seed_grant(soc.id, guard_sup.id, "guard_sup")
    idh.elevate_session(secretary)
    idh.elevate_session(guard_sup)
    world = NW(idh, soc, client, secretary, guard, guard_sup, _n=100, database=database, app=app)
    world.setup_gate()
    try:
        yield world
    finally:
        database.dispose()


@pytest.fixture
def nw(db: DbHandle) -> Iterator[NW]:
    with notifications_world(db) as world:
        yield world


def secs(n: float) -> dt.timedelta:
    return dt.timedelta(seconds=n)
