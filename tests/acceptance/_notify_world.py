"""Helpers for the notification scenarios (AT-11, AT-40) on the seeded acceptance world: the A-203 household, labelled provider simulators and a worker tick
with an injectable clock. Everything a person does goes through the API; the only things moved outside it are TIME (the database clock decides expiry) and
the scripted behaviour of the SIMULATED phones and providers (``simulation = true``)."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any

from dwaar_api.modules.notifications import runner
from dwaar_api.modules.notifications.config import NotificationsConfig
from dwaar_api.modules.notifications.devices import token_ref_for
from dwaar_api.modules.notifications.providers import ProviderSet, SimulatedProviders
from dwaar_api.seed.steps.s590_notifications import _token
from tests.acceptance._visits_world import VisitIds, raise_request, visit_ids
from tests.acceptance._world import Session, World

CFG = NotificationsConfig(providers_mode="simulator")


@dataclass
class Scene:
    world: World
    ids: VisitIds
    unit: uuid.UUID
    guard: Session
    ganesh: Session
    rekha: Session
    secretary: Session
    sup: Session
    sims: SimulatedProviders = field(default_factory=SimulatedProviders)

    @property
    def society(self) -> uuid.UUID:
        return self.ids.society

    def s(self, tail: str) -> str:
        return f"/v1/societies/{self.society}/{tail}"

    def phone(self, key: str) -> Any:
        """The simulated phone behind a seeded device (``ganesh`` or ``rekha``)."""
        return self.sims.push.device(token_ref_for(_token(key)))

    def tick(self, at: dt.datetime) -> None:
        runner.run_tick(
            self.world.database,
            ProviderSet.from_simulators(self.sims),
            societies=[self.society],
            clock=lambda: at,
            cfg=CFG,
        )

    def raise_request(self, alias: str) -> dict[str, Any]:
        return raise_request(self.world, self.guard, self.ids, self.unit, alias)

    def created_at(self, request_id: str) -> dt.datetime:
        row: dt.datetime = self.world.admin_rows(
            "SELECT created_at FROM approval_requests WHERE id = %s", (request_id,)
        )[0][0]
        return row

    def age(self, request_id: str, seconds: float) -> None:
        """Make the request ``seconds`` older (creation, expiry, cascade): the database clock is the authority for expiry."""
        with self.world.db.admin_conn() as conn:
            conn.execute(
                "UPDATE approval_requests SET created_at = created_at - make_interval(secs => %s),"
                " expires_at = expires_at - make_interval(secs => %s) WHERE id = %s",
                (seconds, seconds, request_id),
            )
            conn.execute(
                "UPDATE notification_cascades SET started_at = started_at - make_interval(secs => %s),"
                " expires_at = expires_at - make_interval(secs => %s) WHERE request_id = %s",
                (seconds, seconds, request_id),
            )

    def rows(self, request_id: str) -> list[dict[str, Any]]:
        cols = "channel, cascade_step, recipient_role, state, failure_reason, closed_reason, app_received_at, provider_ref, created_at"
        found = self.world.admin_rows(
            f"SELECT {cols} FROM notifications WHERE request_id = %s ORDER BY created_at, id",
            (request_id,),
        )  # noqa: S608
        keys = [c.strip() for c in cols.split(",")]
        return [dict(zip(keys, r, strict=True)) for r in found]

    def board(self, who: Session, request_id: str) -> dict[str, Any]:
        r = self.world.call(
            who,
            "GET",
            self.s(f"approval-requests/{request_id}/notification-status"),
            params={"gate_id": str(self.ids.gate)},
        )
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        return body


def scene(world: World) -> Scene:
    ids = visit_ids(world, "mh")
    unit = world.society_ref("mh").unit("A", "203")
    return Scene(
        world, ids, unit, world.login("mh.guard1"), world.login("ganesh"), world.login("rekha"), world.login("mh.secretary"),
        world.login("mh.guard_sup"),
    )  # fmt: skip
