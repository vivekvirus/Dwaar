"""One edge scenario world, two clouds: the in-process ``FakeCloud`` and the REAL API (AT-05 .. AT-08 end to end).

``Scene`` is the narrow interface the e2e acceptance scenarios are written against. ``FakeScene`` adapts the existing
``EdgeScene`` (FakeCloud implements the CONTRACT in-process); ``RealScene`` adapts ``Site`` (the real FastAPI application,
real PostgreSQL, real HTTP on a loopback socket, a gateway commissioned through the real enrolment routes).

Both run on a VIRTUAL clock shared by gateway and cloud (a labelled simulation: 72 hours pass in milliseconds). Neither is
field evidence. Differences between the two clouds are listed in docs/adr/0019 (conformance).
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dwaar_edge.clock import ClockModel
from dwaar_edge.gateway import Actor, Gateway
from dwaar_edge.restricted import StandaloneTerminal
from tests.acceptance._edge_world import EdgeScene
from tests.integration.edge._support import EdgeWorld
from tests.integration.edge_e2e._cloud import Site
from tests.integration.edge_gateway.support import ManualTime

MILK_CATEGORY = "milk_vendor"


@dataclass(frozen=True)
class PassRef:
    id: uuid.UUID
    qr: str  # QR text valid for the pass as issued
    max_uses: int


class Scene:
    """What the scenarios need. Subclasses fill it in."""

    kind: str = "abstract"
    t: ManualTime
    gate_a: uuid.UUID
    gate_b: uuid.UUID
    lane_a_in: uuid.UUID
    lane_a_out: uuid.UUID
    lane_b_in: uuid.UUID
    term_a: uuid.UUID
    term_b: uuid.UUID
    term_sup: uuid.UUID
    unit: uuid.UUID
    pass_a: PassRef  # single use, bound to gate A
    pass_any: PassRef  # single use, any gate
    pass_multi: PassRef  # four uses, any gate

    @property
    def gw(self) -> Gateway:
        raise NotImplementedError

    # ---- cloud-side actions ---------------------------------------------------------------------------------
    def sync(self) -> Any:
        raise NotImplementedError

    def set_cloud_online(self, online: bool) -> None:
        raise NotImplementedError

    def refresh_policy(self, *, revoke: PassRef | None = None, valid_for_hours: float = 96) -> None:
        """The cloud issues a NEWER signed snapshot (optionally revoking a pass first)."""
        raise NotImplementedError

    def restart(self, *, trusted: bool = False) -> None:
        raise NotImplementedError

    # ---- cloud-side observations ------------------------------------------------------------------------------
    def cloud_seqs(self) -> list[int]:
        raise NotImplementedError

    def cloud_event_ids(self) -> list[str]:
        raise NotImplementedError

    def cloud_statuses(self) -> set[str]:
        raise NotImplementedError

    def cloud_occurred(self) -> list[str]:
        raise NotImplementedError

    def cloud_entry_payloads(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def cloud_anomalies(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    # ---- shared helpers ---------------------------------------------------------------------------------------
    def actor(self, device: uuid.UUID | None = None, role: str = "guard") -> Actor:
        device = device or self.term_a
        actor = self.gw.authenticate(self.gw.issue_terminal_token(device, role))  # type: ignore[arg-type]
        assert actor is not None
        return actor

    def resident(self) -> dict[str, Any]:
        raise NotImplementedError

    def qr(self, p: PassRef) -> dict[str, Any]:
        return {"kind": "qr", "text": p.qr}

    def guest(self, p: PassRef) -> dict[str, Any]:
        pol = self.gw.policy
        assert pol is not None
        return {
            "kind": "guest_pass",
            "invitation_id": str(p.id),
            "nonce": pol.invitations[p.id].nonce,
        }

    def standing(self) -> dict[str, Any]:
        return {
            "kind": "standing",
            "unit_id": str(self.unit),
            "category": MILK_CATEGORY,
            "visit_kind": "vendor",
        }

    def evaluate(
        self,
        actor: Actor,
        cred: dict[str, Any],
        *,
        gate: uuid.UUID | None = None,
        lane: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        gate = gate or self.gate_a
        lane = lane or (self.lane_a_in if gate == self.gate_a else self.lane_b_in)
        return self.gw.evaluate(actor, gate_id=gate, lane_id=lane, credential=cred)

    def terminal(self, gate: uuid.UUID, device: uuid.UUID) -> StandaloneTerminal:
        term = StandaloneTerminal(
            device_id=device, gate_id=gate, society_id=self.gw.config.society_id,
            issuer_keys=dict(self.gw.config.issuer_keys), clock=ClockModel(wall=self.t.wall, mono=self.t.mono),
        )  # fmt: skip
        term.clock.sync(self.t.wall_now, 50)
        term.load_cache(self.gw.export_terminal_cache(gate))
        return term

    def close(self) -> None:
        raise NotImplementedError


# ------------------------------------------------------------------------------------------ FakeCloud
class FakeScene(Scene):
    kind = "fake"

    def __init__(self, tmp_path: Path) -> None:
        self.e = EdgeScene(tmp_path)
        w = self.e.w
        self.t = self.e.t
        self.gate_a, self.gate_b = w.gate_a, w.gate_b
        self.lane_a_in, self.lane_a_out, self.lane_b_in = w.lane_a_in, w.lane_a_out, w.lane_b_in
        self.term_a, self.term_b, self.term_sup, self.unit = (
            w.term_a,
            w.term_b,
            w.term_sup,
            w.unit_1,
        )
        self.pass_a = PassRef(self.e.inv_a, self.e.qr(self.e.inv_a, gate=w.gate_a), 1)
        self.pass_any = PassRef(self.e.inv_any, self.e.qr(self.e.inv_any), 1)
        self.pass_multi = PassRef(self.e.inv_multi, self.e.qr(self.e.inv_multi), 4)
        self._rules: list[dict[str, Any]] = []
        self._seq = 0
        self._revoked: list[dict[str, Any]] = []

    @property
    def gw(self) -> Gateway:
        return self.e.gw

    def add_milk_rule(self) -> None:
        self._rules = [
            {
                "unit_id": str(self.unit), "rule_kind": "allow_window",
                "params": {"visit_kind": "vendor", "category": MILK_CATEGORY, "action": "allow", "days": [1, 2, 3, 4, 5, 6, 7],
                           "start_local": "00:00", "end_local": "23:59", "tz": "Asia/Kolkata"},
                "effective_from": None, "effective_to": None,
            }
        ]  # fmt: skip

    def publish(self, *, revoke: PassRef | None = None, valid_for_hours: float = 96) -> None:
        self._seq += 1
        if revoke is not None:
            self._revoked.append({"ref": str(revoke.id), "version": len(self._revoked) + 1})
        self.e.publish(
            self._seq, rules=self._rules, revocations=self._revoked, valid_for_hours=valid_for_hours
        )

    def refresh_policy(self, *, revoke: PassRef | None = None, valid_for_hours: float = 96) -> None:
        self.publish(revoke=revoke, valid_for_hours=valid_for_hours)

    def sync(self) -> Any:
        if self._seq == 0:
            self.publish()  # the first snapshot exists before the gateway first asks (the real cloud publishes on first poll)
        return self.e.sync()

    def set_cloud_online(self, online: bool) -> None:
        self.e.cloud.online = online

    def restart(self, *, trusted: bool = False) -> None:
        self.e.restart(trusted=trusted)

    def resident(self) -> dict[str, Any]:
        return {"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1}

    def cloud_seqs(self) -> list[int]:
        return self.e.cloud.accepted_seqs(self.e.w.gateway_device)

    def cloud_event_ids(self) -> list[str]:
        by_seq = {s: e for (d, s), e in self.e.cloud.by_device_seq.items()}
        return [by_seq[s] for s in sorted(by_seq)]

    def cloud_statuses(self) -> set[str]:
        return {o["status"] for o in self.e.cloud.outcome_log}

    def cloud_occurred(self) -> list[str]:
        return [self.e.cloud.events[i]["occurred_at"] for i in self.cloud_event_ids()]

    def cloud_entry_payloads(self) -> list[dict[str, Any]]:
        return [e["payload"] for e in self.e.cloud.events.values() if e["type"] == "EntryObserved"]

    def cloud_anomalies(self) -> list[dict[str, Any]]:
        return [
            e["payload"]
            for e in self.e.cloud.events.values()
            if e["type"] == "ClockAnomalyDetected"
        ]

    def close(self) -> None:
        self.e.close()


# ------------------------------------------------------------------------------------------ the real API
class RealScene(Scene):
    kind = "real"

    def __init__(self, ew: EdgeWorld, site: Site) -> None:
        self.ew, self.s = ew, site
        self.t = site.t  # type: ignore[assignment]
        self.gate_a, self.gate_b = site.gate_a, site.gate_b
        self.lane_a_in, self.lane_a_out, self.lane_b_in = (
            site.lane_a_in,
            site.lane_a_out,
            site.lane_b_in,
        )
        self.term_a, self.term_b, self.term_sup = site.term_a, site.term_b, site.term_sup
        self.unit = ew.soc.units["A-101"]
        self.household = ew.household("A-101", tenant=False, family=False)
        self.pass_a = self._make(1, gate=site.gate_a)
        self.pass_any = self._make(1)
        self.pass_multi = self._make(4)

    def _make(self, uses: int, gate: uuid.UUID | None = None) -> PassRef:
        now = self.s.now()
        view = self.s.make_pass(  # a 12 hour window, like the FakeCloud scene
            self.household.owner, self.unit, windows=[(now - dt.timedelta(minutes=5), now + dt.timedelta(hours=12))],
            max_uses=uses, gate=gate,
        )  # fmt: skip
        return PassRef(uuid.UUID(view["id"]), view["qr"], uses)

    @property
    def gw(self) -> Gateway:
        return self.s.gw

    def add_milk_rule(self) -> None:
        r = self.ew.call(
            self.household.owner, "POST", self.ew.s("standing-rules"),
            json={"unit_id": str(self.unit), "rule_kind": "allow_window", "visit_kind": "vendor", "category": MILK_CATEGORY,
                  "start_local": "00:00", "end_local": "23:59"},
        )  # fmt: skip
        assert r.status_code == 201, r.text

    def refresh_policy(self, *, revoke: PassRef | None = None, valid_for_hours: float = 96) -> None:
        if revoke is not None:
            self.s.revoke_pass(self.household.owner, revoke.id)
        # the cloud publishes on change (and on poll); force a newer snapshot even when only the clock moved
        r = self.ew.call(
            self.ew.secretary, "POST", self.ew.s("edge/policy/publish"), params={"force": True}
        )
        assert r.status_code in (200, 201), r.text

    def sync(self) -> Any:
        return self.s.sync()

    def set_cloud_online(self, online: bool) -> None:
        self.s.wan.online = online

    def restart(self, *, trusted: bool = False) -> None:
        self.s.restart(trusted=trusted)

    def resident(self) -> dict[str, Any]:
        return self.s.resident_cred(self.unit)

    def cloud_seqs(self) -> list[int]:
        return [int(r[1]) for r in self.s.cloud_events()]

    def cloud_event_ids(self) -> list[str]:
        return [str(r[0]) for r in self.s.cloud_events()]

    def cloud_statuses(self) -> set[str]:
        return {str(r[3]) for r in self.s.cloud_events()}

    def cloud_occurred(self) -> list[str]:
        rows = self.s.edge_rows(
            "SELECT occurred_at FROM edge_events WHERE device_id = %s ORDER BY seq",
            (self.s.device.device_id,),
        )
        return [r[0].isoformat() for r in rows]

    def cloud_entry_payloads(self) -> list[dict[str, Any]]:
        rows = self.s.edge_rows(
            "SELECT payload FROM access_events WHERE device_id = %s AND event_type = 'EntryObserved' ORDER BY seq",
            (self.s.device.device_id,),
        )
        return [dict(r[0]) for r in rows]

    def cloud_anomalies(self) -> list[dict[str, Any]]:
        rows = self.s.edge_rows(
            "SELECT event_id FROM edge_events WHERE device_id = %s AND event_type = 'ClockAnomalyDetected'",
            (self.s.device.device_id,),
        )
        return [{"event_id": str(r[0])} for r in rows]

    def close(self) -> None:
        pass  # the Site context manager owns the teardown


__all__ = ["MILK_CATEGORY", "FakeScene", "PassRef", "RealScene", "Scene"]
