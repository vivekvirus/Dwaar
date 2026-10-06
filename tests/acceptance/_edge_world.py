"""Shared builders for the edge acceptance scenarios AT-05..AT-08 (synthetic, simulation only).

Everything runs against the REAL edge gateway code with injected time and an in-process FakeCloud that implements the
edge<->cloud contract. FakeCloud is NOT the real API; wiring the real API is a later integration step.
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from dwaar_edge.clock import ClockModel
from dwaar_edge.decision import GuestPass
from dwaar_edge.gateway import Gateway
from dwaar_edge.qr import parse_qr
from dwaar_edge.restricted import StandaloneTerminal
from dwaar_edge.sync import SyncClient, SyncConfig
from tests.integration.edge_gateway.fakecloud import FakeCloud
from tests.integration.edge_gateway.support import ManualTime, World

DATASET = (
    "edge-synthetic-v1: invented society, two gates (A main, B service), guard terminals A/B, one supervisor terminal, "
    "invented opaque credential refs (no names, no phones); injected clock; in-process FakeCloud implementing the edge contract"
)
NONCE = "nonce-abcdefgh"


class EdgeScene:
    """A commissioned society edge with passes, a FakeCloud and helpers."""

    def __init__(self, tmp_path: Path, **gw_kw: Any) -> None:
        self.tmp = tmp_path
        self.w = World()
        self.t = ManualTime()
        self.gw_kw = gw_kw
        self.cloud = FakeCloud(self.w.society_id, self.t.wall)
        self.cloud.register_device(self.w.gateway_device, self.w.device_signer.public_key)
        self.gw: Gateway = self.w.gateway(tmp_path / "edge", self.t, **gw_kw)
        self.inv_a = uuid.uuid4()  # single-use, bound to gate A
        self.inv_any = uuid.uuid4()  # single-use, no gate binding
        self.inv_multi = uuid.uuid4()  # multi-use, no gate binding
        self.client = self.new_client()
        self.rng = random.Random(1)

    # ---- setup -----------------------------------------------------------------------------------
    def new_client(self, **cfg: Any) -> SyncClient:
        return SyncClient(
            self.gw,
            self.cloud.transport(),
            SyncConfig(**cfg),
            sleep=lambda s: None,
            rng=random.Random(5),
        )

    def publish(
        self,
        seq: int,
        *,
        extra_residents: list[dict[str, Any]] | None = None,
        revocations: list[dict[str, Any]] | None = None,
        rules: list[dict[str, Any]] | None = None,
        window_hours: float = 12,
        valid_for_hours: float = 96,
    ) -> None:
        w, t = self.w, self.t
        invs = [
            w.invitation(
                self.inv_a,
                gate=w.gate_a,
                start=t.wall_now - timedelta(minutes=5),
                end=t.wall_now + timedelta(hours=window_hours),
                nonce=NONCE,
            ),
            w.invitation(
                self.inv_any,
                gate=None,
                start=t.wall_now - timedelta(minutes=5),
                end=t.wall_now + timedelta(hours=window_hours),
                nonce=NONCE,
            ),
            w.invitation(
                self.inv_multi,
                gate=None,
                start=t.wall_now - timedelta(minutes=5),
                end=t.wall_now + timedelta(hours=window_hours),
                max_uses=4,
                nonce=NONCE,
            ),
        ]
        manifest = w.manifest(
            residents=[w.resident(), *(extra_residents or [])],
            invitations=invs,
            rules=rules or [],
            revocations=revocations or [],
        )
        self.cloud.publish_policy(
            w.snapshot(
                seq=seq,
                issued_at=t.wall_now,
                manifest=manifest,
                valid_for=timedelta(hours=valid_for_hours),
            )
        )

    def sync(self) -> Any:
        return self.client.sync_once()

    def restart(self, *, trusted: bool = False) -> None:
        """Process restart: new gateway object, new clock model (monotonic anchor is gone), same files on disk."""
        self.gw.stop()
        self.gw = self.w.gateway(self.tmp / "edge", self.t, trusted=trusted, **self.gw_kw)
        self.client = self.new_client()

    def actor(self, device: uuid.UUID, role: str = "guard") -> Any:
        return self.w.actor(self.gw, device, role)

    def terminal(self, gate: uuid.UUID, device: uuid.UUID) -> StandaloneTerminal:
        term = StandaloneTerminal(
            device_id=device,
            gate_id=gate,
            society_id=self.w.society_id,
            issuer_keys={self.w.issuer.key_id: self.w.issuer.public_key},
            clock=ClockModel(wall=self.t.wall, mono=self.t.mono),
        )
        term.clock.sync(
            self.t.wall_now, 50
        )  # trusted time received over the LAN from the gateway before it failed
        term.load_cache(self.gw.export_terminal_cache(gate))
        return term

    # ---- credentials -------------------------------------------------------------------------------
    def qr(self, inv: uuid.UUID, *, gate: uuid.UUID | None = None) -> str:
        t = self.t.wall_now
        return self.w.qr(
            inv, NONCE, nbf=t - timedelta(minutes=5), exp=t + timedelta(hours=12), gate=gate
        )

    def guest(self, inv: uuid.UUID) -> GuestPass:
        parsed = parse_qr(self.qr(inv), self.gw.config.pass_keys, self.w.society_id)
        assert parsed is not None
        return parsed[0]

    def evaluate(
        self,
        actor: Any,
        cred: dict[str, Any],
        *,
        gate: uuid.UUID | None = None,
        lane: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        gate = gate or self.w.gate_a
        lane = lane or (self.w.lane_a_in if gate == self.w.gate_a else self.w.lane_b_in)
        return self.gw.evaluate(actor, gate_id=gate, lane_id=lane, credential=cred)

    def close(self) -> None:
        self.gw.stop()


RES = {"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1}
