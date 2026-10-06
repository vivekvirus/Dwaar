"""Shared builders for the edge gateway tests: injectable time, a commissioned world, signed snapshots, QR text.

Everything here is SYNTHETIC (invented ids and keys). Time is injected so "72 hours" runs in milliseconds.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.crypto import KeyRing, generate_key
from dwaar_common.events import canonical_json
from dwaar_common.ids import uuid7
from dwaar_common.signing import Signer, b64url_encode, generate_private_key, sign_bytes
from dwaar_common.timeutil import format_iso_utc
from dwaar_edge.clock import ClockModel
from dwaar_edge.config import EdgeConfig
from dwaar_edge.gateway import Actor, Gateway

START = datetime(2026, 10, 5, 6, 0, 0, tzinfo=UTC)  # 11:30 IST


class ManualTime:
    """Wall and monotonic clocks the test drives."""

    def __init__(self, start: datetime = START) -> None:
        self.wall_now = start
        self.mono_now = 5_000.0

    def wall(self) -> datetime:
        return self.wall_now

    def mono(self) -> float:
        return self.mono_now

    def advance(self, seconds: float) -> None:
        self.wall_now += timedelta(seconds=seconds)
        self.mono_now += seconds

    def step_wall(self, seconds: float) -> None:
        """Wall clock jumps (monotonic does not): the AT-08 fault."""
        self.wall_now += timedelta(seconds=seconds)


class RealTime:
    """Same interface as ManualTime but the real clocks (used by subprocess crash tests)."""

    @property
    def wall_now(self) -> datetime:
        return datetime.now(UTC)

    def wall(self) -> datetime:
        return datetime.now(UTC)

    def mono(self) -> float:
        return time.monotonic()


@dataclass
class World:
    society_id: uuid.UUID = field(default_factory=uuid7)
    gateway_device: uuid.UUID = field(default_factory=uuid7)
    gate_a: uuid.UUID = field(default_factory=uuid7)
    gate_b: uuid.UUID = field(default_factory=uuid7)
    lane_a_in: uuid.UUID = field(default_factory=uuid7)
    lane_a_out: uuid.UUID = field(default_factory=uuid7)
    lane_b_in: uuid.UUID = field(default_factory=uuid7)
    term_a: uuid.UUID = field(default_factory=uuid7)
    term_b: uuid.UUID = field(default_factory=uuid7)
    term_sup: uuid.UUID = field(default_factory=uuid7)
    unit_1: uuid.UUID = field(default_factory=uuid7)
    issuer: Signer = field(default_factory=lambda: Signer.generate("issuer-1"))
    other_issuer: Signer = field(default_factory=lambda: Signer.generate("issuer-2"))
    pass_signer: Signer = field(default_factory=lambda: Signer.generate("pass-1"))
    device_signer: Signer = field(default_factory=lambda: Signer.generate("gw-key-1"))
    token_key: Ed25519PrivateKey = field(default_factory=generate_private_key)
    keyring: KeyRing = field(default_factory=lambda: KeyRing({"k1": generate_key()}, "k1"))

    # ---- (de)serialisation for subprocess tests (TEST KEYS ONLY) -----------------------------------------
    def to_json(self) -> dict[str, Any]:
        from dwaar_common.crypto import key_to_b64
        from dwaar_common.signing import private_key_to_b64

        ids = (
            "society_id",
            "gateway_device",
            "gate_a",
            "gate_b",
            "lane_a_in",
            "lane_a_out",
            "lane_b_in",
            "term_a",
            "term_b",
            "term_sup",
            "unit_1",
        )
        out: dict[str, Any] = {k: str(getattr(self, k)) for k in ids}
        out["issuer"] = [self.issuer.key_id, private_key_to_b64(self.issuer.private_key)]
        out["pass_signer"] = [
            self.pass_signer.key_id,
            private_key_to_b64(self.pass_signer.private_key),
        ]
        out["device_signer"] = [
            self.device_signer.key_id,
            private_key_to_b64(self.device_signer.private_key),
        ]
        out["token_key"] = private_key_to_b64(self.token_key)
        out["keyring"] = {k: key_to_b64(self.keyring.get(k)) for k in self.keyring.key_ids}
        out["active_key"] = self.keyring.active_key_id
        return out

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> World:
        from dwaar_common.crypto import key_from_b64
        from dwaar_common.signing import private_key_from_b64

        w = cls(
            **{
                k: uuid.UUID(data[k])
                for k in (
                    "society_id",
                    "gateway_device",
                    "gate_a",
                    "gate_b",
                    "lane_a_in",
                    "lane_a_out",
                    "lane_b_in",
                    "term_a",
                    "term_b",
                    "term_sup",
                    "unit_1",
                )
            }
        )
        w.issuer = Signer(data["issuer"][0], private_key_from_b64(data["issuer"][1]))
        w.pass_signer = Signer(data["pass_signer"][0], private_key_from_b64(data["pass_signer"][1]))
        w.device_signer = Signer(
            data["device_signer"][0], private_key_from_b64(data["device_signer"][1])
        )
        w.token_key = private_key_from_b64(data["token_key"])
        w.keyring = KeyRing(
            {k: key_from_b64(v) for k, v in data["keyring"].items()}, data["active_key"]
        )
        return w

    # ---- config / gateway -------------------------------------------------------------------------
    def config(self, data_dir: Path, **kw: Any) -> EdgeConfig:
        return EdgeConfig(
            society_id=self.society_id,
            device_id=self.gateway_device,
            data_dir=data_dir,
            device_key=self.device_signer.private_key,
            device_key_id=self.device_signer.key_id,
            issuer_keys={self.issuer.key_id: self.issuer.public_key},
            keyring=self.keyring,
            token_key=self.token_key,
            pass_keys={self.pass_signer.key_id: self.pass_signer.public_key},
            **kw,
        )

    def gateway(self, data_dir: Path, t: ManualTime, *, trusted: bool = True, **kw: Any) -> Gateway:
        gw = Gateway(
            self.config(data_dir, **kw), clock=ClockModel(wall=t.wall, mono=t.mono)
        ).start()
        if trusted:
            gw.note_trusted_time(t.wall_now, 50)
        return gw

    def actor(self, gw: Gateway, device: uuid.UUID, role: str = "guard") -> Actor:
        token = gw.issue_terminal_token(device, role)  # type: ignore[arg-type]
        actor = gw.authenticate(token)
        assert actor is not None
        return actor

    # ---- policy ----------------------------------------------------------------------------------------
    def timing(self, **kw: Any) -> dict[str, Any]:
        base = {
            "approval_expiry_s": 90,
            "cascade_steps": [],
            "guest_offline_max_s": 7200,
            "resident_offline_validity_s": 72 * 3600,
            "clock_uncertainty_limit_ms": 60_000,
            "policy_age_limit_s": 72 * 3600,
        }
        base.update(kw)
        return base

    def manifest(
        self,
        *,
        residents: Iterable[dict[str, Any]] = (),
        invitations: Iterable[dict[str, Any]] = (),
        rules: Iterable[dict[str, Any]] = (),
        revocations: Iterable[dict[str, Any]] = (),
        timing: dict[str, Any] | None = None,
        devices: Iterable[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "gates": [
                {"id": str(self.gate_a), "kind": "main"},
                {"id": str(self.gate_b), "kind": "service"},
            ],
            "lanes": [
                {"id": str(self.lane_a_in), "gate_id": str(self.gate_a), "direction": "in"},
                {"id": str(self.lane_a_out), "gate_id": str(self.gate_a), "direction": "out"},
                {"id": str(self.lane_b_in), "gate_id": str(self.gate_b), "direction": "in"},
            ],
            "devices": list(devices)
            if devices is not None
            else [
                {
                    "id": str(self.term_a),
                    "kind": "guard_terminal",
                    "gate_id": str(self.gate_a),
                    "status": "active",
                },
                {
                    "id": str(self.term_b),
                    "kind": "guard_terminal",
                    "gate_id": str(self.gate_b),
                    "status": "active",
                },
            ],
            "residents": list(residents),
            "invitations": list(invitations),
            "standing_rules": list(rules),
            "timing": timing or self.timing(),
            "revocations": list(revocations),
        }

    def snapshot(
        self,
        *,
        seq: int,
        issued_at: datetime,
        manifest: dict[str, Any],
        valid_for: timedelta = timedelta(hours=96),
        signer: Signer | None = None,
        society_id: uuid.UUID | None = None,
        schema_version: int = 1,
    ) -> dict[str, Any]:
        s = signer or self.issuer
        body = {
            "schema_version": schema_version,
            "society_id": str(society_id or self.society_id),
            "seq": seq,
            "issued_at": format_iso_utc(issued_at),
            "valid_until": format_iso_utc(issued_at + valid_for),
            "issuer_key_id": s.key_id,
            "manifest": manifest,
        }
        return {**body, "signature": sign_bytes(s.private_key, canonical_json(body))}

    # ---- fixtures for credentials -----------------------------------------------------------------------------
    def resident(self, ref: str = "cred-r1", **kw: Any) -> dict[str, Any]:
        base = {
            "credential_ref": ref,
            "person_ref": f"p-{ref}",
            "unit_id": str(self.unit_1),
            "status": "active",
            "valid_from": None,
            "valid_until": None,
            "revocation_version": 1,
        }
        base.update(kw)
        return base

    def invitation(
        self,
        inv_id: uuid.UUID,
        *,
        gate: uuid.UUID | None,
        start: datetime,
        end: datetime,
        max_uses: int = 1,
        uses_remaining: int | None = None,
        nonce: str = "nonce-abcdefgh",
        **kw: Any,
    ) -> dict[str, Any]:
        base = {
            "id": str(inv_id),
            "gate_id": None if gate is None else str(gate),
            "window_start": format_iso_utc(start),
            "window_end": format_iso_utc(end),
            "max_uses": max_uses,
            "uses_remaining": max_uses if uses_remaining is None else uses_remaining,
            "revoked_version": None,
            "nonce": nonce,
            "kind": "guest",
            "visitor_alias": None,
        }
        base.update(kw)
        return base

    def qr(
        self,
        inv_id: uuid.UUID,
        nonce: str,
        *,
        nbf: datetime,
        exp: datetime,
        gate: uuid.UUID | None = None,
        signer: Signer | None = None,
    ) -> str:
        s = signer or self.pass_signer
        payload: dict[str, Any] = {
            "v": 1,
            "typ": "dwaar.pass",
            "iid": str(inv_id),
            "sid": str(self.society_id),
            "n": nonce,
            "nbf": int(nbf.timestamp()),
            "exp": int(exp.timestamp()),
            "kid": s.key_id,
        }
        if gate is not None:
            payload["g"] = str(gate)
        body = canonical_json(payload)
        return f"{b64url_encode(body)}.{sign_bytes(s.private_key, body)}"


def standard_world_with_policy(
    tmp_path: Path, t: ManualTime | None = None, **gw_kw: Any
) -> tuple[World, ManualTime, Gateway]:
    t = t or ManualTime()
    w = World()
    gw = w.gateway(tmp_path / "edge", t, **gw_kw)
    gw.apply_policy(
        w.snapshot(seq=1, issued_at=t.wall_now, manifest=w.manifest(residents=[w.resident()]))
    )
    gw.confirm_policy_current()
    return w, t, gw


class LiveServer:
    """The local API on a real loopback socket (uvicorn in a thread). Loopback only: says nothing about a real LAN."""

    def __init__(self, app: Any) -> None:
        import threading

        import uvicorn

        self.config = uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="warning", access_log=False, lifespan="off"
        )
        self.server = uvicorn.Server(self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.port = 0

    def __enter__(self) -> LiveServer:
        self.thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.server.started and self.server.servers:
                self.port = self.server.servers[0].sockets[0].getsockname()[1]
                return self
            time.sleep(0.01)
        raise RuntimeError("uvicorn did not start")

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[idx]
