"""Real edge <-> cloud wiring for the slice 3 integration tests (simulation: loopback, one machine, ephemeral Postgres).

NOTHING here is a fake of the cloud: the cloud is the real FastAPI application (identity + visits + edge modules, real migrations, real
RLS, real device signature authentication) served by uvicorn on a real loopback socket; the gateway is the real :class:`Gateway` with its
real :class:`SyncClient` speaking real HTTP through ``HttpxTransport``. The pieces that are simulated and labelled as such:

* **time**: ``virtual=True`` makes the gateway's wall clock a :class:`ManualTime` AND points the cloud's ``utc_now`` (edge and visits modules)
  and its HTTP ``Date`` header at the same virtual clock, so "72 hours" pass in milliseconds on both sides. ``virtual=False`` uses the
  machine clock everywhere (the real ``Date`` header of uvicorn) and is how clock-skew tests exercise the 401-with-Date repair.
* **the WAN**: :class:`WanSwitch` wraps the real HTTP transport and refuses connections while "down". The server keeps running.
* **commissioning**: a person enrols the gateway through the real routes (guard requests, supervisor approves, maker != checker); the
  gateway pins the issuer / pass keys through ``dwaar_edge.provision`` (signed ``GET /v1/edge/keys``), never from a snapshot.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import pytest

from dwaar_common.crypto import KeyRing, generate_key
from dwaar_common.signing import generate_private_key
from dwaar_edge.clock import ClockModel
from dwaar_edge.config import EdgeConfig
from dwaar_edge.gateway import Actor, Gateway
from dwaar_edge.provision import TrustAnchors, fetch_trust_anchors
from dwaar_edge.sync import (
    HttpxTransport,
    SyncClient,
    SyncConfig,
    TransportError,
    TransportResponse,
)
from tests.integration.edge._support import EdgeClient, EdgeWorld
from tests.integration.edge_gateway.support import ManualTime


class VirtualDate:
    """ASGI wrapper: the ``Date`` response header says what the (virtual) cloud clock says."""

    def __init__(self, app: Any, now: Callable[[], datetime]) -> None:
        self.app, self.now = app, now

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_date(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message["headers"] if k.lower() != b"date"]
                headers.append((b"date", format_datetime(self.now(), usegmt=True).encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_date)


class LiveApi:
    """The real API app on a real loopback socket (uvicorn in a thread)."""

    def __init__(self, app: Any, *, now: Callable[[], datetime] | None = None) -> None:
        import uvicorn

        served = VirtualDate(app, now) if now is not None else app
        self.config = uvicorn.Config(
            served,
            host="127.0.0.1",
            port=0,
            log_level="warning",
            access_log=False,
            lifespan="off",
            date_header=now is None,
        )
        self.server = uvicorn.Server(self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.port = 0

    def __enter__(self) -> LiveApi:
        self.thread.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.server.started and self.server.servers:
                self.port = self.server.servers[0].sockets[0].getsockname()[1]
                return self
            time.sleep(0.01)
        raise RuntimeError("uvicorn did not start")

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=20)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class WanSwitch:
    """Real HTTP underneath; ``online=False`` makes every request fail like a dead uplink (no response at all)."""

    def __init__(self, inner: HttpxTransport) -> None:
        self.inner = inner
        self.online = True
        self.log: list[tuple[str, str, int]] = []  # method, target, status
        self.lose_response_once = False  # process on the server, then pretend nothing came back

    def request(
        self, method: str, path_with_query: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        if not self.online:
            raise TransportError("WAN down (simulated)")
        resp = self.inner.request(method, path_with_query, headers, body)
        self.log.append((method, path_with_query, resp.status))
        if self.lose_response_once and method == "POST":
            self.lose_response_once = False
            raise TransportError("response lost (simulated)")
        return resp


def _patch_cloud_clock(monkeypatch: pytest.MonkeyPatch, now: Callable[[], datetime]) -> None:
    """Point every ``utc_now`` of the edge and visits modules at the virtual clock (identity/core keep the real clock: tokens expire in real time)."""
    for name, module in list(sys.modules.items()):
        if name.startswith(("dwaar_api.modules.edge", "dwaar_api.modules.visits")) and hasattr(
            module, "utc_now"
        ):
            monkeypatch.setattr(module, "utc_now", now)


@dataclass
class Site:
    """One commissioned gateway against the real cloud, plus the cloud-side people and objects of its society."""

    ew: EdgeWorld
    live: LiveApi
    t: ManualTime | None
    true_clock: Callable[[], datetime] | None
    device: EdgeClient  # the gateway as the cloud knows it (id + private key)
    gw: Gateway
    wan: WanSwitch
    anchors: TrustAnchors
    tmp: Path
    gate_a: uuid.UUID
    gate_b: uuid.UUID
    lane_a_in: uuid.UUID
    lane_a_out: uuid.UUID
    lane_b_in: uuid.UUID
    term_a: uuid.UUID
    term_b: uuid.UUID
    term_sup: uuid.UUID
    keyring: KeyRing
    token_key: Any
    sync_cfg: dict[str, Any] = field(default_factory=dict)
    skew: timedelta = timedelta(
        0
    )  # real-clock sites only: the gateway wall clock is this far from the cloud's
    client: SyncClient = field(init=False)

    def __post_init__(self) -> None:
        self.client = self.new_client()

    # ------------------------------------------------------------------------------------------ gateway lifecycle
    def new_client(self) -> SyncClient:
        import random

        return SyncClient(
            self.gw,
            self.wan,
            SyncConfig(**self.sync_cfg),
            sleep=lambda s: None,
            rng=random.Random(5),
        )

    def config(self) -> EdgeConfig:
        return EdgeConfig(
            society_id=self.ew.soc.id,
            device_id=self.device.device_id,
            data_dir=self.tmp / "edge",
            device_key=self.device.key,
            device_key_id="gw-key-1",
            issuer_keys=self.anchors.issuer_keys,
            keyring=self.keyring,
            token_key=self.token_key,
            pass_keys=self.anchors.pass_keys,
        )

    def restart(self, *, trusted: bool = False) -> None:
        """Process restart: same files, new gateway object and clock model (the monotonic anchor is gone)."""
        self.gw.stop()
        self.gw = self._open(trusted=trusted)
        self.client = self.new_client()

    def _open(self, *, trusted: bool) -> Gateway:
        if self.t is not None:
            clock = ClockModel(wall=self.t.wall, mono=self.t.mono)
        elif self.skew:
            skew = self.skew
            clock = ClockModel(wall=lambda: datetime.now(UTC) + skew)
        else:
            clock = ClockModel()
        gw = Gateway(self.config(), clock=clock).start()
        if trusted and self.t is not None:
            gw.note_trusted_time(self.now(), 50)
        return gw

    def close(self) -> None:
        self.gw.stop()

    # ------------------------------------------------------------------------------------------ helpers
    def now(self) -> datetime:
        """TRUE time: what the cloud's clock says. On a virtual site it follows the monotonic clock, so a wall-clock step of the gateway
        (AT-08) does not move it; on a real-clock site it is the machine clock."""
        return self.true_clock() if self.true_clock is not None else datetime.now(UTC)

    def advance(self, seconds: float) -> None:
        assert self.t is not None, "real-clock site"
        self.t.advance(seconds)

    def sync(self) -> Any:
        return self.client.sync_once()

    def actor(self, device: uuid.UUID | None = None, role: str = "guard") -> Actor:
        device = device or self.term_a
        token = self.gw.issue_terminal_token(device, role)  # type: ignore[arg-type]
        actor = self.gw.authenticate(token)
        assert actor is not None
        return actor

    def resident_cred(self, unit: uuid.UUID, index: int = 0) -> dict[str, Any]:
        """The credential a resident presents (the opaque reference the gateway holds for a member of ``unit``)."""
        pol = self.gw.policy
        assert pol is not None
        refs = sorted(r.credential_ref for r in pol.residents.values() if r.unit_id == unit)
        res = pol.residents[refs[index]]
        return {
            "kind": "resident",
            "credential_ref": res.credential_ref,
            "revocation_version": res.revocation_version,
        }

    def make_pass(
        self,
        owner: Any,
        unit: uuid.UUID,
        *,
        hours: float = 3,
        windows: list[tuple[datetime, datetime]] | None = None,
        max_uses: int = 1,
        gate: uuid.UUID | None = None,
        alias: str = "Aunt Sulabha",
        **extra: Any,
    ) -> dict[str, Any]:
        """A guest pass through the real invitations API (the host creates it); returns the API view incl. ``qr``."""
        start = self.now() - timedelta(minutes=5)
        spans = windows or [(start, start + timedelta(hours=hours))]
        body: dict[str, Any] = {
            "unit_id": str(unit), "purpose": "Dinner", "visitor_alias": alias, "people_count": 2,
            "windows": [{"start": a.isoformat(), "end": b.isoformat()} for a, b in spans], "max_uses": max_uses,
        }  # fmt: skip
        if gate is not None:
            body["gate_id"] = str(gate)
        body.update(extra)
        r = self.ew.call(owner, "POST", self.ew.s("invitations"), json=body)
        assert r.status_code == 201, r.text
        view: dict[str, Any] = r.json()
        return view

    def revoke_pass(self, owner: Any, invitation_id: uuid.UUID | str) -> int:
        """The host revokes a pass through the real API. PostgreSQL stamps ``revoked_at`` with the REAL clock; on a virtual site the harness
        then moves that stamp to the virtual true time (a test oracle, labelled), so the simulated timeline stays consistent."""
        r = self.ew.call(owner, "DELETE", f"/v1/invitations/{invitation_id}")
        assert r.status_code == 200, r.text
        if self.true_clock is not None:
            self.ew.sql(
                "UPDATE invitations SET revoked_at = %s WHERE id = %s",
                (self.true_clock(), invitation_id),
            )
        return int(r.json()["revoked_version"])

    def edge_rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        return self.ew.rows(sql, params)

    def cloud_events(self, kind: str | None = None) -> list[tuple[Any, ...]]:
        """(event_id, seq, event_type, status, reason) of the cloud ledger for this gateway, in sequence order."""
        return self.edge_rows(
            "SELECT event_id, seq, event_type, status, reason FROM edge_events WHERE device_id = %s"
            " AND (%s::text IS NULL OR event_type = %s) ORDER BY seq",
            (self.device.device_id, kind, kind),
        )

    def access_events(self) -> list[tuple[Any, ...]]:
        return self.edge_rows(
            "SELECT event_id, seq, event_type, decision_source, credential_kind, visit_id FROM access_events"
            " WHERE device_id = %s ORDER BY seq",
            (self.device.device_id,),
        )


def _enrol_terminals(
    ew: EdgeWorld, gate_a: uuid.UUID, gate_b: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    a = ew.edge_device(kind="terminal", gate=gate_a, name="Terminal A").device_id
    b = ew.edge_device(kind="terminal", gate=gate_b, name="Terminal B").device_id
    sup = ew.edge_device(kind="terminal", bind_gate=False, name="Supervisor terminal").device_id
    return a, b, sup


def _lane(ew: EdgeWorld, gate: uuid.UUID, label: str, direction: str) -> uuid.UUID:
    r = ew.call(
        ew.secretary,
        "POST",
        ew.s(f"gates/{gate}/lanes"),
        json={"label": label, "direction": direction},
    )
    assert r.status_code == 201, r.text
    return uuid.UUID(r.json()["id"])


@contextmanager
def commissioned_site(
    ew: EdgeWorld,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    virtual: bool = True,
    start_offset: timedelta = timedelta(0),
    sync_cfg: dict[str, Any] | None = None,
    gateway_gate_bound: bool = False,
    skew: timedelta = timedelta(0),
) -> Iterator[Site]:
    """Commission a gateway for ``ew``'s society against a live loopback API. See the module docstring for what is simulated."""
    t: ManualTime | None = None
    true_clock: Callable[[], datetime] | None = None
    if virtual:
        t = ManualTime(datetime.now(UTC).replace(microsecond=0) + start_offset)
        wall0, mono0 = t.wall_now, t.mono()
        clock = t

        def true_clock() -> (
            datetime
        ):  # the cloud's time: start + monotonic elapsed (never the gateway's stepped wall clock)
            return wall0 + timedelta(seconds=clock.mono() - mono0)

        _patch_cloud_clock(monkeypatch, true_clock)
    gate_a = ew.gate_id
    assert gate_a is not None
    tag = uuid.uuid4().hex[:6]
    gate_b = ew.make_gate(f"Service gate {tag}", kind="pedestrian")
    lane_a_in = _lane(ew, gate_a, f"Entry A {tag}", "in")
    lane_a_out = _lane(ew, gate_a, f"Exit A {tag}", "out")
    lane_b_in = _lane(ew, gate_b, f"Entry B {tag}", "in")
    term_a, term_b, term_sup = _enrol_terminals(ew, gate_a, gate_b)
    # the gateway itself: a REAL device enrolment (guard asks, a different supervisor approves)
    device = ew.edge_device(kind="gateway", bind_gate=gateway_gate_bound, name="Edge gateway")
    with LiveApi(ew.app, now=true_clock) as live:
        wan = WanSwitch(HttpxTransport(live.url))
        anchors = fetch_trust_anchors(
            wan, device.device_id, device.key, now=true_clock() if true_clock else None
        )
        site = Site(
            ew=ew, live=live, t=t, true_clock=true_clock, device=device, gw=None,  # type: ignore[arg-type]
            wan=wan, anchors=anchors, tmp=tmp_path, gate_a=gate_a, gate_b=gate_b,
            lane_a_in=lane_a_in, lane_a_out=lane_a_out, lane_b_in=lane_b_in,
            term_a=term_a, term_b=term_b, term_sup=term_sup,
            keyring=KeyRing({"k1": generate_key()}, "k1"), token_key=generate_private_key(),
            sync_cfg=sync_cfg or {}, skew=skew,
        )  # fmt: skip
        site.gw = site._open(trusted=False)
        site.client = site.new_client()
        try:
            yield site
        finally:
            site.close()
            wan.inner.close()
