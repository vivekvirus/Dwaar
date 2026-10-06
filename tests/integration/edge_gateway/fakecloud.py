"""FakeCloud: an in-process implementation of the edge <-> cloud CONTRACT (clearly NOT the real API).

A later integration step wires the real ``dwaar_api.modules.edge``. This fake implements exactly the shared
contract the edge client codes to: signed requests (X-Dwaar-Device/Timestamp/Signature), GET /v1/edge/policy,
POST /v1/edge/sync/batches with per-event outcomes, highest contiguous seq, gaps and a policy cursor. It also
offers fault injection (down, lost responses, slow link) so crash/partition scenarios are testable.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from dwaar_common.events import EdgeEvent
from dwaar_common.signing import VerifierRing, verify_bytes
from dwaar_common.timeutil import parse_iso_utc
from dwaar_edge.sync import TransportError, TransportResponse

MAX_EVENTS = 500
MAX_BYTES = 1_000_000


@dataclass
class FakeCloud:
    society_id: uuid.UUID
    now: Callable[[], datetime]
    device_keys: dict[str, Ed25519PublicKey] = field(default_factory=dict)
    policy: dict[str, Any] | None = None
    online: bool = True
    serve_policy_always: bool = False  # emulate a buggy/hostile cloud replaying an old snapshot
    drop_response_once: bool = (
        False  # process the batch, then lose the response (client must resend)
    )
    fail_status_once: int | None = None
    # storage
    events: dict[str, dict[str, Any]] = field(default_factory=dict)  # event_id -> wire
    by_device_seq: dict[tuple[str, int], str] = field(default_factory=dict)
    quarantine: dict[str, str] = field(default_factory=dict)
    entities: dict[str, tuple[str, int]] = field(default_factory=dict)  # entity -> (state, version)
    requests: list[tuple[str, str]] = field(default_factory=list)
    outcome_log: list[dict[str, Any]] = field(default_factory=list)
    auth_failures: int = 0

    def register_device(self, device_id: uuid.UUID, key: Ed25519PublicKey) -> None:
        self.device_keys[str(device_id)] = key

    def publish_policy(self, signed_snapshot: dict[str, Any]) -> None:
        self.policy = signed_snapshot

    # ---- the contract -------------------------------------------------------------------------------
    def handle(
        self, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        if not self.online:
            raise TransportError("connection refused (fake cloud offline)")
        self.requests.append((method, path))
        server_time = self.now()
        if self.fail_status_once is not None:
            status, self.fail_status_once = self.fail_status_once, None
            return TransportResponse(status, {"code": "injected"}, server_time)
        device = headers.get("X-Dwaar-Device", "")
        if not self._authentic(method, path, headers, body, server_time):
            self.auth_failures += 1
            return TransportResponse(401, {"code": "unauthenticated"}, server_time)
        if method == "GET" and path.startswith("/v1/edge/policy"):
            after = int(path.split("after=")[1]) if "after=" in path else 0
            if self.policy is not None and after > int(self.policy["seq"]):
                return TransportResponse(
                    409,
                    {"code": "stale_version", "details": {"reason": "cursor_ahead_of_cloud"}},
                    server_time,
                )
            if self.policy is not None and (
                self.serve_policy_always or int(self.policy["seq"]) > after
            ):
                return TransportResponse(200, self.policy, server_time)
            return TransportResponse(204, None, server_time)
        if method == "POST" and path == "/v1/edge/sync/batches":
            return self._batch(device, body, server_time)
        return TransportResponse(404, {"code": "not_found"}, server_time)

    def _authentic(
        self, method: str, path: str, headers: dict[str, str], body: bytes, now: datetime
    ) -> bool:
        key = self.device_keys.get(headers.get("X-Dwaar-Device", ""))
        ts = headers.get("X-Dwaar-Timestamp")
        sig = headers.get("X-Dwaar-Signature")
        if key is None or ts is None or sig is None:
            return False
        try:
            stamp = parse_iso_utc(ts)
        except ValueError:
            return False
        if abs(stamp - now) > timedelta(minutes=5):
            return False
        canonical = f"{method}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
        return verify_bytes(key, canonical, sig)

    def _batch(self, device: str, body: bytes, server_time: datetime) -> TransportResponse:
        if len(body) > MAX_BYTES:
            return TransportResponse(413, {"code": "batch_too_large"}, server_time)
        data = json.loads(body)
        events = data.get("events", [])
        if len(events) > MAX_EVENTS or data.get("device_id") != device:
            return TransportResponse(
                413 if len(events) > MAX_EVENTS else 400, {"code": "bad_batch"}, server_time
            )
        ring = VerifierRing(require_binding=True)
        ring.add(
            device,
            self.device_keys[device],
            society_id=self.society_id,
            device_id=uuid.UUID(device),
        )
        outcomes = []
        for wire in events:
            outcomes.append(self._one(device, ring, wire))
        self.outcome_log.extend(outcomes)
        seqs = sorted(s for (d, s) in self.by_device_seq if d == device)
        high, gaps = 0, []
        present = set(seqs)
        if present:
            top = max(present)
            cur = 1
            while cur in present:
                cur += 1
            high = cur - 1
            lo = None
            for s in range(high + 1, top + 1):
                if s not in present and lo is None:
                    lo = s
                if s in present and lo is not None:
                    gaps.append([lo, s - 1])
                    lo = None
        resp = {
            "outcomes": outcomes,
            "highest_contiguous_seq": high,
            "gaps": gaps,
            "policy_cursor": {"latest_seq": 0 if self.policy is None else int(self.policy["seq"])},
        }
        if self.drop_response_once:
            self.drop_response_once = False
            raise TransportError("response lost")
        return TransportResponse(200, resp, server_time)

    def _one(self, device: str, ring: VerifierRing, wire: dict[str, Any]) -> dict[str, Any]:
        eid = str(wire.get("event_id"))
        try:
            event = EdgeEvent.from_wire(wire)
        except Exception:
            self.quarantine[eid] = "malformed"
            return {"event_id": eid, "status": "quarantined", "reason": "malformed"}
        if event.society_id != self.society_id:
            self.quarantine[eid] = "wrong_society"
            return {"event_id": eid, "status": "quarantined", "reason": "wrong_society"}
        if not ring.verify_event(device, event):
            self.quarantine[eid] = "bad_signature"
            self.by_device_seq[(device, event.seq)] = eid  # seen, so it never becomes a gap
            return {"event_id": eid, "status": "quarantined", "reason": "bad_signature"}
        if eid in self.events or (device, event.seq) in self.by_device_seq:
            return {"event_id": eid, "status": "duplicate"}
        state = self.entities.get(str(event.entity_id))
        if event.type == "EntryObserved":
            if state is not None:
                self.by_device_seq[(device, event.seq)] = eid
                self.events[eid] = wire  # preserved for the exception queue, not applied
                return {"event_id": eid, "status": "rejected_transition", "reason": "entity_exists"}
            self.entities[str(event.entity_id)] = ("inside", event.entity_version)
        elif event.type == "ExitObserved":
            if state is not None and (state[0] != "inside" or event.entity_version != state[1] + 1):
                self.by_device_seq[(device, event.seq)] = eid
                self.events[eid] = wire
                return {"event_id": eid, "status": "rejected_transition", "reason": "not_inside"}
            self.entities[str(event.entity_id)] = ("exited", event.entity_version)
        self.events[eid] = wire
        self.by_device_seq[(device, event.seq)] = eid
        return {"event_id": eid, "status": "accepted"}

    # ---- helpers for assertions -----------------------------------------------------------------------------
    def accepted_seqs(self, device: uuid.UUID) -> list[int]:
        return sorted(s for (d, s) in self.by_device_seq if d == str(device))

    def transport(self) -> FakeCloudTransport:
        return FakeCloudTransport(self)


class FakeCloudTransport:
    def __init__(self, cloud: FakeCloud) -> None:
        self.cloud = cloud
        self.bytes_up = 0
        self.calls = 0

    def request(
        self, method: str, path_with_query: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        self.calls += 1
        self.bytes_up += len(body)
        return self.cloud.handle(method, path_with_query, headers, body)


class ThrottledTransport:
    """Simulated slow link: advances a VIRTUAL clock by body_bits / bandwidth + RTT. A SIMULATION, not a measurement of a
    real network."""

    def __init__(
        self,
        inner: FakeCloudTransport,
        *,
        bits_per_s: float,
        rtt_s: float = 0.05,
        advance: Callable[[float], None] | None = None,
    ) -> None:
        self.inner = inner
        self.bits_per_s = bits_per_s
        self.rtt_s = rtt_s
        self.virtual_seconds = 0.0
        self.advance = advance

    def request(
        self, method: str, path_with_query: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        cost = len(body) * 8 / self.bits_per_s + self.rtt_s
        self.virtual_seconds += cost
        if self.advance is not None:
            self.advance(cost)
        return self.inner.request(method, path_with_query, headers, body)


def utc(*a: int) -> datetime:
    return datetime(*a, tzinfo=UTC)
