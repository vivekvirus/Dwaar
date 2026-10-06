"""Outbox sync client: signed requests, policy pull, event batches, acknowledgements, backoff.

REQ: EDGE-03 (batches of at most 500 events / 1 MB; per-event outcomes; highest contiguous acknowledged sequence;
gaps re-sent; retries with exponential backoff and jitter; event ids never regenerated; a quarantined event does
not block later ones), EDGE-04 (policy pull), EDGE-10 (policy and tombstones are pulled BEFORE events are
uploaded), NFR-09 / NFR-10 (buffer and reconcile), PRD 7.4 (trusted sync time recorded from the cloud response).

Request authentication (shared contract with the cloud edge module): headers ``X-Dwaar-Device``,
``X-Dwaar-Timestamp`` (UTC ISO 8601) and ``X-Dwaar-Signature`` = ed25519 over
``METHOD \\n PATH_WITH_QUERY \\n TIMESTAMP \\n sha256_hex(body)``. mTLS and certificate pinning are NOT in this
slice: the request signature authenticates the device; confidentiality needs TLS from the deployment (EDGE-09).
"""

# REQ: EDGE-03, EDGE-04, EDGE-10, NFR-09, NFR-10

from __future__ import annotations

import hashlib
import json
import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final, Protocol

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.signing import sign_bytes
from dwaar_common.timeutil import format_iso_utc

from .errors import PolicyRejected
from .gateway import Gateway
from .outbox import MAX_BATCH_BYTES, MAX_BATCH_EVENTS

log = logging.getLogger("dwaar_edge.sync")

DATE_RESOLUTION_MS: Final = 1000  # HTTP Date has one-second resolution
TIMESTAMP_RETRY_SKEW_S: Final = 60


class TransportError(Exception):
    """Network-level failure (no response)."""


@dataclass(frozen=True)
class TransportResponse:
    status: int
    json: Any = None
    server_time: datetime | None = None  # authenticated cloud time (HTTP Date), if any
    elapsed_ms: int = 0


class Transport(Protocol):
    def request(
        self, method: str, path_with_query: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse: ...


class HttpxTransport:
    """Real HTTP transport. The base URL must be https in deployment; certificates/mTLS come from the installer."""

    def __init__(
        self, base_url: str, *, timeout_s: float = 30.0, verify: bool | str = True, cert: Any = None
    ) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=timeout_s, verify=verify, cert=cert)

    def request(
        self, method: str, path_with_query: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        t0 = time.monotonic()
        try:
            resp = self._client.request(method, path_with_query, headers=headers, content=body)
        except httpx.HTTPError as exc:
            raise TransportError(type(exc).__name__) from exc
        elapsed = int((time.monotonic() - t0) * 1000)
        server_time = None
        date = resp.headers.get("date")
        if date:
            try:
                server_time = parsedate_to_datetime(date).astimezone(UTC)
            except (TypeError, ValueError):
                server_time = None
        data: Any = None
        if resp.content:
            try:
                data = resp.json()
            except ValueError:
                data = None
        return TransportResponse(resp.status_code, data, server_time, elapsed)

    def close(self) -> None:
        self._client.close()


@dataclass
class SyncConfig:
    max_events: int = MAX_BATCH_EVENTS
    max_bytes: int = MAX_BATCH_BYTES
    backoff_base_s: float = 1.0
    backoff_cap_s: float = 300.0
    max_bytes_per_s: float | None = None  # throttle to protect live decisions (None = unthrottled)
    max_batches_per_cycle: int = 10_000


@dataclass
class SyncResult:
    policy: str = "skipped"  # applied | up_to_date | rejected:<code> | failed | skipped
    batches: int = 0
    sent: int = 0
    acked: int = 0
    quarantined: int = 0
    rejected: int = 0
    requeued: int = 0
    failed: str | None = None
    next_delay_s: float = 0.0
    bytes_sent: int = 0


@dataclass
class SyncClient:
    gateway: Gateway
    transport: Transport
    config: SyncConfig = field(default_factory=SyncConfig)
    sleep: Callable[[float], None] = time.sleep
    rng: random.Random = field(default_factory=random.Random)
    _failures: int = field(default=0, init=False)
    _batch_limit: int = field(default=0, init=False)
    _pull_policy_next: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        self._batch_limit = self.config.max_events

    # ---- request signing ----------------------------------------------------------------------------
    @property
    def _key(self) -> Ed25519PrivateKey:
        return self.gateway.config.device_key

    def signed_headers(
        self, method: str, path_with_query: str, body: bytes, at: datetime
    ) -> dict[str, str]:
        ts = format_iso_utc(at)
        canonical = (
            f"{method}\n{path_with_query}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
        )
        return {
            "X-Dwaar-Device": str(self.gateway.config.device_id),
            "X-Dwaar-Timestamp": ts,
            "X-Dwaar-Signature": sign_bytes(self._key, canonical),
            "Content-Type": "application/json",
        }

    def _send(self, method: str, path: str, payload: Any | None) -> TransportResponse:
        body = (
            b""
            if payload is None
            else json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        )
        at = self.gateway.clock.assess().now
        resp = self.transport.request(
            method, path, self.signed_headers(method, path, body, at), body
        )
        if resp.status == 401 and resp.server_time is not None:
            skew = abs((resp.server_time - at).total_seconds())
            if skew > TIMESTAMP_RETRY_SKEW_S:
                # A clock far off (for example after a restart) makes every signed request look stale to the cloud.
                # Retry ONCE stamping the request with the server's own Date; the clock itself is only synchronised
                # from an authenticated 2xx response, never from this 401.
                at = resp.server_time + timedelta(milliseconds=resp.elapsed_ms // 2)
                resp = self.transport.request(
                    method, path, self.signed_headers(method, path, body, at), body
                )
        if 200 <= resp.status < 300 and resp.server_time is not None:
            # trusted time = server Date + half the round trip; uncertainty covers RTT and Date resolution
            unc = resp.elapsed_ms // 2 + DATE_RESOLUTION_MS
            self.gateway.note_trusted_time(resp.server_time, unc)
        return resp

    # ---- backoff -------------------------------------------------------------------------------------
    def _fail(self, reason: str) -> float:
        """Exponential backoff with FULL jitter: delay ~ U(0, min(cap, base * 2^n))."""
        self._failures += 1
        ceiling = min(
            self.config.backoff_cap_s, self.config.backoff_base_s * (2 ** min(self._failures, 30))
        )
        delay = self.rng.uniform(0, ceiling)
        self.gateway.sync_info.update(
            {"last_error": reason, "consecutive_failures": self._failures}
        )
        return delay

    def _ok(self) -> None:
        self._failures = 0
        self.gateway.sync_info.update({"last_error": None, "consecutive_failures": 0})

    # ---- policy -----------------------------------------------------------------------------------------
    def pull_policy(self) -> str:
        seq = self.gateway.policy_seq()
        resp = self._send("GET", f"/v1/edge/policy?after={seq}", None)
        if resp.status == 204:
            self.gateway.confirm_policy_current()
            self._pull_policy_next = False
            return "up_to_date"
        if resp.status == 409:
            # the cloud's cursor is behind ours: never roll back; alert and keep serving the cached policy
            self.gateway.sync_info["policy_cursor_ahead_of_cloud"] = True
            self.gateway.note_cloud_contact()
            return "cursor_ahead_of_cloud"
        if resp.status == 200 and isinstance(resp.json, dict):
            self.gateway.sync_info["policy_cursor_ahead_of_cloud"] = False
            try:
                self.gateway.apply_policy(resp.json)
            except PolicyRejected as exc:
                self.gateway.sync_info["last_policy_error"] = exc.code
                self.gateway.note_cloud_contact()
                return f"rejected:{exc.code}"
            self.gateway.confirm_policy_current()
            self._pull_policy_next = False
            return "applied"
        self.gateway.note_cloud_contact() if resp.status < 500 else None
        raise TransportError(f"policy status {resp.status}")

    # ---- events -------------------------------------------------------------------------------------------
    def push_batch(self) -> SyncResult:
        """Send one batch. Returns counts; raises TransportError on failure (events stay pending)."""
        res = SyncResult()
        rows = self.gateway.outbox.pending_batch(
            max_events=self._batch_limit, max_bytes=self.config.max_bytes
        )
        if not rows:
            return res
        wire = [r.wire for r in rows]
        body = {"device_id": str(self.gateway.config.device_id), "events": wire}
        self.gateway.outbox.note_attempt([r.seq for r in rows], self.gateway.clock.assess().now)
        resp = self._send("POST", "/v1/edge/sync/batches", body)
        res.batches, res.sent = 1, len(rows)
        res.bytes_sent = len(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode())
        if resp.status in (400, 413, 422) and len(rows) > 1:
            self._batch_limit = max(1, len(rows) // 2)  # isolate the offender by halving
            raise TransportError(
                f"batch refused {resp.status}; batch limit now {self._batch_limit}"
            )
        if resp.status in (400, 422) and len(rows) == 1:
            # one event the cloud refuses outright must not block every later event
            self.gateway.outbox.apply_outcomes(
                [(str(rows[0].event_id), "quarantined", f"cloud_http_{resp.status}")],
                [],
                self.gateway.clock.assess().now,
            )
            res.quarantined = 1
            return res
        if resp.status in (401, 403):
            self.gateway.sync_info["auth_failed"] = True
            raise TransportError(f"authentication refused ({resp.status})")
        if resp.status != 200 or not isinstance(resp.json, dict):
            raise TransportError(f"sync status {resp.status}")
        self.gateway.sync_info["auth_failed"] = False
        data = resp.json
        sent_ids = {str(r.event_id) for r in rows}
        outcomes: list[tuple[str, str, str | None]] = []
        for o in data.get("outcomes", []):
            if (
                isinstance(o, dict)
                and str(o.get("event_id")) in sent_ids
                and isinstance(o.get("status"), str)
            ):
                outcomes.append((str(o["event_id"]), o["status"], o.get("reason")))
        gaps: list[tuple[int, int]] = []
        for g in data.get("gaps", []):
            if isinstance(g, list | tuple) and len(g) == 2 and all(isinstance(x, int) for x in g):
                gaps.append((g[0], g[1]))
        counts = self.gateway.outbox.apply_outcomes(outcomes, gaps, self.gateway.clock.assess().now)
        res.acked, res.quarantined, res.rejected, res.requeued = (
            counts["acked"],
            counts["quarantined"],
            counts["rejected"],
            counts["requeued"],
        )
        self.gateway.sync_info["highest_contiguous_seq"] = data.get("highest_contiguous_seq")
        self.gateway.note_cloud_contact()
        cursor = data.get("policy_cursor")
        if (
            isinstance(cursor, dict)
            and isinstance(cursor.get("latest_seq"), int)
            and cursor["latest_seq"] > self.gateway.policy_seq()
        ):
            self._pull_policy_next = True
        self._batch_limit = min(self.config.max_events, max(self._batch_limit * 2, 1))
        return res

    # ---- one cycle -------------------------------------------------------------------------------------------
    def sync_once(self) -> SyncResult:
        """Policy first (tombstones before cached personal records, EDGE-10), then batches until drained.
        On failure returns ``failed`` and ``next_delay_s`` (jittered backoff); never raises."""
        total = SyncResult()
        try:
            total.policy = self.pull_policy()
            self._ok()
        except TransportError as exc:
            total.policy = "failed"
            total.failed = str(exc)
            total.next_delay_s = self._fail(str(exc))
            return total
        throttle_started = time.monotonic()
        for _ in range(self.config.max_batches_per_cycle):
            try:
                part = self.push_batch()
            except TransportError as exc:
                total.failed = str(exc)
                total.next_delay_s = self._fail(str(exc))
                return total
            if part.batches == 0:
                break
            total.batches += part.batches
            for name in ("sent", "acked", "quarantined", "rejected", "requeued", "bytes_sent"):
                setattr(total, name, getattr(total, name) + getattr(part, name))
            self._ok()
            if self.config.max_bytes_per_s:
                wait = part.bytes_sent / self.config.max_bytes_per_s - (
                    time.monotonic() - throttle_started
                )
                throttle_started = time.monotonic()
                if wait > 0:
                    self.sleep(wait)
            if (
                part.acked == 0
                and part.quarantined == 0
                and part.rejected == 0
                and part.requeued == 0
            ):
                break  # nothing progressed (cloud returned no outcomes): do not spin
        return total


class SyncWorker:
    """Background thread that runs ``sync_once`` forever with backoff. Stoppable; no inbound ports."""

    def __init__(self, client: SyncClient, *, interval_s: float = 15.0) -> None:
        self.client = client
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="dwaar-edge-sync", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                result = self.client.sync_once()
            except Exception:
                log.exception("sync cycle crashed; will retry")
                result = SyncResult(failed="crash", next_delay_s=self.interval_s)
            self._stop.wait(result.next_delay_s if result.failed else self.interval_s)
