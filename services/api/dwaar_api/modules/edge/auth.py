"""Device authentication for the edge endpoints: per-device Ed25519 request signatures.

REQ: EDGE-09 (per-device identity; revocation effective at once; scrubbed logs), EDGE-03 (retries), INV-01 (the society is derived from the
device row, never from the request), PRD 12.2 (401 / 403 / 429 error body), OBS-01 (no signature, key, timestamp or raw header is ever logged).

What this is NOT: mTLS with per-device certificates (EDGE-09) is a deployment-layer control and is not claimed here.

Canonical request bytes (docs/contracts/edge-sync.md section 1)::

    METHOD "\\n" PATH_WITH_QUERY "\\n" TIMESTAMP "\\n" sha256_hex(body)

Verification is Ed25519 (no secret-dependent comparison happens in this code). Every authentication failure is the same 401 body whatever
the reason; the reason goes to the log as a code next to a keyed-free hash of the claimed device id.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import text

from dwaar_common.errors import DependencyUnavailable, NotAuthorised, RateLimited, Unauthenticated
from dwaar_common.logging import society_log_token
from dwaar_common.signing import (
    SIGNATURE_PREFIX,
    SigningError,
    public_key_from_b64,
    sign_bytes,
    verify_bytes,
)
from dwaar_common.timeutil import parse_iso_utc, utc_now

from ...core import ratelimit
from ...core.db import Database
from .config import EdgeConfig
from .metrics import EdgeMetrics

log = logging.getLogger("dwaar_api.edge.auth")

DEVICE_HEADER: Final = "X-Dwaar-Device"
TIMESTAMP_HEADER: Final = "X-Dwaar-Timestamp"
SIGNATURE_HEADER: Final = "X-Dwaar-Signature"
_MAX_HEADER: Final = 200
_DECOY_KEY: Final = Ed25519PrivateKey.generate().public_key()


@dataclass(frozen=True)
class EdgeDevice:
    """An authenticated, ACTIVE device. ``society_id`` comes from the database row."""

    id: uuid.UUID
    society_id: uuid.UUID
    kind: str
    name: str
    gate_id: uuid.UUID | None
    state: str
    key_id: str
    simulation: bool
    public_key: str


@dataclass(frozen=True)
class SignedEdgeRequest:
    device: EdgeDevice
    body: bytes
    request_id: uuid.UUID


# ------------------------------------------------------------------------------------------ canonical bytes
def request_target(request: Request) -> str:
    """The request target exactly as sent (raw path plus raw query string), the part both sides sign."""
    raw = request.scope.get("raw_path")
    path = raw.decode("latin-1") if isinstance(raw, bytes) else request.scope["path"]
    path = path.partition("?")[0]
    query = request.scope.get("query_string", b"")
    return path + ("?" + query.decode("latin-1") if query else "")


def canonical_request_bytes(method: str, target: str, timestamp: str, body: bytes) -> bytes:
    return "\n".join([method.upper(), target, timestamp, hashlib.sha256(body).hexdigest()]).encode(
        "utf-8"
    )


def sign_request_headers(
    private_key: Ed25519PrivateKey,
    device_id: uuid.UUID,
    method: str,
    target: str,
    body: bytes = b"",
    *,
    timestamp: str | None = None,
) -> dict[str, str]:
    """The three headers an edge sends. Used by the tests and by simulators; the edge agent has its own implementation."""
    ts = (
        timestamp
        or utc_now().strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc_now().microsecond // 1000:03d}Z"
    )
    return {
        DEVICE_HEADER: str(device_id),
        TIMESTAMP_HEADER: ts,
        SIGNATURE_HEADER: sign_bytes(
            private_key, canonical_request_bytes(method, target, ts, body)
        ),
    }


# ------------------------------------------------------------------------------------------ authentication
def _fail(metrics: EdgeMetrics | None, reason: str, claimed: str | None) -> Unauthenticated:
    token = hashlib.sha256((claimed or "").encode("utf-8", "replace")).hexdigest()[:12]
    log.info("edge authentication failed", extra={"reason": reason, "device_token": token})
    if metrics is not None:
        metrics.inc("auth_failures_total", reason=reason)
    return Unauthenticated()


def _parse_uuid(raw: str) -> uuid.UUID | None:
    try:
        parsed = uuid.UUID(raw)
    except ValueError:
        return None
    return parsed if str(parsed) == raw.lower() else None  # one spelling per device


def authenticate(request: Request, body: bytes) -> EdgeDevice:
    """Verify the three headers against the device's registered key. Raises 401 / 403 / 429 / 503; never returns a revoked device."""
    state = request.app.state
    cfg: EdgeConfig | None = getattr(state, "edge_config", None)
    if cfg is None:
        raise DependencyUnavailable(retry_after=30)
    metrics: EdgeMetrics | None = getattr(state, "edge_metrics", None)
    db: Database = state.db
    headers = request.headers
    raw_device = headers.get(DEVICE_HEADER, "")
    raw_ts = headers.get(TIMESTAMP_HEADER, "")
    raw_sig = headers.get(SIGNATURE_HEADER, "")
    if not raw_device or not raw_ts or not raw_sig:
        raise _fail(metrics, "missing_headers", raw_device[:64])
    if max(len(raw_device), len(raw_ts), len(raw_sig)) > _MAX_HEADER:
        raise _fail(metrics, "header_too_long", raw_device[:64])
    device_id = _parse_uuid(raw_device)
    if device_id is None:
        raise _fail(metrics, "malformed_device", raw_device[:64])
    # coarse pre-authentication budget per source address (cheap), then the per-device budget once the signature is proven
    client = request.client.host if request.client else "unknown"
    pre = ratelimit.take(
        db,
        "edge-ip:" + hashlib.sha256(client.encode()).hexdigest()[:24],
        capacity=cfg.ip_rate_capacity,
        refill_per_second=cfg.ip_rate_refill_per_s,
    )
    if not pre.allowed:
        raise RateLimited(retry_after=pre.retry_after_seconds)
    with db.app_tx() as conn:
        row = (
            conn.execute(text("SELECT * FROM edge.device_for_auth(:d)"), {"d": device_id})
            .mappings()
            .first()
        )
    if row is None:
        # spend the same work an existing device costs (one Ed25519 verification), so response time does not tell an
        # outsider which device ids exist
        verify_bytes(_DECOY_KEY, b"decoy", SIGNATURE_PREFIX + "A" * 86)
        raise _fail(metrics, "unknown_device", raw_device)
    try:
        stamp = parse_iso_utc(raw_ts)
    except (ValueError, TypeError):
        raise _fail(metrics, "malformed_timestamp", raw_device) from None
    if abs((utc_now() - stamp).total_seconds()) > cfg.max_skew_s:
        raise _fail(metrics, "timestamp_outside_window", raw_device)
    try:
        key: Ed25519PublicKey = public_key_from_b64(str(row["public_key"]))
    except (SigningError, ValueError):  # unreachable: the column is checked; fail closed anyway
        raise _fail(metrics, "bad_registered_key", raw_device) from None
    signature = raw_sig if raw_sig.startswith(SIGNATURE_PREFIX) else SIGNATURE_PREFIX + raw_sig
    signed = canonical_request_bytes(request.method, request_target(request), raw_ts, body)
    if not verify_bytes(key, signed, signature):
        raise _fail(metrics, "bad_signature", raw_device)
    if row["state"] != "active":
        # the caller proved it holds this device's key: telling it the state leaks nothing it does not own
        if metrics is not None:
            metrics.inc("auth_failures_total", reason="device_not_active")
        log.info(
            "edge device refused", extra={"reason": "device_not_active", "state": row["state"]}
        )
        raise NotAuthorised(details={"reason": "device_not_active"})
    decision = ratelimit.take(
        db,
        f"edge-device:{device_id}",
        capacity=cfg.rate_capacity,
        refill_per_second=cfg.rate_refill_per_s,
    )
    if not decision.allowed:
        if metrics is not None:
            metrics.inc("rate_limited_total", device=str(device_id))
        raise RateLimited(retry_after=decision.retry_after_seconds)
    request.scope.setdefault("state", {})["society_token"] = society_log_token(row["society_id"])
    return EdgeDevice(
        id=device_id,
        society_id=row["society_id"],
        kind=row["kind"],
        name=row["name"],
        gate_id=row["gate_id"],
        state=row["state"],
        key_id=row["key_id"],
        simulation=bool(row["simulation"]),
        public_key=row["public_key"],
    )


async def signed_edge_request(request: Request) -> SignedEdgeRequest:
    """FastAPI dependency for every device endpoint: reads the body, authenticates, returns device + body."""
    body = await request.body()
    device = await run_in_threadpool(authenticate, request, body)
    request_id = uuid.UUID(str(request.scope.get("state", {}).get("request_id")))
    return SignedEdgeRequest(device, body, request_id)
