"""Device-facing routes: ``/v1/edge/me``, ``/policy``, ``/keys``, ``/sync/batches`` (docs/contracts/edge-sync.md).

REQ: EDGE-03 (batch sync: <= 500 events or 1 MB, per-event outcome, highest contiguous ack, gaps, policy cursor), EDGE-04 (signed policy,
rollback rejected), EDGE-07, EDGE-09 (device signature auth), PRD 12.1, PRD 12.2 (error bodies), INV-01 (the society comes from the device
row), OBS-01 (nothing from the request is logged beyond the route template).
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, text

from dwaar_common.errors import DependencyUnavailable, InvalidSchema, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.signing import public_key_to_b64
from dwaar_common.timeutil import format_iso_utc, utc_now

from ...core.authz import public_route
from ...core.db import Database, RequestContext
from .auth import EdgeDevice, SignedEdgeRequest, signed_edge_request
from .config import MAX_BATCH_BYTES, MAX_BATCH_EVENTS, SCHEMA_VERSION, EdgeConfig
from .metrics import EdgeMetrics
from .snapshot import latest_snapshot, publish_policy, snapshot_document
from .sync import ACTOR_ROLE, ingest_batch

router = APIRouter(prefix="/v1/edge", tags=["edge"])

_DEVICE_AUTH = Depends(
    public_route(
        "device-signed edge endpoint: Ed25519 request signature of the registered device key (docs/contracts/edge-sync.md section 1)"
    )
)
_ALLOWED_BODY_KEYS = frozenset({"device_id", "cursor", "events", "schema_version"})


def _cfg(request: Request) -> EdgeConfig:
    cfg: EdgeConfig | None = getattr(request.app.state, "edge_config", None)
    if cfg is None:
        raise DependencyUnavailable(retry_after=30)
    return cfg


def _metrics(request: Request) -> EdgeMetrics | None:
    found: EdgeMetrics | None = getattr(request.app.state, "edge_metrics", None)
    return found


def _ctx(device: EdgeDevice, request_id: uuid.UUID) -> RequestContext:
    return RequestContext(device.society_id, None, ACTOR_ROLE, request_id)


def _ensure_state(conn: Connection, device: EdgeDevice) -> None:
    conn.execute(
        text(
            "INSERT INTO edge_device_state (id, society_id, device_id) VALUES (:id, :s, :d)"
            " ON CONFLICT (society_id, device_id) DO NOTHING"
        ),
        {"id": uuid7(), "s": device.society_id, "d": device.id},
    )


def _touch(conn: Connection, device: EdgeDevice, cfg: EdgeConfig) -> None:
    """``devices.last_seen_at`` at most once per ``last_seen_touch_s`` (a hot row would serialise a busy gateway)."""
    conn.execute(
        text(
            "UPDATE devices SET last_seen_at = clock_timestamp() WHERE id = :id AND (last_seen_at IS NULL"
            " OR last_seen_at < clock_timestamp() - make_interval(secs => :n))"
        ),
        {"id": device.id, "n": cfg.last_seen_touch_s},
    )


# REQ: EDGE-09
@router.get("/me", dependencies=[_DEVICE_AUTH])
def me(
    request: Request, signed: Annotated[SignedEdgeRequest, Depends(signed_edge_request)]
) -> dict[str, Any]:
    cfg, device = _cfg(request), signed.device
    db: Database = request.app.state.db
    with db.app_tx(_ctx(device, signed.request_id)) as conn:
        seen = conn.execute(
            text("SELECT last_seen_at FROM devices WHERE id = :d"), {"d": device.id}
        ).scalar_one()
        _touch(conn, device, cfg)
        _ensure_state(conn, device)
        latest = latest_snapshot(conn)
        state = conn.execute(
            text(
                "SELECT highest_contiguous_seq, last_sync_at, policy_seq_applied FROM edge_device_state WHERE device_id = :d"
            ),
            {"d": device.id},
        ).one()
    return {
        "device": {
            "id": device.id,
            "society_id": device.society_id,
            "kind": device.kind,
            "name": device.name,
            "gate_id": device.gate_id,
            "state": device.state,
            "key_id": device.key_id,
            "simulation": device.simulation,
            "last_seen_at": seen,
        },
        "policy": {
            "latest_seq": latest["seq"] if latest else 0,
            "applied_seq": state[2],
            "latest_issued_at": latest["issued_at"] if latest else None,
        },
        "sync": {"highest_contiguous_seq": state[0], "last_sync_at": state[1]},
        "server_time": format_iso_utc(utc_now()),
    }


# REQ: EDGE-04
@router.get("/keys", dependencies=[_DEVICE_AUTH])
def issuer_keys(
    request: Request, signed: Annotated[SignedEdgeRequest, Depends(signed_edge_request)]
) -> dict[str, Any]:
    """Trust anchors for provisioning: policy issuer keys (``keys``) and the guest-pass QR verification keys (``pass_keys``).

    Both are PUBLIC halves. A gateway pins them at commissioning (ADR-0019); it never takes a key from a snapshot."""
    body: dict[str, Any] = {"keys": _cfg(request).key_list(), "pass_keys": []}
    visits = getattr(request.app.state, "visits_config", None)
    if visits is not None:
        body["pass_keys"] = [
            {
                "key_id": visits.key_id,
                "public_key": public_key_to_b64(visits.signing_key.public_key()),
                "status": "active",
                "simulation": bool(visits.simulation),
            }
        ]
    return body


# REQ: EDGE-04, GATE-06, GATE-14
@router.get("/policy", dependencies=[_DEVICE_AUTH], response_model=None)
def policy(
    request: Request,
    signed: Annotated[SignedEdgeRequest, Depends(signed_edge_request)],
    after: Annotated[int, Query(ge=0, le=2**62)] = 0,
) -> Response:
    """The latest signed snapshot when newer than ``after``; 204 when there is nothing newer; 409 when the device claims to be ahead."""
    cfg, device = _cfg(request), signed.device
    db: Database = request.app.state.db
    ctx = _ctx(device, signed.request_id)
    with db.app_tx(ctx) as conn:
        _touch(conn, device, cfg)
        _ensure_state(conn, device)
        if cfg.publish_on_poll:
            publish_policy(
                conn, RequestContext(device.society_id, None, "system", signed.request_id), cfg
            )
        latest = latest_snapshot(conn)
        latest_seq = int(latest["seq"]) if latest else 0
        if after > latest_seq:
            raise StaleVersion(
                details={"reason": "cursor_ahead_of_cloud", "latest_seq": latest_seq}
            )
        conn.execute(
            text(
                "UPDATE edge_device_state SET policy_seq_applied = GREATEST(policy_seq_applied, :a),"
                " last_policy_poll_at = clock_timestamp() WHERE device_id = :d"
            ),
            {"a": after, "d": device.id},
        )
    metrics = _metrics(request)
    if latest is None or latest_seq <= after:
        if metrics:
            metrics.inc("policy_polls_total", result="none", device=str(device.id))
        return Response(status_code=204)
    if metrics:
        metrics.inc("policy_polls_total", result="served", device=str(device.id))
    return JSONResponse(snapshot_document(latest))


def _too_big(
    request: Request, signed: SignedEdgeRequest, reason: str, **details: Any
) -> JSONResponse:
    request.scope.setdefault("state", {})["error_code"] = InvalidSchema.code
    error = InvalidSchema(details={"reason": reason, **details})
    return JSONResponse(status_code=413, content=error.to_body(str(signed.request_id)))


# REQ: EDGE-03, EDGE-07
@router.post("/sync/batches", dependencies=[_DEVICE_AUTH])
def sync_batches(
    request: Request, signed: Annotated[SignedEdgeRequest, Depends(signed_edge_request)]
) -> Response:
    cfg, device = _cfg(request), signed.device
    db: Database = request.app.state.db
    metrics = _metrics(request)
    if len(signed.body) > MAX_BATCH_BYTES:
        return _too_big(request, signed, "payload_too_large", max_bytes=MAX_BATCH_BYTES)
    try:
        doc = json.loads(signed.body)
    except (ValueError, RecursionError):
        raise InvalidSchema.for_fields([("body", "invalid_json")]) from None
    if not isinstance(doc, dict) or not set(doc) <= _ALLOWED_BODY_KEYS:
        raise InvalidSchema.for_fields([("body", "unexpected_members")])
    if doc.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise InvalidSchema.for_fields([("schema_version", "unsupported")])
    events = doc.get("events")
    if not isinstance(events, list):
        raise InvalidSchema.for_fields([("events", "required_array")])
    if len(events) > MAX_BATCH_EVENTS:
        return _too_big(request, signed, "too_many_events", max_events=MAX_BATCH_EVENTS)
    claimed = doc.get("device_id")
    if not isinstance(claimed, str) or claimed.lower() != str(device.id):
        raise InvalidSchema.for_fields([("device_id", "must_match_authenticated_device")])
    result = ingest_batch(db, device, cfg, signed.request_id, events, metrics=metrics)
    if metrics:
        metrics.inc("batches_total", device=str(device.id))
    return JSONResponse(result.to_wire())
