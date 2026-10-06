"""Society-facing routes of the edge module: publish a snapshot, status/metrics, quarantine, standing rules (GATE-14).

REQ: EDGE-04 (publish), OBS-02 (sync age, policy age, outbox backlog), EDGE-03 (quarantine is visible), GATE-14 (standing rules per
household), INV-01 (society from the validated path; the household may only touch its own units: 404 otherwise), PRD 12 (Idempotency-Key
on command creation; naturally idempotent calls say so).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import DependencyUnavailable, NotFound

from ...core.authz import AuthContext, idempotency_exempt, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import PageParams, Paginator, SortColumn, get_paginator, page_params
from .config import EdgeConfig
from .metrics import collect_gauges
from .snapshot import latest_snapshot, publish_policy
from .standing_rules import StandingRuleCreate, create_rule, end_rule, list_rules

router = APIRouter(prefix="/v1", tags=["edge"])


def _cfg(request: Request) -> EdgeConfig:
    cfg: EdgeConfig | None = getattr(request.app.state, "edge_config", None)
    if cfg is None:
        raise DependencyUnavailable(retry_after=30)
    return cfg


def _meta(row: dict[str, Any]) -> dict[str, Any]:
    counts = {
        k: len(row["manifest"].get(k, []))
        for k in (
            "gates",
            "lanes",
            "devices",
            "residents",
            "invitations",
            "standing_rules",
            "revocations",
        )
    }
    return {
        "seq": row["seq"],
        "issued_at": row["issued_at"],
        "valid_until": row["valid_until"],
        "issuer_key_id": row["issuer_key_id"],
        "content_hash": row["content_hash"],
        "reason": row["reason"],
        "counts": counts,
    }


# REQ: EDGE-04
@router.post(
    "/societies/{society_id}/edge/policy/publish",
    dependencies=[
        Depends(
            idempotency_exempt(
                "publishing is idempotent by content hash: unchanged content returns the existing snapshot"
            )
        )
    ],
)
def publish(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("edge.policy.publish"))],
    force: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    cfg = _cfg(request)
    with auth.tx() as conn:
        result = publish_policy(conn, auth.ctx, cfg, force=force)
    return {
        "seq": result.seq,
        "changed": result.changed,
        "reason": result.reason,
        "issued_at": result.issued_at,
        "valid_until": result.valid_until,
        "issuer_key_id": result.issuer_key_id,
        "content_hash": result.content_hash,
    }


@router.get("/societies/{society_id}/edge/policy")
def latest_policy(
    society_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("edge.status.read"))]
) -> dict[str, Any]:
    """Metadata of the latest snapshot (never the manifest: that is for devices)."""
    with auth.tx() as conn:
        row = latest_snapshot(conn)
    if row is None:
        raise NotFound()
    return _meta(row)


# REQ: OBS-02
@router.get("/societies/{society_id}/edge/status")
def status(
    society_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("edge.status.read"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return collect_gauges(conn, auth.scope.society_id)


# REQ: EDGE-03
@router.get("/societies/{society_id}/edge/quarantine")
def quarantine(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("edge.status.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    device_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    where = ["true"]
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    if device_id is not None:
        where.append("device_id = :dev")
        params["dev"] = device_id
        filters["device_id"] = device_id
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql="SELECT id, device_id, seq, event_id, event_type, reason, received_at, exception_id FROM edge_quarantine",
            where=where,
            params=params,
            sort=[
                SortColumn("received_at", "timestamptz", nullable=False),
                SortColumn("id", "uuid", nullable=False),
            ],
            page=page,
            society_id=auth.scope.society_id,
            filters=filters,
            descending=True,
        )
    return {"items": result.items, "next_cursor": result.next_cursor}


# ------------------------------------------------------------------------------------------ standing rules (GATE-14)
# REQ: GATE-14
@router.post("/societies/{society_id}/standing-rules", status_code=201)
def create_standing_rule(
    society_id: uuid.UUID,
    body: StandingRuleCreate,
    auth: Annotated[AuthContext, Depends(require("gate.standing_rule.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """``unit_id`` is validated against the caller's grants from the BODY below (a body unit outside the grants is 404)."""
    if not auth.scope.covers_unit(body.unit_id):
        raise NotFound()
    return idem.run(
        auth, lambda conn: create_rule(conn, auth.ctx, auth.scope.society_id, body), status_code=201
    )


@router.get("/societies/{society_id}/standing-rules")
def list_standing_rules(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.standing_rule.read"))],
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[str | None, Query(pattern="^(active|ended)$")] = "active",
) -> dict[str, Any]:
    if unit_id is not None:
        if not auth.scope.covers_unit(unit_id):
            raise NotFound()
        units: list[uuid.UUID] | None = [unit_id]
    elif auth.scope.society_wide:
        units = None
    else:
        units = sorted(auth.scope.unit_ids, key=lambda u: u.int)
    with auth.tx() as conn:
        return {"items": list_rules(conn, units, state=state)}


@router.delete(
    "/societies/{society_id}/standing-rules/{rule_id}",
    dependencies=[
        Depends(
            idempotency_exempt(
                "ending is naturally idempotent: a second DELETE returns the ended rule"
            )
        )
    ],
)
def delete_standing_rule(
    society_id: uuid.UUID,
    rule_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.standing_rule.manage"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return end_rule(conn, auth.ctx, rule_id, auth.scope.covers_unit)
