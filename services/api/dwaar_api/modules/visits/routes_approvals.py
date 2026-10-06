"""HTTP routes: approval requests (unannounced visitors), decisions, destination helpers.

REQ: GATE-02, GATE-03, GATE-13, PRD 9.2 (Approval request), PRD 12.1 / 12.3 (``POST /v1/approval-requests/{id}/decision``:
decision, expected_version, client_action_id -> canonical state), PRD 12.2 (409 stale_version / already_decided /
request_expired), INV-01, INV-03, INV-07.

The society of ``/v1/approval-requests...`` routes is selected by ``X-Society-Id`` (the PRD paths carry none) and validated
against the caller's grants like a path society; a header naming a society the caller is not in is 404.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation

from ...core.authz import AuthContext, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import (
    PageParams,
    Paginator,
    SortColumn,
    get_paginator,
    page_params,
    parse_filters,
)
from . import approvals, common, gates
from . import policy as policy_mod
from .config import VisitsConfig
from .deps import audience, covered, restore_canonical, visits_config
from .schemas import (
    HTTP_DECISION_CHANNELS,
    ApprovalRequestCreate,
    CancelIn,
    DecisionIn,
    ReversalIn,
)

router = APIRouter(prefix="/v1", tags=["approvals"])


# REQ: GATE-02
@router.post("/approval-requests", status_code=201)
def create_request(
    body: ApprovalRequestCreate,
    auth: Annotated[AuthContext, Depends(require("gate.request.create"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[VisitsConfig, Depends(visits_config)],
) -> JSONResponse:
    """The guard raises a request for an unannounced visitor: destination (unit, confirmed against the masked surname hint),
    visitor notice and consent recorded, request PENDING until the household decides or it expires (default 90 s from
    the society policy). Nothing here admits anybody."""

    def work(conn: Any) -> dict[str, Any]:
        policy = policy_mod.load_policy(conn)
        return approvals.create_request(conn, auth.ctx, cfg, auth.scope.society_id, body, policy)

    return idem.run(auth, work, status_code=201)


@router.get("/approval-requests/{request_id}")
def get_request(
    request_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.request.read"))],
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """The request as the caller may see it (the household of the unit, or a guard of the CURRENT gate: ``gate_id`` is
    required for a guard and must be the gate of the request). Expiry is applied first (lazily)."""
    who = audience(auth.scope.role)
    if who == "guard" and gate_id is None:
        raise InvalidSchema.for_fields([("gate_id", "required_for_guard")])
    with auth.tx() as conn:
        approvals.expire_due_requests(conn, auth.ctx, request_id=request_id)
        row = approvals.fetch_request(conn, request_id)
        if row is None:
            raise NotFound()
        if who == "household":
            covered(auth, row["unit_id"])
        elif row["gate_id"] != gate_id:
            raise NotFound()
        return approvals.request_view(row, audience="guard" if who == "guard" else "household")


# REQ: GATE-03
@router.post("/approval-requests/{request_id}/decision")
def decide_request(
    request_id: uuid.UUID,
    body: DecisionIn,
    auth: Annotated[AuthContext, Depends(require("gate.request.decide"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """PRD 12.3. The first valid decision wins (compare-and-swap in one transaction). A later caller gets 409
    ``already_decided`` with the canonical result; a decision after expiry gets 409 ``request_expired`` and issues NO
    permission. ``client_action_id`` makes a retry harmless even under a new Idempotency-Key."""
    if body.channel not in HTTP_DECISION_CHANNELS:
        # recorded provenance is the server's to state, never a client's claim (the notifications module sets ivr / whatsapp / sms / guard_assisted)
        raise PolicyViolation(
            "This decision channel cannot be claimed by a client.",
            details={
                "reason": "channel_set_by_the_server",
                "allowed": sorted(HTTP_DECISION_CHANNELS),
            },
        )
    # An expiry that is due is PERSISTED first, in its own transaction: the decision below then fails with 409 and rolls
    # back, which must not roll the expiry (and its ApprovalEscalated event) back with it.
    with auth.tx() as conn:
        approvals.expire_due_requests(conn, auth.ctx, request_id=request_id)

    def work(conn: Any) -> dict[str, Any]:
        policy = policy_mod.load_policy(conn)
        return approvals.decide(conn, auth.ctx, auth.scope, request_id, body, policy)

    return restore_canonical(idem.run(auth, work, status_code=200))


@router.post("/approval-requests/{request_id}/reversal")
def reverse_request(
    request_id: uuid.UUID,
    body: ReversalIn,
    auth: Annotated[AuthContext, Depends(require("gate.request.decide"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Reverse an APPROVAL before the visitor has entered: a NEW decision event (the first decision is never edited)."""

    def work(conn: Any) -> dict[str, Any]:
        return approvals.reverse(conn, auth.ctx, auth.scope, request_id, body)

    return restore_canonical(idem.run(auth, work))


@router.post("/approval-requests/{request_id}/cancel")
def cancel_request(
    request_id: uuid.UUID,
    body: CancelIn,
    auth: Annotated[AuthContext, Depends(require("gate.request.create"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The guard withdraws a pending request (the visitor left)."""

    def work(conn: Any) -> dict[str, Any]:
        return approvals.cancel(conn, auth.ctx, request_id, body)

    return restore_canonical(idem.run(auth, work))


@router.get("/societies/{society_id}/approval-requests")
def list_requests(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("gate.request.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[
        Literal["pending", "approved", "denied", "expired", "cancelled"], Query()
    ] = "pending",
) -> dict[str, Any]:
    """Household: its own units' requests. Guard: the CURRENT gate's requests (``gate_id`` is required), masked."""
    parse_filters(
        dict(request.query_params),
        {},
        reserved=frozenset({"limit", "cursor", "unit_id", "gate_id", "state"}),
    )
    who = audience(auth.scope.role)
    where: list[str] = ["r.state = :state"]
    params: dict[str, Any] = {"state": state}
    filters: dict[str, Any] = {"state": state}
    if who == "guard":
        if gate_id is None:
            raise InvalidSchema.for_fields([("gate_id", "required_for_guard")])
        where.append("r.gate_id = :gate")
        params["gate"] = gate_id
        filters["gate_id"] = gate_id
        if unit_id is not None:
            where.append("r.unit_id = :unit")
            params["unit"] = unit_id
            filters["unit_id"] = unit_id
    else:
        if unit_id is not None:
            covered(auth, unit_id)
            units = [unit_id]
        else:
            units = sorted(auth.scope.unit_ids, key=lambda u: u.int)
        where.append("r.unit_id = ANY(:units)")
        params["units"] = units
        filters["units"] = ",".join(str(u) for u in units)
    with auth.tx() as conn:
        approvals.expire_due_requests(conn, auth.ctx, limit=50)
        result = paginator.fetch(
            conn,
            select_sql=approvals._REQ_SELECT.rstrip(),  # noqa: SLF001 (same module family)
            where=where,
            params=params,
            sort=[
                SortColumn("r.created_at", "timestamptz", nullable=False),
                SortColumn("r.id", "uuid", nullable=False),
            ],
            page=page,
            society_id=auth.scope.society_id,
            filters=filters,
            descending=True,
        )
    return {
        "items": [
            approvals.request_view(r, audience="guard" if who == "guard" else "household")
            for r in result.items
        ],
        "next_cursor": result.next_cursor,
    }


# ------------------------------------------------------------------------------------------ destination helpers (GATE-02)
@router.get("/societies/{society_id}/units/{unit_id}/destination-hint")
def destination_hint(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.destination.read", unit_param="unit_id"))],
) -> dict[str, Any]:
    """Masked surname confirmation: the guard sees the unit and ``P****`` (first letter of the occupant's family name) and
    asks the visitor to confirm. No resident name, number or identity beyond that (GATE-13)."""
    with auth.tx() as conn:
        unit = common.require_unit(conn, unit_id)
        hint = common.surname_hint(conn, unit_id)
    return {
        "unit_id": unit_id,
        "block_name": unit["block_name"],
        "unit_label": unit["label"],
        "surname_hint": hint,
        "can_request": hint is not None,
    }


@router.get("/societies/{society_id}/gates/{gate_id}/recent-destinations")
def recent_destinations(
    society_id: uuid.UUID,
    gate_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.destination.read"))],
    limit: Annotated[int, Query(ge=1, le=20)] = 10,
) -> dict[str, Any]:
    """Recent destinations at this gate (most recent first, distinct), to speed up the tower-first selection grid."""
    with auth.tx() as conn:
        gates.require_active_gate(conn, gate_id)
        rows = conn.execute(
            text(
                "SELECT r.unit_id, max(r.created_at) AS last_at, u.label, b.name AS block_name FROM approval_requests r"
                " JOIN units u ON u.society_id = r.society_id AND u.id = r.unit_id"
                " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
                " WHERE r.gate_id = :g GROUP BY r.unit_id, u.label, b.name ORDER BY last_at DESC LIMIT :n"
            ),
            {"g": gate_id, "n": limit},
        ).mappings()
        items = [
            {
                "unit_id": r["unit_id"],
                "block_name": r["block_name"],
                "unit_label": r["label"],
                "last_at": r["last_at"],
            }
            for r in rows
        ]
    return {"items": items}
