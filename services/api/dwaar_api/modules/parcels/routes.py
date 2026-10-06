"""HTTP routes of the parcels module (PRD 9.5, PRD 12.1 ``POST /v1/parcels``, ``POST /v1/parcels/{id}/collect``).

REQ: PAR-01..PAR-05, PAR-08, INV-01 (the society comes from ``X-Society-Id`` / the grants, a unit in a body is validated against the
caller's coverage; another society's id answers exactly like a random one), INV-07, PRD 12.2 errors, cursor pagination.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import NotFound
from dwaar_common.timeutil import utc_now

from ...core.authz import AuthContext, idempotency_exempt, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import PageParams, Paginator, get_paginator, page_params
from ..visits.deps import audience as visits_audience
from ..visits.permissions import GATE_STAFF
from . import service
from .config import DEFAULT_CONFIG, ParcelsConfig
from .permissions import permissions as _permissions
from .schemas import (
    ConsentPut,
    CourierClaim,
    CustodyReportCreate,
    ExpectationCreate,
    ParcelCollect,
    ParcelReceive,
    ParcelResolve,
    ParcelStore,
    PickupTokenIssue,
)

router = APIRouter(prefix="/v1", tags=["parcels"])

_SUPERVISED = next(p for p in _permissions if p.action == "parcel.collect.supervised").roles
_LOST_ROLES = frozenset({"guard_sup", "secretary", "estate_mgr"})


def config(request: Request) -> ParcelsConfig:
    cfg = getattr(request.app.state, "parcels_config", None)
    return cfg if isinstance(cfg, ParcelsConfig) else DEFAULT_CONFIG


def _covered(auth: AuthContext, unit_id: uuid.UUID) -> None:
    if not auth.scope.covers_unit(unit_id):
        raise NotFound()


def _audience(role: str) -> str:
    return "guard" if role in GATE_STAFF else visits_audience(role)


# REQ: PAR-01
@router.post("/parcel-expectations", status_code=201)
def create_expectation(
    body: ExpectationCreate,
    auth: Annotated[AuthContext, Depends(require("parcel.expect"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The resident pre-approves a delivery by brand and time window for the OWN unit (a unit outside the caller's grants is 404)."""
    _covered(auth, body.unit_id)
    return idem.run(
        auth,
        lambda conn: service.create_expectation(conn, auth.ctx, body, now=utc_now()),
        status_code=201,
    )


# REQ: PAR-01
@router.delete(
    "/parcel-expectations/{parcel_id}",
    dependencies=[
        Depends(
            idempotency_exempt(
                "withdrawing is naturally idempotent: a second DELETE returns the cancelled expectation"
            )
        )
    ],
)
def cancel_expectation(
    parcel_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("parcel.expect"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.cancel_expectation(conn, auth.ctx, auth.scope, parcel_id)


# REQ: PAR-02
@router.post("/parcels", status_code=201)
def receive_parcel(
    body: ParcelReceive,
    auth: Annotated[AuthContext, Depends(require("parcel.handle"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The guard records a parcel at the gate (custody moves from the courier to the receiving guard). A pre-approval of the same unit
    and brand whose window contains now is matched automatically."""
    return idem.run(auth, lambda conn: service.receive(conn, auth.ctx, body), status_code=201)


@router.get("/parcels")
def list_parcels(
    auth: Annotated[AuthContext, Depends(require("parcel.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    state: Annotated[
        Literal[
            "expected", "received_at_gate", "stored", "pickup_pending", "collected", "refused", "returned",
            "lost_exception", "cancelled",
        ] | None,
        Query(),
    ] = None,
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:  # fmt: skip
    """The household sees the parcels of its own units; the guard the society's OPEN parcels (masked); society roles all of them."""
    with auth.tx() as conn:
        return service.list_parcels(
            conn, paginator, page, society_id=auth.scope.society_id, scope=auth.scope,
            audience=_audience(auth.scope.role), state=state, unit_id=unit_id,
        )  # fmt: skip


@router.get("/parcels/{parcel_id}")
def get_parcel(
    parcel_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("parcel.read"))]
) -> dict[str, Any]:
    """One parcel with its custody chain, its pickup attempts and the courier's claims (kept apart, labelled external)."""
    with auth.tx() as conn:
        unit = service.parcel_unit(conn, parcel_id)
        if unit is None or not auth.scope.covers_unit(unit):
            raise NotFound()
        return service.get_view(conn, parcel_id, _audience(auth.scope.role))


# REQ: PAR-02
@router.post("/parcels/{parcel_id}/store")
def store_parcel(
    parcel_id: uuid.UUID,
    body: ParcelStore,
    auth: Annotated[AuthContext, Depends(require("parcel.handle"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: service.store(conn, auth.ctx, parcel_id, body))


# REQ: PAR-03
@router.put("/parcels/{parcel_id}/leave-at-gate-consent")
def put_consent(
    parcel_id: uuid.UUID,
    body: ConsentPut,
    auth: Annotated[AuthContext, Depends(require("parcel.consent"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Grant or revoke leave-at-gate consent. It is explicit and revocable only BEFORE custody (409/422 afterwards)."""
    return idem.run(
        auth,
        lambda conn: service.put_consent(
            conn, auth.ctx, auth.scope, parcel_id, body.granted, body.expected_version
        ),
    )


# REQ: PAR-03
@router.post("/parcels/{parcel_id}/pickup-token")
def issue_pickup_token(
    parcel_id: uuid.UUID,
    body: PickupTokenIssue,
    auth: Annotated[AuthContext, Depends(require("parcel.pickup_token.issue"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[ParcelsConfig, Depends(config)],
) -> JSONResponse:
    """The household issues the SINGLE-USE pickup token (shown once; only its hash is stored). A family member needs delegated authority."""
    return idem.run(
        auth,
        lambda conn: service.issue_pickup_token(
            conn, auth.ctx, auth.scope, parcel_id, body.expected_version, cfg
        ),
    )


# REQ: PAR-03
@router.post("/parcels/{parcel_id}/collect")
def collect_parcel(
    parcel_id: uuid.UUID,
    body: ParcelCollect,
    auth: Annotated[AuthContext, Depends(require("parcel.handle"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Hand over against the single-use token, or (supervisor only) a supervised alternate proof. A second attempt is DENIED and
    recorded; the custody history is untouched (AT-13)."""
    try:
        return idem.run(
            auth,
            lambda conn: service.collect(
                conn, auth.ctx, auth.scope, parcel_id, body, supervised_roles=_SUPERVISED
            ),
        )
    except service.PickupDenied as denied:
        with (
            auth.tx() as conn
        ):  # the denied request rolled back: the attempt is appended in its own transaction
            service.record_denied_attempt(conn, auth.ctx, denied)
        raise denied.error from None


# REQ: PAR-02
@router.post("/parcels/{parcel_id}/resolve")
def resolve_parcel(
    parcel_id: uuid.UUID,
    body: ParcelResolve,
    auth: Annotated[AuthContext, Depends(require("parcel.resolve"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Refused, returned to the carrier, or lost_exception (supervisor or secretary only)."""
    return idem.run(
        auth,
        lambda conn: service.resolve(
            conn, auth.ctx, parcel_id, body, may_declare_lost=auth.scope.role in _LOST_ROLES
        ),
    )


# REQ: PAR-04
@router.post("/parcels/{parcel_id}/courier-claims", status_code=201)
def record_courier_claim(
    parcel_id: uuid.UUID,
    body: CourierClaim,
    auth: Annotated[AuthContext, Depends(require("parcel.handle"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Store what a courier SAYS as an external observation. It never changes the parcel's state or custody."""
    return idem.run(
        auth,
        lambda conn: service.record_courier_claim(conn, auth.ctx, parcel_id, body),
        status_code=201,
    )


# REQ: PAR-05
@router.post("/parcel-custody-reports", status_code=201)
def create_custody_report(
    body: CustodyReportCreate,
    auth: Annotated[AuthContext, Depends(require("parcel.report.create"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The physical count is reconciled against what the system says the society holds; a discrepancy is reported, never auto-resolved."""
    return idem.run(
        auth, lambda conn: service.create_custody_report(conn, auth.ctx, body), status_code=201
    )


@router.get("/parcel-custody-reports")
def list_custody_reports(
    auth: Annotated[AuthContext, Depends(require("parcel.report.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.list_reports(conn, paginator, page, society_id=auth.scope.society_id)
