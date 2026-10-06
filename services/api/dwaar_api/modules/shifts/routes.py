"""HTTP routes of the shifts module (PRD 9.6 SHIFT-01/02, UX-08, UX-09; GATE-09/GATE-11 shift context).

REQ: SHIFT-01, SHIFT-02, UX-08, UX-09, Appendix C, INV-08 (no route can lock or block anything), INV-01 (society from ``X-Society-Id``; another
society's id answers exactly like a random one), PRD 12.2 errors, cursor pagination.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import NotFound

from ...core.authz import AuthContext, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import PageParams, Paginator, get_paginator, page_params
from . import service
from .config import DEFAULT_CONFIG, ShiftsConfig
from .permissions import GUARD, SUPERVISORS
from .schemas import (
    HandoverAck,
    OverrideGrant,
    ProfilePut,
    ShiftCreate,
    ShiftEnd,
    ShiftStart,
    TrainingRecord,
)

router = APIRouter(prefix="/v1", tags=["shifts"])


def config(request: Request) -> ShiftsConfig:
    cfg = getattr(request.app.state, "shifts_config", None)
    return cfg if isinstance(cfg, ShiftsConfig) else DEFAULT_CONFIG


def _own_only(auth: AuthContext) -> uuid.UUID | None:
    """A guard sees only its own shifts and handovers; supervisors and society roles see all."""
    return auth.principal.person_id if auth.scope.role == GUARD else None


def _self_or_supervisor(auth: AuthContext, person_id: uuid.UUID) -> None:
    if auth.scope.role == GUARD and person_id != auth.principal.person_id:
        raise NotFound()


# ------------------------------------------------------------------------------------------ guard profile and training
# REQ: UX-08
@router.put("/guards/{person_id}/profile")
def put_profile(
    person_id: uuid.UUID,
    body: ProfilePut,
    auth: Annotated[AuthContext, Depends(require("guard.profile.write"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The guard's language, chosen per guard. English, Hindi, Marathi at M1; Kannada is refused until M2."""
    _self_or_supervisor(auth, person_id)
    return idem.run(auth, lambda conn: service.put_profile(conn, auth.ctx, person_id, body))


@router.get("/guards/{person_id}/profile")
def get_profile(
    person_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("guard.profile.read"))]
) -> dict[str, Any]:
    _self_or_supervisor(auth, person_id)
    with auth.tx() as conn:
        service.require_guard(conn, person_id)
        return service.profile_view(conn, person_id)


# REQ: UX-09
@router.post("/guards/{person_id}/training", status_code=201)
def record_training(
    person_id: uuid.UUID,
    body: TrainingRecord,
    auth: Annotated[AuthContext, Depends(require("guard.training.record"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A practice-mode completion (dummy units) for one scenario type. Practice data only."""
    _self_or_supervisor(auth, person_id)
    return idem.run(
        auth,
        lambda conn: service.record_training(conn, auth.ctx, person_id, body.scenario_type),
        status_code=201,
    )


@router.get("/guards/{person_id}/training")
def get_training(
    person_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("guard.profile.read"))]
) -> dict[str, Any]:
    _self_or_supervisor(auth, person_id)
    with auth.tx() as conn:
        service.require_guard(conn, person_id)
        return service.training_status(conn, person_id)


# ------------------------------------------------------------------------------------------ shifts
# REQ: SHIFT-01
@router.post("/shifts", status_code=201)
def create_shift(
    body: ShiftCreate,
    auth: Annotated[AuthContext, Depends(require("shift.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: service.create_shift(conn, auth.ctx, body), status_code=201)


@router.get("/shifts")
def list_shifts(
    auth: Annotated[AuthContext, Depends(require("shift.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[Literal["scheduled", "active", "ended"] | None, Query()] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.list_shifts(
            conn,
            paginator,
            page,
            society_id=auth.scope.society_id,
            own_only=_own_only(auth),
            gate_id=gate_id,
            state=state,
        )


# REQ: GATE-09, GATE-11
@router.get("/shifts/current")
def current_shift(
    auth: Annotated[AuthContext, Depends(require("shift.operate"))],
    cfg: Annotated[ShiftsConfig, Depends(config)],
) -> dict[str, Any]:
    """The caller's ACTIVE shift and its context: the pending queue, parcels, inside records, open incidents, overstay alerts, language."""
    with auth.tx() as conn:
        assert auth.principal.person_id is not None  # noqa: S101
        return service.current_context(conn, auth.principal.person_id, cfg)


@router.get("/shifts/{shift_id}")
def get_shift(
    shift_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("shift.read"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        owner = service.shift_owner(conn, shift_id)
        own = _own_only(auth)
        if owner is None or (own is not None and owner != own):
            raise NotFound()
        return service.get_shift(conn, shift_id)


def _may_operate(auth: AuthContext, owner: uuid.UUID | None) -> None:
    if owner is None or (auth.scope.role not in SUPERVISORS and owner != auth.principal.person_id):
        raise NotFound()


# REQ: SHIFT-01
@router.post("/shifts/{shift_id}/start")
def start_shift(
    shift_id: uuid.UUID,
    body: ShiftStart,
    auth: Annotated[AuthContext, Depends(require("shift.operate"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[ShiftsConfig, Depends(config)],
) -> JSONResponse:
    """Start the OWN shift with the start checklist (what the terminal reports plus what the server knows). The checklist never blocks."""

    def work(conn: Any) -> dict[str, Any]:
        _may_operate(auth, service.shift_owner(conn, shift_id))
        return service.start_shift(conn, auth.ctx, shift_id, body.checklist, cfg=cfg)

    return idem.run(auth, work)


# REQ: SHIFT-01
@router.post("/shifts/{shift_id}/end")
def end_shift(
    shift_id: uuid.UUID,
    body: ShiftEnd,
    auth: Annotated[AuthContext, Depends(require("shift.operate"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[ShiftsConfig, Depends(config)],
) -> JSONResponse:
    """End the shift: end checklist (parcels counted, inside records reviewed), overrides expire, the handover is created. A missing next
    guard never blocks this and never locks anything: the handover simply escalates later (INV-08)."""

    def work(conn: Any) -> dict[str, Any]:
        _may_operate(auth, service.shift_owner(conn, shift_id))
        return service.end_shift(conn, auth.ctx, shift_id, body.checklist, cfg=cfg)

    return idem.run(auth, work)


# REQ: Appendix C
@router.post("/shifts/{shift_id}/overrides", status_code=201)
def grant_override(
    shift_id: uuid.UUID,
    body: OverrideGrant,
    auth: Annotated[AuthContext, Depends(require("shift.override.grant"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[ShiftsConfig, Depends(config)],
) -> JSONResponse:
    """A supervisor override valid until the shift ends or earlier (the cap is the shift's planned end; ending the shift revokes it)."""
    return idem.run(
        auth,
        lambda conn: service.grant_override(conn, auth.ctx, shift_id, body, cfg),
        status_code=201,
    )


# ------------------------------------------------------------------------------------------ handovers
@router.get("/handovers")
def list_handovers(
    auth: Annotated[AuthContext, Depends(require("shift.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[Literal["pending", "acknowledged", "escalated"] | None, Query()] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.list_handovers(
            conn,
            paginator,
            page,
            society_id=auth.scope.society_id,
            own_only=_own_only(auth),
            state=state,
            gate_id=gate_id,
        )


# REQ: SHIFT-02
@router.get("/handovers/{handover_id}")
def get_handover(
    handover_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("shift.read"))]
) -> dict[str, Any]:
    """The handover: any summary FIRST, the deterministic open items ALWAYS after it (``display_order``)."""
    with auth.tx() as conn:
        parties = service.handover_parties(conn, handover_id)
        own = _own_only(auth)
        if parties is None or (own is not None and own not in parties):
            raise NotFound()
        return service.get_handover(conn, handover_id)


# REQ: SHIFT-01
@router.post("/handovers/{handover_id}/acknowledge")
def acknowledge_handover(
    handover_id: uuid.UUID,
    body: HandoverAck,
    auth: Annotated[AuthContext, Depends(require("shift.handover.acknowledge"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The outgoing guard, the incoming guard (the handover is signed when BOTH have), or the supervisor (signs alone)."""
    return idem.run(
        auth, lambda conn: service.acknowledge(conn, auth.ctx, handover_id, body.expected_version)
    )
