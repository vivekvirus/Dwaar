"""HTTP routes: gates, lanes, devices (enrolment request + supervisor approval), gate policy.

REQ: SOC-05 (subset), GATE-11, PRD 12.1 (device enrolment: supervisor-approved, one society), INV-01 (society from the
validated path, never a body), PRD 12 (Idempotency-Key on command creation and approvals).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from dwaar_common.errors import NotFound

from ...core.authz import AuthContext, idempotency_exempt, require
from ...core.idempotency import IdempotentCall, idempotency_required
from . import gates
from . import policy as policy_mod
from .schemas import DeviceDecision, DeviceEnrol, DeviceRevoke, GateCreate, LaneCreate, PolicyPut

router = APIRouter(prefix="/v1", tags=["gates"])


# REQ: GATE-01
@router.post("/societies/{society_id}/gates", status_code=201)
def create_gate(
    society_id: uuid.UUID,
    body: GateCreate,
    auth: Annotated[AuthContext, Depends(require("gate.configure"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(
        auth,
        lambda conn: gates.create_gate(conn, auth.ctx, auth.scope.society_id, body),
        status_code=201,
    )


@router.get("/societies/{society_id}/gates")
def list_gates(
    society_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("gate.configure.read"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {"items": gates.list_gates(conn)}


@router.post("/societies/{society_id}/gates/{gate_id}/lanes", status_code=201)
def create_lane(
    society_id: uuid.UUID,
    gate_id: uuid.UUID,
    body: LaneCreate,
    auth: Annotated[AuthContext, Depends(require("gate.configure"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(
        auth,
        lambda conn: gates.create_lane(conn, auth.ctx, auth.scope.society_id, gate_id, body),
        status_code=201,
    )


@router.get("/societies/{society_id}/gates/{gate_id}/lanes")
def list_lanes(
    society_id: uuid.UUID,
    gate_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.configure.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {"items": gates.list_lanes(conn, gate_id)}


# ------------------------------------------------------------------------------------------ policy
@router.get("/societies/{society_id}/gate-policy")
def get_policy(
    society_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("gate.configure.read"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return policy_mod.load_policy(conn).as_view()


# REQ: GATE-02, GATE-11
@router.put(
    "/societies/{society_id}/gate-policy",
    dependencies=[
        Depends(
            idempotency_exempt(
                "PUT sets absolute state guarded by expected_version: a replay is a 409"
            )
        )
    ],
)
def put_policy(
    society_id: uuid.UUID,
    body: PolicyPut,
    auth: Annotated[AuthContext, Depends(require("gate.configure"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return gates.put_policy(conn, auth.ctx, auth.scope.society_id, body)


# ------------------------------------------------------------------------------------------ devices
# REQ: SOC-05
@router.post("/societies/{society_id}/devices", status_code=201)
def enrol_device(
    society_id: uuid.UUID,
    body: DeviceEnrol,
    auth: Annotated[AuthContext, Depends(require("gate.device.request"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(
        auth,
        lambda conn: gates.enrol_device(conn, auth.ctx, auth.scope.society_id, body),
        status_code=201,
    )


@router.get("/societies/{society_id}/devices")
def list_devices(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.device.read"))],
    state: Annotated[
        Literal["pending_approval", "active", "rejected", "revoked"] | None, Query()
    ] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {"items": gates.list_devices(conn, state)}


@router.get("/societies/{society_id}/devices/{device_id}")
def get_device(
    society_id: uuid.UUID,
    device_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.device.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        device = gates.fetch_device(conn, device_id)
    if device is None:
        raise NotFound()
    return gates.device_view(device)


@router.post("/societies/{society_id}/devices/{device_id}/decision")
def decide_device(
    society_id: uuid.UUID,
    device_id: uuid.UUID,
    body: DeviceDecision,
    auth: Annotated[AuthContext, Depends(require("gate.device.decide"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: gates.decide_device(conn, auth.ctx, device_id, body))


@router.post("/societies/{society_id}/devices/{device_id}/revoke")
def revoke_device(
    society_id: uuid.UUID,
    device_id: uuid.UUID,
    body: DeviceRevoke,
    auth: Annotated[AuthContext, Depends(require("gate.device.decide"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: gates.revoke_device(conn, auth.ctx, device_id, body))
