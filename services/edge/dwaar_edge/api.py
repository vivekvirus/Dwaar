"""Authenticated local API for guard terminals (the ONLY way terminals touch gateway state).

REQ: EDGE-01 (one process owns writes; terminals use an authenticated local API; they never open the SQLite file),
EDGE-09 (no inbound internet ports: bind to the security LAN address only; mTLS/pinning belongs to deployment),
GATE-06, GATE-07, GATE-05, NFR-04 (LAN propagation via the feed), Appendix C (overrides expire at shift end).

Authentication: ``Authorization: Bearer <signed terminal token>`` issued at commissioning. Errors carry a stable
``code`` and a request id and never echo credentials.
"""

# REQ: EDGE-01, EDGE-09, GATE-05, GATE-06, GATE-07, NFR-04

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from dwaar_common.ids import uuid7

from .errors import (
    ConflictError,
    EdgeError,
    InvalidRequest,
    NotAuthorisedError,
    PolicyRejected,
    TombstonesRequired,
)
from .gateway import Actor, Gateway


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvaluateIn(_In):
    gate_id: uuid.UUID
    lane_id: uuid.UUID
    credential: dict[str, Any]
    client_action_id: uuid.UUID | None = None


class EntryIn(_In):
    gate_id: uuid.UUID
    lane_id: uuid.UUID
    evaluation_id: str | None = None
    pending_id: str | None = None
    alias: str | None = Field(default=None, max_length=80)
    client_action_id: uuid.UUID | None = None


class ExitIn(_In):
    gate_id: uuid.UUID
    lane_id: uuid.UUID
    movement_id: uuid.UUID | None = None
    invitation_id: uuid.UUID | None = None
    basis: Literal["scanned", "observed"] = "observed"
    client_action_id: uuid.UUID | None = None


class GuardDecisionIn(_In):
    pending_id: str
    resolution: str
    note: str | None = Field(default=None, max_length=200)
    client_action_id: uuid.UUID | None = None


class OverrideIn(_In):
    supervisor_ref: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=3, max_length=200)
    shift_end: datetime
    gate_id: uuid.UUID | None = None
    client_action_id: uuid.UUID | None = None


class EmergencyIn(_In):
    gate_id: uuid.UUID
    lane_id: uuid.UUID | None = None
    authority: str = Field(min_length=1, max_length=60)
    reason: str = Field(min_length=3, max_length=200)
    client_action_id: uuid.UUID | None = None


class FreshApprovalIn(_In):
    gate_id: uuid.UUID
    lane_id: uuid.UUID
    unit_id: uuid.UUID | None = None
    client_action_id: uuid.UUID | None = None


class ReconcileIn(_In):
    terminal_policy_seq: int = Field(ge=0)
    observations: list[dict[str, Any]] = Field(max_length=2000)


class AckIn(_In):
    seq: int = Field(ge=0)


_STATUS = {
    NotAuthorisedError: 403,
    ConflictError: 409,
    TombstonesRequired: 409,
    InvalidRequest: 422,
    PolicyRejected: 422,
}


class _Unauthenticated(Exception):
    pass


def actor_dep(request: Request, authorization: Annotated[str | None, Header()] = None) -> Actor:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _Unauthenticated
    gw: Gateway = request.app.state.gateway
    actor = gw.authenticate(authorization[7:].strip())
    if actor is None:
        raise _Unauthenticated
    return actor


Auth = Annotated[Actor, Depends(actor_dep)]


def create_app(gateway: Gateway) -> FastAPI:
    app = FastAPI(
        title="Dwaar edge gateway (local API)", docs_url=None, redoc_url=None, openapi_url=None
    )

    @app.exception_handler(EdgeError)
    async def _edge_error(request: Request, exc: EdgeError) -> JSONResponse:
        status = next((s for t, s in _STATUS.items() if isinstance(exc, t)), 400)
        if exc.code == "not_found":
            status = 404
        return JSONResponse(
            status_code=status,
            content={
                "code": exc.code,
                "message": str(exc),
                "request_id": str(uuid7()),
                "details": {},
            },
        )

    app.state.gateway = gateway

    @app.exception_handler(_Unauthenticated)
    async def _unauth(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={
                "code": "unauthenticated",
                "message": "authentication required",
                "request_id": str(uuid7()),
                "details": {},
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _gate_ok(actor: Actor, gate_id: uuid.UUID | None) -> None:
        """A guard terminal may act only for its assigned gate (when the signed policy assigns one)."""
        bundle = gateway.policy
        if bundle is None or gate_id is None or actor.role != "guard":
            return
        for dev in bundle.snapshot.manifest.devices:
            if dev.id == actor.device_id and dev.gate_id is not None and dev.gate_id != gate_id:
                raise NotAuthorisedError(
                    "terminal is not assigned to this gate", code="gate_mismatch"
                )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "dwaar-edge",
            "simulation": str(gateway.config.simulation).lower(),
        }

    @app.post("/v1/terminal/evaluate")
    def evaluate(body: EvaluateIn, actor: Auth) -> dict[str, Any]:
        _gate_ok(actor, body.gate_id)
        return gateway.evaluate(
            actor,
            gate_id=body.gate_id,
            lane_id=body.lane_id,
            credential=body.credential,
            client_action_id=body.client_action_id,
        )

    @app.post("/v1/terminal/entries")
    def entries(body: EntryIn, actor: Auth) -> dict[str, Any]:
        _gate_ok(actor, body.gate_id)
        return gateway.record_entry(
            actor,
            gate_id=body.gate_id,
            lane_id=body.lane_id,
            evaluation_id=body.evaluation_id,
            pending_id=body.pending_id,
            alias=body.alias,
            client_action_id=body.client_action_id,
        )

    @app.post("/v1/terminal/exits")
    def exits(body: ExitIn, actor: Auth) -> dict[str, Any]:
        _gate_ok(actor, body.gate_id)
        return gateway.record_exit(
            actor,
            gate_id=body.gate_id,
            lane_id=body.lane_id,
            movement_id=body.movement_id,
            invitation_id=body.invitation_id,
            basis=body.basis,
            client_action_id=body.client_action_id,
        )

    @app.post("/v1/terminal/fresh-approvals")
    def fresh(body: FreshApprovalIn, actor: Auth) -> dict[str, Any]:
        _gate_ok(actor, body.gate_id)
        return gateway.start_fresh_approval(
            actor,
            gate_id=body.gate_id,
            lane_id=body.lane_id,
            unit_id=body.unit_id,
            client_action_id=body.client_action_id,
        )

    @app.post("/v1/terminal/guard-decisions")
    def guard_decisions(body: GuardDecisionIn, actor: Auth) -> dict[str, Any]:
        return gateway.guard_decision(
            actor,
            pending_id=body.pending_id,
            resolution=body.resolution,
            note=body.note,
            client_action_id=body.client_action_id,
        )

    @app.post("/v1/terminal/overrides")
    def overrides(body: OverrideIn, actor: Auth) -> dict[str, Any]:
        return gateway.record_override(
            actor,
            supervisor_ref=body.supervisor_ref,
            reason=body.reason,
            shift_end=body.shift_end,
            gate_id=body.gate_id,
            client_action_id=body.client_action_id,
        )

    @app.post("/v1/terminal/emergency-entries")
    def emergency(body: EmergencyIn, actor: Auth) -> dict[str, Any]:
        _gate_ok(actor, body.gate_id)
        return gateway.emergency_entry(
            actor,
            gate_id=body.gate_id,
            lane_id=body.lane_id,
            authority=body.authority,
            reason=body.reason,
            client_action_id=body.client_action_id,
        )

    @app.get("/v1/terminal/pending")
    def pending(actor: Auth, gate_id: uuid.UUID | None = None) -> dict[str, Any]:
        return {"items": gateway.list_pending(gate_id)}

    @app.get("/v1/terminal/inside")
    def inside(actor: Auth, gate_id: uuid.UUID | None = None) -> dict[str, Any]:
        return gateway.list_inside(gate_id)

    @app.get("/v1/terminal/status")
    def status(actor: Auth) -> dict[str, Any]:
        return gateway.status()

    @app.get("/v1/terminal/feed")
    def feed(
        actor: Auth,
        after: Annotated[int, Query(ge=0)] = 0,
        wait_ms: Annotated[int, Query(ge=0, le=30_000)] = 0,
    ) -> dict[str, Any]:
        items = gateway.wait_feed(after, wait_ms / 1000.0) if wait_ms else gateway.feed_after(after)
        return {"items": items, "last_id": items[-1]["id"] if items else after}

    @app.get("/v1/terminal/cache/{gate_id}")
    def cache(gate_id: uuid.UUID, actor: Auth) -> dict[str, Any]:
        _gate_ok(actor, gate_id)
        return gateway.export_terminal_cache(gate_id)

    @app.get("/v1/terminal/tombstones")
    def tombstones(actor: Auth, after_seq: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        return gateway.tombstones_since(after_seq)

    @app.post("/v1/terminal/tombstones/ack")
    def tombstones_ack(body: AckIn, actor: Auth) -> dict[str, Any]:
        return gateway.ack_tombstones(actor, body.seq)

    @app.post("/v1/terminal/reconcile")
    def reconcile(body: ReconcileIn, actor: Auth) -> dict[str, Any]:
        return gateway.reconcile_standalone(
            actor, terminal_policy_seq=body.terminal_policy_seq, observations=body.observations
        )

    @app.get("/v1/terminal/review")
    def review(actor: Auth) -> dict[str, Any]:
        if actor.role not in ("supervisor", "admin"):
            raise NotAuthorisedError("supervisor only", code="supervisor_required")
        return {"items": gateway.review_items()}

    return app
