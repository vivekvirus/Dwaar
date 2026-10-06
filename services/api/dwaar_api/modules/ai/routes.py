"""HTTP routes of the AI module (PRD 12.1: POST /v1/ai/proposals, POST /v1/ai/proposals/{id}/confirm, POST /v1/ai/feedback; plus read/admin routes).

The society comes from ``X-Society-Id`` (validated against the caller's grants, ADR-0006), never from a body. Writes carry ``Idempotency-Key``.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_ai_gateway.asr import asr_status
from dwaar_ai_gateway.config import SUBPROCESSORS
from dwaar_ai_gateway.guardrails import EXCLUDED_AI, GUARDRAILS
from dwaar_common.errors import NotFound

from ...core.authz import AuthContext, require
from ...core.idempotency import IdempotentCall, idempotency_required
from . import service
from .ports import AiRuntime
from .schemas import ConfirmBody, ControlsPut, FeedbackBody, ProposalCreate

router = APIRouter(prefix="/v1/ai", tags=["ai"])


def runtime(request: Request) -> AiRuntime:
    rt = getattr(request.app.state, "ai", None)
    if not isinstance(rt, AiRuntime):
        raise NotFound()
    return rt


Auth = Annotated[AuthContext, Depends(require("ai.use"))]
Rt = Annotated[AiRuntime, Depends(runtime)]


# REQ: AI-SYS-08, G3, G8, PRD 11.1 (what exists, for whom, and what is honestly unavailable)
@router.get("/features")
def list_features(auth: Auth, rt: Rt) -> dict[str, Any]:
    items = []
    with auth.tx() as conn:
        for h in rt.gateway.features():
            s = h.spec
            if auth.scope.role not in s.roles:
                continue
            av = service.availability(conn, auth.scope.society_id, s.id, s.uses_model)
            items.append({
                "id": s.id, "name": s.name, "risk_class": s.risk_class.value, "milestone": s.milestone, "uses_model": s.uses_model,
                "available": s.available and av.allowed and (av.budget_ok or not s.uses_model), "unavailable_reason": s.unavailable_reason or av.reason
                or (None if av.budget_ok or not s.uses_model else "budget_exhausted"),
                "command": s.command, "summary_key": s.summary_key, "input_schema": dict(s.input_schema), "g3_basis": s.g3_basis,
            })  # fmt: skip
    return {
        "request_id": str(auth.request_id), "items": items, "optional": True, "declining_ai_reduces_service": False,
        "labelling": "Every AI output is labelled 'AI draft' with sources, what will be saved and a way to correct it.",
        "guardrails": dict(GUARDRAILS), "excluded_ai": [e["id"] for e in EXCLUDED_AI],
        "subprocessors": [{k: v for k, v in x.items() if k != "enabled_by"} for x in SUBPROCESSORS], "training_on_customer_data": False,
    }  # fmt: skip


# REQ: PRD 12.1 'POST /v1/ai/proposals: intent and scoped inputs -> draft or proposal; no direct privileged execution'
@router.post("/proposals")
def create_proposal(
    body: ProposalCreate,
    auth: Auth,
    rt: Rt,
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: service.create(conn, auth, rt, body))


@router.get("/proposals")
def list_proposals(
    auth: Auth,
    state: Annotated[
        Literal["proposed", "confirmed", "rejected", "expired", "failed"] | None, Query()
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {
            "request_id": str(auth.request_id),
            "items": service.list_proposals(conn, auth, state, limit),
        }


@router.get("/proposals/{proposal_id}")
def get_proposal(proposal_id: uuid.UUID, auth: Auth) -> dict[str, Any]:
    with auth.tx() as conn:
        return {
            "request_id": str(auth.request_id),
            **service.proposal_view(service.get_proposal(conn, auth, proposal_id)),
        }


# REQ: PRD 12.1 'POST /v1/ai/proposals/{id}/confirm: payload hash, versions -> deterministic command result; re-validates permission and target state'
@router.post("/proposals/{proposal_id}/confirm")
def confirm_proposal(
    proposal_id: uuid.UUID,
    body: ConfirmBody,
    auth: Auth,
    rt: Rt,
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: service.confirm(conn, auth, rt, proposal_id, body))


# REQ: PRD 12.1 'POST /v1/ai/feedback: run id, outcome, correction -> stored; feeds evaluation'
@router.post("/feedback")
def post_feedback(
    body: FeedbackBody, auth: Auth, idem: Annotated[IdempotentCall, Depends(idempotency_required)]
) -> JSONResponse:
    return idem.run(auth, lambda conn: service.feedback(conn, auth, body))


@router.get("/drafts")
def list_drafts(auth: Auth, limit: Annotated[int, Query(ge=1, le=100)] = 50) -> dict[str, Any]:
    with auth.tx() as conn:
        return {"request_id": str(auth.request_id), "items": service.list_drafts(conn, auth, limit)}


# ------------------------------------------------------------------------------------------------ administration
@router.get("/status")
def get_status(
    auth: Annotated[AuthContext, Depends(require("ai.status.read"))], rt: Rt
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.status(conn, auth, rt)


@router.put("/controls")
def put_controls(
    body: ControlsPut,
    auth: Annotated[AuthContext, Depends(require("ai.controls.manage"))],
    rt: Rt,
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: service.put_controls(conn, auth, rt, body))


@router.get("/runs")
def list_runs(
    auth: Annotated[AuthContext, Depends(require("ai.audit.read"))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before: Annotated[uuid.UUID | None, Query()] = None,
    feature_id: Annotated[str | None, Query(pattern=r"^AI-[A-Z][0-9]{2}$")] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {
            "request_id": str(auth.request_id),
            **service.list_runs(conn, auth, limit, before, feature_id),
        }


@router.get("/providers")
def get_providers(
    auth: Annotated[AuthContext, Depends(require("ai.providers.read"))], rt: Rt
) -> dict[str, Any]:
    """Adapter table INCLUDING the missing dependency ('not configured: ...'). Authorised admins only; never the key itself."""
    gw = rt.gateway
    return {
        "request_id": str(auth.request_id), "gateway": gw.config.public_view(), "providers": gw.providers.status(), "asr": asr_status(),
        "subprocessors": gw.providers.subprocessors(), "models": {"extraction": "claude-haiku-4-5-20251001", "drafting": "claude-sonnet-5-5", "complex": "claude-opus-5-5 (only where Sonnet fails evaluation)"},
        "note": "no model quality is measured by the simulator; the Anthropic adapter is untested against the live API",
    }  # fmt: skip
