"""HTTP routes of the helpdesk (PRD 12: ``POST /v1/tickets``, ``POST /v1/tickets/{id}/merge``; the society is named by
``X-Society-Id`` exactly like the other ``/v1/<noun>`` routes, and validated against the caller's grants).

REQ: OPS-01..OPS-04, OPS-09, UX-07, INV-01 (a foreign or unknown id is the same 404 ``not_found``), INV-07, PRD 12.2.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound

from ...core.authn import Principal, current_principal
from ...core.authz import AuthContext, Scope, ScopeKind, require
from ...core.db import RequestContext
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import (
    FilterDef,
    PageParams,
    Paginator,
    SortColumn,
    get_paginator,
    page_params,
    parse_filters,
)
from ..identity import store as identity_store
from . import service, views
from . import settings as settings_mod
from .schemas import (
    AssignIn,
    EmergencyProcedureIn,
    Hazard,
    MergeIn,
    Note,
    PriorityIn,
    ReasonIn,
    SettingsIn,
    SupportRequestCreate,
    TicketCreate,
    TransitionIn,
    TriageIn,
)
from .views import Actor

router = APIRouter(prefix="/v1", tags=["helpdesk"])

_FILTERS = {
    "state": FilterDef("enum", frozenset({"draft", "submitted", "triaged", "assigned", "in_progress", "awaiting_material",
                                          "awaiting_resident", "resolved", "closed", "cancelled"})),
    "scope": FilterDef("enum", frozenset({"private", "block", "society"})),
    "priority": FilterDef("enum", frozenset({"emergency", "urgent", "normal", "low"})),
    "category": FilterDef("str", max_length=30),
    "unit_id": FilterDef("uuid"),
    "mine": FilterDef("bool"),
    "hazard": FilterDef("bool"),
}  # fmt: skip


def actor_of(auth: AuthContext) -> Actor:
    return Actor(
        auth.principal.person_id, auth.scope.role, auth.scope.society_wide, auth.scope.unit_ids
    )


def _sys_ctx(auth: AuthContext) -> RequestContext:
    return RequestContext(auth.scope.society_id, None, "system", auth.request_id)


def _emergency_block(conn: Connection, result: dict[str, Any]) -> dict[str, Any] | None:
    hazard = result["hazard"]
    if hazard is None:
        return None
    return {
        "hazard_kind": hazard.kind,
        "rule": hazard.rule,
        "emergency": hazard.emergency,
        "routing": "qualified_contractor",
        "procedure": result["procedure"],
        "no_rescue_guarantee": True,
        "no_repair_instructions": True,
    }


def _created_body(conn: Connection, auth: AuthContext, result: dict[str, Any]) -> dict[str, Any]:
    actor = actor_of(auth)
    t = result["ticket"]
    block = _emergency_block(conn, result)
    if actor.role == "guard":  # GUARD is create-only (PRD 5.2): the id and the state, nothing else
        return {"id": t["id"], "ticket_no": t["ticket_no"], "state": t["state"], "emergency": block}
    aud = "manager" if actor.is_manager else "household"
    return {
        "ticket": views.view(t, aud, actor),
        "emergency": block,
        "possible_duplicates": result["duplicates"],
    }


# REQ: OPS-01, OPS-02, OPS-03, OPS-09
@router.post("/tickets", status_code=201)
def create_ticket(
    body: TicketCreate,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.create"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Standard form, no AI needed. Unsafe lift/electrical/gas/fire observations return the site emergency procedure in THIS
    response and are submitted at once as emergencies; duplicates are only PROPOSED, from the same scope or household."""

    def work(conn: Connection) -> dict[str, Any]:
        result = service.create_ticket(conn, auth.ctx, actor_of(auth), body)
        return _created_body(conn, auth, result)

    return idem.run(auth, work, status_code=201)


@router.get("/tickets")
def list_tickets(
    request: Request,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    f = parse_filters(dict(request.query_params), _FILTERS)
    actor = actor_of(auth)
    with auth.tx() as conn:
        service.sweep_closures(conn, _sys_ctx(auth))
        blocks = views.my_blocks(conn, actor)
        where, params = views.list_filter(actor, blocks)
        for name, col in (
            ("state", "state"),
            ("scope", "scope"),
            ("priority", "priority"),
            ("category", "category"),
            ("unit_id", "unit_id"),
        ):
            if name in f:
                where.append(f"t.{col} = :f_{name}")
                params[f"f_{name}"] = f[name]
        if f.get("mine"):
            where.append("t.raised_by = :me")
        if f.get("hazard"):
            where.append("t.hazard_kind IS NOT NULL")
        result = paginator.fetch(
            conn,
            select_sql=service.TICKET_SELECT,
            where=where, params=params,
            sort=[SortColumn("t.created_at", "timestamptz", nullable=False), SortColumn("t.id", "uuid", nullable=False)],
            page=page, society_id=auth.scope.society_id, filters={**f, "_actor": str(actor.person_id)}, descending=True,
        )  # fmt: skip
        items = []
        for row in result.items:
            aud = views.audience(row, actor, blocks)
            if aud is not None:
                items.append(views.view(row, aud, actor))
    return {"items": items, "next_cursor": result.next_cursor}


def _visible(
    conn: Connection, auth: AuthContext, ticket_id: uuid.UUID
) -> tuple[dict[str, Any], str]:
    t = service.fetch_ticket(conn, ticket_id)
    if t is None:
        raise NotFound()
    actor = actor_of(auth)
    aud = views.audience(t, actor, views.my_blocks(conn, actor))
    if aud is None:
        raise NotFound()
    return t, aud


@router.get("/tickets/{ticket_id}")
def get_ticket(
    ticket_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.read"))]
) -> dict[str, Any]:
    actor = actor_of(auth)
    with auth.tx() as conn:
        service.sweep_closures(conn, _sys_ctx(auth))
        t, aud = _visible(conn, auth, ticket_id)
        body = {
            "ticket": views.view(t, aud, actor),
            "events": service.events_of(conn, ticket_id, status_only=aud == "common"),
        }
        if aud != "common":
            body["possible_duplicates"] = service.duplicate_proposals(conn, ticket_id)
    return body


@router.get("/tickets/{ticket_id}/sla")
def get_sla(
    ticket_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("helpdesk.sla.read"))]
) -> dict[str, Any]:
    """Clocks, pause log (reason and approver), breaches and the immutable priority history (OPS-01)."""
    actor = actor_of(auth)
    with auth.tx() as conn:
        t, aud = _visible(conn, auth, ticket_id)
        if aud != "manager":
            raise NotFound()
        return {"ticket": views.view(t, aud, actor), **service.sla_history(conn, ticket_id)}


def _act(
    auth: AuthContext,
    idem: IdempotentCall,
    fn: Any,
    ticket_id: uuid.UUID,
    body: Any,
    *,
    status_code: int = 200,
) -> JSONResponse:
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        t = fn(conn, auth.ctx, actor, ticket_id, body)
        aud = "manager" if actor.is_manager else "household"
        return {"ticket": views.view(t, aud, actor)}

    return idem.run(auth, work, status_code=status_code)


@router.post("/tickets/{ticket_id}/submit")
def submit_ticket(
    ticket_id: uuid.UUID,
    body: Note,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.act"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """OPS-03: the resident confirms a draft; the clocks start now."""
    return _act(auth, idem, service.submit_ticket, ticket_id, body)


@router.post("/tickets/{ticket_id}/acknowledge")
def acknowledge_ticket(
    ticket_id: uuid.UUID,
    body: Note,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return _act(auth, idem, service.acknowledge, ticket_id, body)


@router.post("/tickets/{ticket_id}/triage")
def triage_ticket(
    ticket_id: uuid.UUID,
    body: TriageIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return _act(auth, idem, service.triage, ticket_id, body)


@router.post("/tickets/{ticket_id}/assign")
def assign_ticket(
    ticket_id: uuid.UUID,
    body: AssignIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Hazard and beyond-competence work needs ``contractor_name`` (qualified contractor), never in-house staff (OPS-09)."""
    return _act(auth, idem, service.assign, ticket_id, body)


@router.post("/tickets/{ticket_id}/transition")
def transition_ticket(
    ticket_id: uuid.UUID,
    body: TransitionIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return _act(auth, idem, service.transition, ticket_id, body)


@router.post("/tickets/{ticket_id}/priority")
def change_priority(
    ticket_id: uuid.UUID,
    body: PriorityIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """History is append-only and the approver is recorded; a breach already recorded cannot be erased by this call."""
    return _act(auth, idem, service.change_priority, ticket_id, body)


@router.post("/tickets/{ticket_id}/respond")
def respond_ticket(
    ticket_id: uuid.UUID,
    body: Note,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.act"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return _act(auth, idem, service.respond, ticket_id, body)


@router.post("/tickets/{ticket_id}/confirm")
def confirm_ticket(
    ticket_id: uuid.UUID,
    body: Note,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.act"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """OPS-04: closure by the resident's confirmation."""
    return _act(auth, idem, service.confirm, ticket_id, body)


@router.post("/tickets/{ticket_id}/reopen")
def reopen_ticket(
    ticket_id: uuid.UUID,
    body: ReasonIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.act"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """OPS-04: within the reopen window; the original SLA history is retained."""
    return _act(auth, idem, service.reopen, ticket_id, body)


@router.post("/tickets/{ticket_id}/cancel")
def cancel_ticket(
    ticket_id: uuid.UUID,
    body: ReasonIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.act"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return _act(auth, idem, service.cancel, ticket_id, body)


# REQ: OPS-02
@router.post("/tickets/{ticket_id}/merge")
def merge_ticket(
    ticket_id: uuid.UUID,
    body: MergeIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.ticket.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Merge a duplicate into another ticket of the SAME scope or household; the merged ticket's text is not copied anywhere."""
    return _act(auth, idem, service.merge, ticket_id, body)


# ------------------------------------------------------------------------------------------ configuration
@router.get("/helpdesk/settings")
def get_settings(
    auth: Annotated[AuthContext, Depends(require("helpdesk.settings.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return settings_mod.ensure_settings(conn, auth.ctx).view()


@router.put("/helpdesk/settings")
def put_settings(
    body: SettingsIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.settings.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: settings_mod.update_settings(conn, auth.ctx, body))


@router.get("/helpdesk/emergency-procedures")
def get_procedures(
    auth: Annotated[AuthContext, Depends(require("helpdesk.emergency.read"))],
) -> dict[str, Any]:
    """OPS-09: the site procedure per hazard (and 'general'); an unconfigured hazard says so plainly."""
    with auth.tx() as conn:
        found = settings_mod.list_procedures(conn)
        return {
            h: settings_mod.procedure_for(conn, h, found)
            for h in ("lift", "electrical", "gas", "fire", "general")
        }


@router.put("/helpdesk/emergency-procedures/{hazard}")
def put_procedure(
    hazard: Hazard,
    body: EmergencyProcedureIn,
    auth: Annotated[AuthContext, Depends(require("helpdesk.emergency.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: settings_mod.put_procedure(conn, auth.ctx, hazard, body))


# ------------------------------------------------------------------------------------------ UX-07
def _request_uuid(request: Request) -> uuid.UUID:
    state = request.scope.get("state", {})
    return uuid.UUID(str(state.get("request_id")))


def _support_auth(
    request: Request, principal: Principal, society_id: uuid.UUID
) -> tuple[AuthContext, uuid.UUID]:
    """UX-07: ANY person with a pending, disputed, re-verifying or verified membership in the society may raise a support or
    privacy issue about it. Standing is read from the database (the access overview), never from the token; anyone without
    a membership in this society gets the same 404 as for an unknown society."""
    db = request.app.state.db
    with db.app_tx(RequestContext(person_id=principal.person_id)) as conn:
        rows = identity_store.access_overview(conn, principal.person_id)
    units = sorted(
        {r.unit_id for r in rows if r.source_kind == "membership" and r.society_id == society_id and r.unit_id is not None
         and r.verification in {"pending", "disputed", "reverification", "verified"}},
        key=lambda u: u.int,
    )  # fmt: skip
    if not units:
        raise NotFound()
    scope = Scope(
        society_id=society_id,
        role="applicant",
        kind=ScopeKind.UNIT,
        unit_id=None,
        unit_ids=frozenset(units),
    )
    permission = request.app.state.permissions.get("helpdesk.support.create")
    return AuthContext(principal, scope, permission, _request_uuid(request), db), units[0]


@router.post("/societies/{society_id}/support-requests", status_code=201)
def create_support_request(
    society_id: uuid.UUID,
    body: SupportRequestCreate,
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """UX-07: works while the membership is pending or DISPUTED. A private, household-level ticket visible to its raiser and
    the secretary only; it never appears in duplicate proposals."""
    auth, default_unit = _support_auth(request, principal, society_id)
    unit = body.unit_id or default_unit
    if unit not in auth.scope.unit_ids:
        raise NotFound()
    actor = Actor(principal.person_id, "applicant", False, auth.scope.unit_ids)

    def work(conn: Connection) -> dict[str, Any]:
        result = service.create_support_request(conn, auth.ctx, actor, unit, body)
        return {
            "ticket": views.view(result["ticket"], "household", actor),
            "emergency": _emergency_block(conn, result),
        }

    return idem.run(auth, work, status_code=201)


@router.get("/societies/{society_id}/support-requests")
def list_support_requests(
    society_id: uuid.UUID,
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    auth, _unit = _support_auth(request, principal, society_id)
    actor = Actor(principal.person_id, "applicant", False, auth.scope.unit_ids)
    with auth.tx() as conn:
        rows = conn.execute(
            text(
                f"{service.TICKET_SELECT} WHERE t.raised_by = :me AND t.category = 'support_privacy'"  # noqa: S608
                " ORDER BY t.created_at DESC, t.id DESC LIMIT :n"
            ),
            {"me": principal.person_id, "n": limit},
        ).mappings()
        items = [views.view(dict(r), "household", actor) for r in rows]
    return {"items": items}
