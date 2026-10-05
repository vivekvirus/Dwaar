"""HTTP routes: visits (register, history, detail), observations, stops, cancellation, exceptions.

REQ: GATE-04, GATE-05, GATE-07, GATE-11, GATE-13, INV-07, INV-01, PRD 12.1 (``POST /v1/visits/{id}/observations``: entry/exit,
gate, device, event id -> accepted event; observation never creates permission), PRD 5.2 ("Gate operations": the household of
the unit and society roles; guard = current-gate, active, masked), AT-02 (``GET /v1/societies/{id}/units/{unit_id}/visits``).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import InvalidSchema, NotAuthorised, NotFound

from ...core.authz import AuthContext, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import (
    DateRange,
    FilterDef,
    PageParams,
    Paginator,
    SortColumn,
    date_range_params,
    get_paginator,
    page_params,
    parse_filters,
)
from ..identity.access import authorize, clean_purpose, log_privileged_read
from . import approvals, common, exceptions, gates
from . import policy as policy_mod
from . import visits as visits_svc
from .config import VisitsConfig
from .deps import audience, visits_config
from .schemas import (
    ExceptionCreate,
    ExceptionTransition,
    ObservationIn,
    StopAdd,
    VisitCancel,
)

router = APIRouter(prefix="/v1", tags=["visits"])

_STATES = frozenset({"requested", "authorised", "inside", "exited", "cancelled", "expired"})
_KINDS = frozenset({"guest", "delivery", "service", "cab", "staff", "vendor"})
_FILTERS = {
    "state": FilterDef("enum", _STATES),
    "kind": FilterDef("enum", _KINDS),
}
_RESERVED = frozenset({"limit", "cursor", "from", "to", "purpose", "gate_id", "unit_id"})
_SORT = [
    SortColumn("v.created_at", "timestamptz", nullable=False),
    SortColumn("v.id", "uuid", nullable=False),
]


def _paged_visits(
    conn: Any,
    auth: AuthContext,
    paginator: Paginator,
    page: PageParams,
    *,
    where: list[str],
    params: dict[str, Any],
    filters: dict[str, Any],
    rng: DateRange,
    raw_range: dict[str, str],
) -> tuple[list[dict[str, Any]], str | None]:
    where = [*where, "v.created_at >= :_from", "v.created_at < :_to"]
    params = {**params, "_from": rng.start, "_to": rng.end}
    # a cursor is bound to the range the CLIENT asked for; a defaulted range ends at "now" and must not invalidate it
    filters = {**filters, **{f"range_{k}": v for k, v in raw_range.items()}}
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {common.VISIT_COLUMNS} FROM visits v",  # noqa: S608 (constant column list)
        where=where,
        params=params,
        sort=_SORT,
        page=page,
        society_id=auth.scope.society_id,
        filters=filters,
        descending=True,
    )
    return result.items, result.next_cursor


def _guard_gate(conn: Any, gate_id: uuid.UUID | None) -> uuid.UUID:
    """A guard names the gate they are standing at; it must be a gate of this society (RLS)."""
    if gate_id is None:
        raise InvalidSchema.for_fields([("gate_id", "required_for_guard")])
    gates.require_active_gate(conn, gate_id)
    return gate_id


# REQ: GATE-13, AT-02
@router.get("/societies/{society_id}/units/{unit_id}/visits")
def unit_visit_history(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("gate.history.read", unit_param="unit_id"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    rng: Annotated[DateRange, Depends(date_range_params)],
    purpose: Annotated[str | None, Query(max_length=200)] = None,
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """Visitor history of ONE unit (PRD 5.2 "Gate operations", own-unit read; AT-02).

    * the household that LIVES in the unit (occupying owner, tenant, family): all visits that stopped at the unit; other
      destinations of a multi-stop visit are not shown;
    * a non-resident owner: refused (403, or 404 when the unit is outside their covering grants): the tenant's private
      visitors are not theirs (PRD 5.1);
    * secretary, committee, estate manager: with a ``purpose`` (audited, IAM-04);
    * guard: only the CURRENT gate's ACTIVE visits (``gate_id`` required), masked.
    Cursor pagination, at most 100 rows, bounded date range (default 92 days)."""
    filters = parse_filters(dict(request.query_params), _FILTERS, reserved=_RESERVED)
    who = audience(auth.scope.role)
    where = [
        "EXISTS (SELECT 1 FROM visit_stops s WHERE s.society_id = v.society_id AND s.visit_id = v.id AND s.unit_id = :unit)"
    ]
    params: dict[str, Any] = {"unit": unit_id}
    key_filters: dict[str, Any] = {"unit": unit_id, **filters}
    for name, value in filters.items():
        where.append(f"v.{name} = :f_{name}")
        params[f"f_{name}"] = value
    with auth.tx() as conn:
        common.require_unit(conn, unit_id)
        approvals.expire_due_requests(conn, auth.ctx, unit_id=unit_id, limit=50)
        if who == "guard":
            gate = _guard_gate(conn, gate_id)
            where.append("v.state = ANY(:active) AND v.gate_id = :gate")
            params.update(active=list(common.ACTIVE_VISIT_STATES), gate=gate)
            key_filters["gate_id"] = gate
        elif who == "full":
            purpose = clean_purpose(purpose)
        rows, nxt = _paged_visits(
            conn,
            auth,
            paginator,
            page,
            where=where,
            params=params,
            filters=key_filters,
            rng=rng,
            raw_range={k: v for k, v in request.query_params.items() if k in ("from", "to")},
        )
        view = who
        items = common.visit_views(
            conn, rows, view=view, own_units=frozenset({unit_id}) if view == "household" else None
        )
        if who == "full":
            log_privileged_read(
                conn, auth.ctx, object_type="visit_history", purpose=purpose or "",
                scope={"unit_id": str(unit_id)}, returned=len(items),
            )  # fmt: skip
    return {"unit_id": unit_id, "view": view, "items": items, "next_cursor": nxt}


@router.get("/societies/{society_id}/visits")
def list_visits(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("gate.visit.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    rng: Annotated[DateRange, Depends(date_range_params)],
    purpose: Annotated[str | None, Query(max_length=200)] = None,
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """The society's visit register. Guard: the current gate's active visits, masked (``gate_id`` required). Secretary,
    committee and estate manager: everything, with a ``purpose`` (audited). Inside counts carry ``inside_confidence``."""
    filters = parse_filters(dict(request.query_params), _FILTERS, reserved=_RESERVED)
    who = audience(auth.scope.role)
    where: list[str] = []
    params: dict[str, Any] = {}
    key_filters: dict[str, Any] = dict(filters)
    for name, value in filters.items():
        where.append(f"v.{name} = :f_{name}")
        params[f"f_{name}"] = value
    with auth.tx() as conn:
        approvals.expire_due_requests(conn, auth.ctx, limit=50)
        if who == "guard":
            gate = _guard_gate(conn, gate_id)
            where.append("v.state = ANY(:active) AND v.gate_id = :gate")
            params.update(active=list(common.ACTIVE_VISIT_STATES), gate=gate)
            key_filters["gate_id"] = gate
        else:
            purpose = clean_purpose(purpose)
            if gate_id is not None:
                where.append("v.gate_id = :gate")
                params["gate"] = gate_id
                key_filters["gate_id"] = gate_id
        if unit_id is not None:
            where.append(
                "EXISTS (SELECT 1 FROM visit_stops s WHERE s.society_id = v.society_id AND s.visit_id = v.id AND s.unit_id = :unit)"
            )
            params["unit"] = unit_id
            key_filters["unit_id"] = unit_id
        rows, nxt = _paged_visits(
            conn,
            auth,
            paginator,
            page,
            where=where,
            params=params,
            filters=key_filters,
            rng=rng,
            raw_range={k: v for k, v in request.query_params.items() if k in ("from", "to")},
        )
        items = common.visit_views(conn, rows, view="guard" if who == "guard" else "full")
        if who != "guard":
            log_privileged_read(
                conn, auth.ctx, object_type="visit_register", purpose=purpose or "",
                scope={"unit_id": str(unit_id) if unit_id else None}, returned=len(items),
            )  # fmt: skip
    return {"items": items, "next_cursor": nxt}


@router.get("/visits/{visit_id}")
def get_visit(
    visit_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.history.read"))],
    purpose: Annotated[str | None, Query(max_length=200)] = None,
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """One visit (society chosen by ``X-Society-Id``), for the audience of the caller's role. A household sees a visit only if
    it has a stop at one of its units; a guard only an ACTIVE visit of the gate it names; others need a purpose."""
    who = audience(auth.scope.role)
    with auth.tx() as conn:
        row = visits_svc.fetch_visit_row(conn, visit_id)
        if row is None:
            raise NotFound()
        stops = common.fetch_stops(conn, [visit_id]).get(visit_id, [])
        if who == "household":
            own = frozenset(s["unit_id"] for s in stops if auth.scope.covers_unit(s["unit_id"]))
            if not own:
                raise NotFound()
            return common.visit_view(row, stops, view="household", own_units=own)
        if who == "guard":
            gate = _guard_gate(conn, gate_id)
            if row["gate_id"] != gate or row["state"] not in common.ACTIVE_VISIT_STATES:
                raise NotFound()
            return common.visit_view(row, stops, view="guard")
        purpose = clean_purpose(purpose)
        log_privileged_read(
            conn,
            auth.ctx,
            object_type="visit",
            purpose=purpose,
            scope={"visit_id": str(visit_id)},
            returned=1,
        )
        return common.visit_view(row, stops, view="full")


# REQ: INV-07, GATE-05
@router.post("/visits/{visit_id}/observations", status_code=201)
def record_observation(
    visit_id: uuid.UUID,
    body: ObservationIn,
    auth: Annotated[AuthContext, Depends(require("gate.visit.observe"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Record an ENTRY or EXIT observation (gate, device, event id, device sequence). It is a fact, appended; it never
    creates or widens permission. Exit: ``exit_basis`` is ``scanned``, ``observed`` or ``reconciled_unknown`` (then NO exit
    time is stored). The same event id again is deduplicated; the same id with other content is 409."""

    def work(conn: Any) -> dict[str, Any]:
        body_out, _new = visits_svc.observe(conn, auth.ctx, auth.scope.society_id, visit_id, body)
        return body_out

    return idem.run(auth, work, status_code=201)


# REQ: GATE-04
@router.post("/visits/{visit_id}/stops", status_code=201)
def add_stop(
    visit_id: uuid.UUID,
    body: StopAdd,
    auth: Annotated[AuthContext, Depends(require("gate.visit.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[VisitsConfig, Depends(visits_config)],
) -> JSONResponse:
    """Another destination: a NEW stop and a NEW approval request. Approving one stop never authorises another."""

    def work(conn: Any) -> dict[str, Any]:
        policy = policy_mod.load_policy(conn)
        return approvals.add_stop(
            conn, auth.ctx, cfg, auth.scope.society_id, visit_id, body, policy
        )

    return idem.run(auth, work, status_code=201)


@router.post("/visits/{visit_id}/cancel")
def cancel_visit(
    visit_id: uuid.UUID,
    body: VisitCancel,
    auth: Annotated[AuthContext, Depends(require("gate.visit.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(auth, lambda conn: visits_svc.cancel_visit(conn, auth.ctx, visit_id, body))


# ------------------------------------------------------------------------------------------ exceptions
@router.get("/societies/{society_id}/exceptions")
def list_exceptions(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.exception.read"))],
    state: Annotated[
        Literal["open", "supervisor_review", "resolved", "escalated"] | None, Query()
    ] = None,
    kind: Annotated[str | None, Query(max_length=40)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {
            "items": list(exceptions.list_exceptions(conn, state=state, kind=kind, limit=limit))
        }


# REQ: GATE-07
@router.post("/societies/{society_id}/exceptions", status_code=201)
def raise_exception(
    society_id: uuid.UUID,
    body: ExceptionCreate,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("gate.exception.raise"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Raise an exception with a reason. Emergency and manual entry additionally need the LOCAL AUTHORITY (the guard
    supervisor, GATE-07): a plain guard cannot authorise an entry; the exception it leaves always needs a review."""
    if body.kind in exceptions.PRIVILEGED_KINDS:
        authority = authorize(
            request, auth.principal, ["gate.exception.authorise_entry"], auth.scope.society_id
        )
        if authority.scope.role not in (
            "guard_sup",
        ):  # pragma: no cover (the permission lists only the supervisor)
            raise NotAuthorised()
        auth = authority

    def work(conn: Any) -> dict[str, Any]:
        policy = policy_mod.load_policy(conn)
        return exceptions.raise_exception(conn, auth.ctx, auth.scope.society_id, body, policy)

    return idem.run(auth, work, status_code=201)


@router.post("/exceptions/{exception_id}/transition")
def transition_exception(
    exception_id: uuid.UUID,
    body: ExceptionTransition,
    auth: Annotated[AuthContext, Depends(require("gate.exception.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """open -> supervisor_review -> resolved / escalated; compare-and-swap on state and version."""
    return idem.run(auth, lambda conn: exceptions.transition(conn, auth.ctx, exception_id, body))
