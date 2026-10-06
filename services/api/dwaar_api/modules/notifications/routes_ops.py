"""HTTP routes of the guard board and the administrators: status, new attempt, proxy call, provider registry, metrics, budget, templates.

REQ: NOTIF-02, NOTIF-03, NOTIF-07, CALL-01, CALL-02, D-21 (provider registry for authorised administrators only), PRD 9.4 budget metrics, OBS-02,
INV-01 (society from the validated path; ids looked up under RLS: foreign ids are the SAME ``not_found``), GATE-13 (no number, no name), INV-03.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import DependencyUnavailable

from ...core.authz import AuthContext, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import (
    DateRange,
    PageParams,
    Paginator,
    SortColumn,
    date_range_params,
    get_paginator,
    page_params,
    parse_filters,
)
from . import metrics, service, templates
from .config import NotificationsConfig
from .providers import registry_status
from .schemas import AttemptIn, BudgetIn, DltIn, ProxyCallIn, TemplateIn

router = APIRouter(prefix="/v1/societies/{society_id}", tags=["notifications"])


def config_of(request: Request) -> NotificationsConfig:
    cfg = getattr(request.app.state, "notifications_config", None)
    if not isinstance(cfg, NotificationsConfig):
        raise DependencyUnavailable(retry_after=30)
    return cfg


# ------------------------------------------------------------------------------------------------------------ guard board
# REQ: NOTIF-02, NOTIF-03, AT-11, AT-40
@router.get("/approval-requests/{request_id}/notification-status")
def notification_status(
    society_id: uuid.UUID,
    request_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.status.read"))],
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """The board of one request: the cascade by step, every notification with its honest state (``provider_accepted`` is not
    ``person_reached``), calls, the fallback offered when the app has not answered, and after expiry the guard-assisted options. A guard names the
    gate and must be at the request's gate. No person, no number."""
    with auth.tx() as conn:
        request = service.guard_request(conn, auth.ctx, auth.scope.role, request_id, gate_id)
        return service.status(conn, request)


@router.post("/approval-requests/{request_id}/cascade-attempts", status_code=201)
def start_attempt(
    society_id: uuid.UUID,
    request_id: uuid.UUID,
    body: AttemptIn,
    auth: Annotated[AuthContext, Depends(require("notification.cascade.restart"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A supervisor starts a new attempt for a still-pending request (the only way past one primary and one alternate call). The expiry is not
    extended and nothing is allowed (INV-03)."""

    def work(conn: Any) -> dict[str, Any]:
        return service.start_attempt(conn, auth.ctx, request_id, body.reason)

    return idem.run(auth, work, status_code=201)


# REQ: CALL-01
@router.post("/approval-requests/{request_id}/proxy-calls", status_code=201)
def start_proxy_call(
    society_id: uuid.UUID,
    request_id: uuid.UUID,
    body: ProxyCallIn,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.call.start"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A masked, TTL-bound call to the household's primary (or alternate) approver. The server picks the callee, the guard learns a masked label
    only, dial outcome and duration are logged, nothing is recorded. A second call to the same role in the same attempt is refused."""
    cfg = config_of(request)

    def work(conn: Any) -> dict[str, Any]:
        req = service.guard_request(conn, auth.ctx, auth.scope.role, request_id, body.gate_id)
        return service.start_proxy_call(conn, auth.ctx, req, target=body.target, cfg=cfg)

    return idem.run(auth, work, status_code=201)


@router.get("/proxy-calls/{call_id}")
def get_proxy_call(
    society_id: uuid.UUID,
    call_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.call.read"))],
    gate_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """State, dial outcome and duration of a proxy-call session (never audio, never a number). A guard names the gate of the request."""
    with auth.tx() as conn:
        req = service.call_request(conn, call_id)
        service.guard_request(conn, auth.ctx, auth.scope.role, req["id"], gate_id)
        return service.call_view(conn, call_id)


# ------------------------------------------------------------------------------------------------------------ administrators
@router.get("/notification-providers")
def providers(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.provider.read"))],
) -> dict[str, Any]:
    """The adapter registry (administrators only): for every kind either a labelled simulator or ``not configured: <the specific missing
    dependency>``. Real vendors (D-21) are not built. A provider outage exposes the intercom or office process (CALL-01)."""
    cfg = config_of(request)
    rows = [s.as_view() for s in registry_status(cfg.providers_mode)]
    return {
        "providers": rows,
        "simulation": cfg.simulation,
        "any_live_provider": False,
        "outage_fallback": ["intercom", "office"],
        "outage_fallback_text_key": "fallback.provider_outage",
    }


@router.get("/notification-metrics")
def notification_metrics(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.metrics.read"))],
    window: Annotated[DateRange, Depends(date_range_params)],
) -> dict[str, Any]:
    """Budget metrics (PRD 9.4): notifications and calls per 1,000 arrivals, failed calls, fallback share, and the approval acknowledgement rate
    (PRD 18.1) with its definition. A high fallback share is an operations problem, not a cost passed to the society."""
    parse_filters(dict(request.query_params), {})
    cfg = config_of(request)
    with auth.tx() as conn:
        now = service.db_now(conn)
        return metrics.collect_metrics(
            conn,
            auth.scope.society_id,
            since=window.start,
            until=window.end,
            now=now,
            cfg=cfg,
        )


@router.get("/device-health")
def device_health(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.health.read"))],
    window: Annotated[DateRange, Depends(date_range_params)],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> dict[str, Any]:
    """Delivery telemetry by phone model and OS version (NOTIF-07): acknowledgement rate and fallback share per group."""
    parse_filters(dict(request.query_params), {}, reserved=frozenset({"limit", "from", "to"}))
    with auth.tx() as conn:
        return metrics.device_health(
            conn,
            since=window.start,
            until=window.end,
            limit=limit,
        )


@router.get("/notification-budget")
def get_budget(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.budget.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.budget_view(conn)


@router.put("/notification-budget")
def put_budget(
    society_id: uuid.UUID,
    body: BudgetIn,
    auth: Annotated[AuthContext, Depends(require("notification.budget.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Set the monthly caps. They bound non-safety sends only; security approval and emergency are never blocked by a cap."""

    def work(conn: Any) -> dict[str, Any]:
        return service.set_budget(
            conn, auth.ctx, monthly_notification_cap=body.monthly_notification_cap, monthly_call_cap=body.monthly_call_cap,
            monthly_sms_cap=body.monthly_sms_cap, expected_version=body.expected_version,
        )  # fmt: skip

    return idem.run(auth, work)


@router.get("/notification-templates")
def list_templates(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.template.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    category: Annotated[str | None, Query(max_length=40)] = None,
    channel: Annotated[str | None, Query(max_length=20)] = None,
) -> dict[str, Any]:
    """The society's templates with their DLT placeholders and whitelisted URLs."""
    parse_filters(
        dict(request.query_params),
        {},
        reserved=frozenset({"limit", "cursor", "category", "channel"}),
    )
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    if category:
        where.append("category = :category")
        params["category"] = category
        filters["category"] = category
    if channel:
        where.append("channel = :channel")
        params["channel"] = channel
        filters["channel"] = channel
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql="SELECT id, template_key, category, channel, language, content_class, body_key, dlt_header, dlt_template_id,"
            " whitelisted_url, status, created_at, version FROM notification_templates",
            where=where,
            params=params,
            sort=[
                SortColumn("created_at", "timestamptz", nullable=False),
                SortColumn("id", "uuid", nullable=False),
            ],
            page=page,
            society_id=auth.scope.society_id,
            filters=filters,
            descending=False,
        )
    return {
        "items": [templates.template_view(r) for r in result.items],
        "next_cursor": result.next_cursor,
    }


@router.post("/notification-templates", status_code=201)
def create_template(
    society_id: uuid.UUID,
    body: TemplateIn,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.template.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Register a template. A promotional template on the security or emergency category is refused (NOTIF-01); an SMS link must be on a
    whitelisted host and an SMS template without DLT ids is a placeholder that is never sent (CALL-02)."""
    cfg = config_of(request)

    def work(conn: Any) -> dict[str, Any]:
        return templates.create_template(
            conn, auth.ctx, template_key=body.template_key, category=body.category, channel=body.channel, language=body.language,
            content_class=body.content_class, body_key=body.body_key, dlt_header=body.dlt_header,
            dlt_template_id=body.dlt_template_id, whitelisted_url=body.whitelisted_url, hosts=cfg.link_hosts,
        )  # fmt: skip

    return idem.run(auth, work, status_code=201)


@router.put("/notification-templates/{template_id}/dlt")
def register_template_dlt(
    society_id: uuid.UUID,
    template_id: uuid.UUID,
    body: DltIn,
    auth: Annotated[AuthContext, Depends(require("notification.template.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Record the DLT sender header and template id the society registered with an operator: an SMS placeholder becomes sendable (CALL-02)."""

    def work(conn: Any) -> dict[str, Any]:
        return templates.register_dlt(
            conn, auth.ctx, template_id, dlt_header=body.dlt_header, dlt_template_id=body.dlt_template_id,
            expected_version=body.expected_version,
        )  # fmt: skip

    return idem.run(auth, work)
