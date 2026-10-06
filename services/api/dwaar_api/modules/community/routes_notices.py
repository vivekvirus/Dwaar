"""HTTP routes: notices (COM-01..COM-03), translations (COM-02), receipts, delivery records, emergency broadcast (COM-05).

REQ: COM-01, COM-02, COM-03, COM-05, INV-01 (foreign and unknown ids answer the same 404 ``not_found``), PRD 12.2.
The society is named by ``X-Society-Id`` and validated against the caller's grants, like every ``/v1/<noun>`` route.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection

from dwaar_common.errors import NotFound

from ...core import ratelimit
from ...core.authz import AuthContext, require
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
from . import notices
from .actors import Actor
from .config import CommunityConfig
from .schemas import (
    ApproveIn,
    ArchiveIn,
    EmergencyBroadcastIn,
    NoticeCreate,
    NoticeEdit,
    PublishIn,
    ReceiptIn,
    RevisionCreate,
    TranslationIn,
    TranslationReviewIn,
)

router = APIRouter(prefix="/v1", tags=["notices"])

_FILTERS = {
    "state": FilterDef("enum", frozenset({"draft", "approved", "scheduled", "published", "superseded", "archived"})),
    "kind": FilterDef("enum", frozenset({"general", "legal", "safety", "emergency"})),
}  # fmt: skip


def actor_of(auth: AuthContext) -> Actor:
    return Actor(
        auth.principal.person_id, auth.scope.role, auth.scope.society_wide, auth.scope.unit_ids
    )


def sys_ctx(auth: AuthContext) -> RequestContext:
    return RequestContext(auth.scope.society_id, None, "system", auth.request_id)


def config_of(request: Request) -> CommunityConfig:
    from dwaar_common.errors import DependencyUnavailable

    cfg = getattr(request.app.state, "community_config", None)
    if not isinstance(cfg, CommunityConfig):
        raise DependencyUnavailable(retry_after=30)
    return cfg


def _staff_view(conn: Connection, n: dict[str, Any], actor: Actor) -> dict[str, Any]:
    return {"notice": notices.notice_view(conn, n, "staff", actor)}


# REQ: COM-01, COM-03
@router.post("/notices", status_code=201)
def create_notice(
    body: NoticeCreate,
    auth: Annotated[AuthContext, Depends(require("notice.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A DRAFT. ``drafted_by_ai`` flags a model-produced draft: it can never be published without a person's approval."""
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        return _staff_view(conn, notices.create_notice(conn, auth.ctx, actor, body), actor)

    return idem.run(auth, work, status_code=201)


@router.get("/notices")
def list_notices(
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notice.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    """Staff (secretary, committee, estate manager): every state. Everyone else: published history addressed to them."""
    f = parse_filters(dict(request.query_params), _FILTERS)
    actor = actor_of(auth)
    with auth.tx() as conn:
        notices.publish_due(conn, sys_ctx(auth))
        if actor.can_draft:
            where: list[str] = []
            params: dict[str, Any] = {}
        else:
            where, params = notices.reader_filter(conn, actor)
            if f.get("state") == "draft" or f.get("state") in {"approved", "scheduled"}:
                where.append("false")
        for name in ("state", "kind"):
            if name in f:
                where.append(f"n.{name} = :f_{name}")
                params[f"f_{name}"] = f[name]
        if not actor.can_draft and "state" not in f:
            where.append("n.state = 'published'")
        result = paginator.fetch(
            conn, select_sql=notices.NOTICE_SELECT, where=where, params=params,
            sort=[SortColumn("n.created_at", "timestamptz", nullable=False), SortColumn("n.id", "uuid", nullable=False)],
            page=page, society_id=auth.scope.society_id, filters={**f, "_staff": actor.can_draft}, descending=True,
        )  # fmt: skip
        items = []
        for row in result.items:
            aud = notices.viewer_audience(row, actor)
            if aud is not None:
                items.append(notices.notice_view(conn, row, aud, actor))
    return {"items": items, "next_cursor": result.next_cursor}


def _load(
    conn: Connection, auth: AuthContext, notice_id: uuid.UUID
) -> tuple[dict[str, Any], str, Actor]:
    actor = actor_of(auth)
    n = notices.fetch_notice(conn, notice_id)
    if n is None:
        raise NotFound()
    aud = notices.viewer_audience(n, actor)
    if aud is None or (aud == "reader" and not notices.in_audience(conn, actor, n)):
        raise NotFound()
    return n, aud, actor


@router.get("/notices/{notice_id}")
def get_notice(
    notice_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("notice.read"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        notices.publish_due(conn, sys_ctx(auth))
        n, aud, actor = _load(conn, auth, notice_id)
        return {"notice": notices.notice_view(conn, n, aud, actor)}


def _write(
    auth: AuthContext,
    idem: IdempotentCall,
    fn: Any,
    notice_id: uuid.UUID,
    body: Any,
    *,
    status_code: int = 200,
) -> JSONResponse:
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        return _staff_view(conn, fn(conn, auth.ctx, actor, notice_id, body), actor)

    return idem.run(auth, work, status_code=status_code)


@router.patch("/notices/{notice_id}")
def edit_notice(
    notice_id: uuid.UUID,
    body: NoticeEdit,
    auth: Annotated[AuthContext, Depends(require("notice.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Only a DRAFT revision can be edited; anything past draft is immutable (409): start a new revision."""
    return _write(auth, idem, notices.edit_draft, notice_id, body)


@router.post("/notices/{notice_id}/revisions", status_code=201)
def new_revision(
    notice_id: uuid.UUID,
    body: RevisionCreate,
    auth: Annotated[AuthContext, Depends(require("notice.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """COM-01: a change to a published notice is a new revision; the published one is superseded when the new one goes live."""
    return _write(auth, idem, notices.new_revision, notice_id, body, status_code=201)


@router.post("/notices/{notice_id}/approve")
def approve_notice(
    notice_id: uuid.UUID,
    body: ApproveIn,
    auth: Annotated[AuthContext, Depends(require("notice.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """COM-03: the approval step a model-drafted notice can never skip (``confirm_ai_review`` must be true for it)."""
    return _write(auth, idem, notices.approve, notice_id, body)


@router.post("/notices/{notice_id}/publish")
def publish_notice(
    notice_id: uuid.UUID,
    body: PublishIn,
    auth: Annotated[AuthContext, Depends(require("notice.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Needs an APPROVED revision; a legal or safety notice also needs every translation reviewed by a person (COM-02)."""
    return _write(auth, idem, notices.publish, notice_id, body)


@router.post("/notices/{notice_id}/archive")
def archive_notice(
    notice_id: uuid.UUID,
    body: ArchiveIn,
    auth: Annotated[AuthContext, Depends(require("notice.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        n = notices.archive(conn, auth.ctx, actor, notice_id, body.reason, body.expected_version)
        return _staff_view(conn, n, actor)

    return idem.run(auth, work)


# REQ: COM-02
@router.post("/notices/{notice_id}/translations", status_code=201)
def add_translation(
    notice_id: uuid.UUID,
    body: TranslationIn,
    auth: Annotated[AuthContext, Depends(require("notice.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A human translation of the latest revision. It starts ``unreviewed``; the original is always shown beside it."""
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        n = notices.add_translation(
            conn, auth.ctx, notice_id, body.language, body.title, body.body, origin="human"
        )
        return _staff_view(conn, n, actor)

    return idem.run(auth, work, status_code=201)


@router.post("/notices/{notice_id}/translations/{language}/review")
def review_translation(
    notice_id: uuid.UUID,
    language: str,
    body: TranslationReviewIn,
    auth: Annotated[AuthContext, Depends(require("notice.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """COM-02: recorded human review of the exact text (approve or reject)."""
    actor = actor_of(auth)
    if language not in {"en", "hi", "mr", "kn"}:
        raise NotFound()

    def work(conn: Connection) -> dict[str, Any]:
        n = notices.review_translation(
            conn, auth.ctx, actor, notice_id, language, body.decision, body.note
        )
        return _staff_view(conn, n, actor)

    return idem.run(auth, work)


# REQ: COM-01
@router.post("/notices/{notice_id}/receipts", status_code=201)
def record_receipt(
    notice_id: uuid.UUID,
    body: ReceiptIn,
    auth: Annotated[AuthContext, Depends(require("notice.read"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The caller read or acknowledged the CURRENT published revision (once of each kind; repeating is harmless)."""
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        n = notices.fetch_notice(conn, notice_id)
        if n is None:
            raise NotFound()
        return notices.record_receipt(conn, auth.ctx, actor, n, body.kind)

    return idem.run(auth, work, status_code=201)


@router.get("/notices/{notice_id}/receipts")
def get_receipts(
    notice_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notice.receipts.read"))],
    detail: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """Read and acknowledgement counts and the delivery summary; the list of who acknowledged is for the secretary only."""
    actor = actor_of(auth)
    with auth.tx() as conn:
        n = notices.fetch_notice(conn, notice_id)
        if n is None:
            raise NotFound()
        return notices.receipt_summary(conn, n, detail=detail and actor.can_manage)


@router.get("/notices/{notice_id}/deliveries")
def get_deliveries(
    notice_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notice.receipts.read"))],
) -> dict[str, Any]:
    """Delivery ATTEMPTS recorded by the notifications module (this module never dispatches)."""
    with auth.tx() as conn:
        n = notices.fetch_notice(conn, notice_id)
        if n is None:
            raise NotFound()
        return {"items": notices.deliveries_of(conn, n)}


# REQ: COM-05
@router.post("/emergency-broadcasts", status_code=201)
def emergency_broadcast(
    body: EmergencyBroadcastIn,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notice.emergency"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[CommunityConfig, Depends(config_of)],
) -> JSONResponse:
    """Privileged roles only, rate-limited per person and per society, plain text, no links, never AI-drafted. Dispatch on the
    emergency channel is done by the notifications module from the ``EmergencyBroadcastIssued`` event."""
    db = request.app.state.db
    sid = auth.scope.society_id
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        # inside the idempotent work: a replay of the same key does not spend rate-limit tokens again, and a refused text
        # (links) is refused before it can use up the allowance
        notices.validate_emergency(conn, body)
        ratelimit.enforce(
            db, f"community:emergency:actor:{sid}:{auth.principal.person_id}", capacity=cfg.emergency_actor_per_hour,
            refill_per_second=cfg.emergency_actor_per_hour / 3600,
        )  # fmt: skip
        ratelimit.enforce(
            db, f"community:emergency:society:{sid}", capacity=cfg.emergency_society_per_hour,
            refill_per_second=cfg.emergency_society_per_hour / 3600,
        )  # fmt: skip
        n = notices.emergency_broadcast(conn, auth.ctx, actor, body)
        return {
            "notice": notices.notice_view(conn, n, "staff", actor),
            "channel": "emergency",
            "carries_ads": False,
        }

    return idem.run(auth, work, status_code=201)
