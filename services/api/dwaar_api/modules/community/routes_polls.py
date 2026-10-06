"""HTTP routes: opinion polls (COM-06). NON-BINDING by construction: no route here (or anywhere) records a binding vote.

REQ: COM-06, D-24 / GOV-01 (binding votes belong to M2 governance behind an approved legal pack; the only poll there is
is an opinion poll), INV-01.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection

from dwaar_common.errors import NotFound

from ...core.authz import AuthContext, require
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
from . import polls
from .routes_notices import actor_of, sys_ctx
from .schemas import PollCloseIn, PollCreate, PollOpenIn, PollResponseIn

router = APIRouter(prefix="/v1", tags=["polls"])
_FILTERS = {"state": FilterDef("enum", frozenset({"draft", "open", "closed"}))}


@router.post("/polls", status_code=201)
def create_poll(
    body: PollCreate,
    auth: Annotated[AuthContext, Depends(require("poll.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A draft OPINION poll (never binding). The neutral-wording check runs now; a flag needs a person's decision to open."""
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        return {
            "poll": polls.poll_view(
                conn, polls.create_poll(conn, auth.ctx, body), actor, staff=True
            )
        }

    return idem.run(auth, work, status_code=201)


@router.get("/polls")
def list_polls(
    request: Request,
    auth: Annotated[AuthContext, Depends(require("poll.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    """Staff: every poll. Residents: opened polls (drafts are invisible)."""
    f = parse_filters(dict(request.query_params), _FILTERS)
    actor = actor_of(auth)
    where = [] if actor.can_draft else ["p.state IN ('open', 'closed')"]
    params: dict[str, Any] = {}
    if "state" in f:
        where.append("p.state = :f_state")
        params["f_state"] = f["state"]
    with auth.tx() as conn:
        polls.close_due(conn, sys_ctx(auth))
        result = paginator.fetch(
            conn, select_sql=polls._POLL_SQL, where=where, params=params,
            sort=[SortColumn("p.created_at", "timestamptz", nullable=False), SortColumn("p.id", "uuid", nullable=False)],
            page=page, society_id=auth.scope.society_id, filters={**f, "_staff": actor.can_draft}, descending=True,
        )  # fmt: skip
        items = [polls.poll_view(conn, r, actor, staff=actor.can_draft) for r in result.items]
    return {"items": items, "next_cursor": result.next_cursor}


def _visible(conn: Connection, auth: AuthContext, poll_id: uuid.UUID) -> dict[str, Any]:
    poll = polls.fetch_poll(conn, poll_id)
    if poll is None or (poll["state"] == "draft" and not actor_of(auth).can_draft):
        raise NotFound()
    return poll


@router.get("/polls/{poll_id}")
def get_poll(
    poll_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("poll.read"))]
) -> dict[str, Any]:
    actor = actor_of(auth)
    with auth.tx() as conn:
        polls.close_due(conn, sys_ctx(auth))
        poll = _visible(conn, auth, poll_id)
        return {"poll": polls.poll_view(conn, poll, actor, staff=actor.can_draft)}


@router.post("/polls/{poll_id}/open")
def open_poll(
    poll_id: uuid.UUID,
    body: PollOpenIn,
    auth: Annotated[AuthContext, Depends(require("poll.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        return {
            "poll": polls.poll_view(
                conn, polls.open_poll(conn, auth.ctx, poll_id, body), actor, staff=True
            )
        }

    return idem.run(auth, work)


@router.post("/polls/{poll_id}/close")
def close_poll(
    poll_id: uuid.UUID,
    body: PollCloseIn,
    auth: Annotated[AuthContext, Depends(require("poll.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    actor = actor_of(auth)

    def work(conn: Connection) -> dict[str, Any]:
        return {
            "poll": polls.poll_view(
                conn, polls.close_poll(conn, auth.ctx, poll_id, body), actor, staff=True
            )
        }

    return idem.run(auth, work)


@router.post("/polls/{poll_id}/responses", status_code=201)
def respond(
    poll_id: uuid.UUID,
    body: PollResponseIn,
    auth: Annotated[AuthContext, Depends(require("poll.respond"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """One answer per person. An opinion, not a vote: it binds nobody. Owners-only polls need an owner role."""
    actor = actor_of(auth)
    return idem.run(
        auth,
        lambda conn: polls.respond(conn, auth.ctx, actor, poll_id, body.option_id),
        status_code=201,
    )


@router.get("/polls/{poll_id}/results")
def get_results(
    poll_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("poll.read"))]
) -> dict[str, Any]:
    """Counts only, subject to the poll's result-visibility rule; who answered what is never returned."""
    actor = actor_of(auth)
    with auth.tx() as conn:
        polls.close_due(conn, sys_ctx(auth))
        poll = _visible(conn, auth, poll_id)
        return polls.results(conn, poll, actor, staff=actor.can_draft)
