"""HTTP routes: document vault (COM-04) with scan gate and signed, short-lived downloads (SEC-03, SEC-04).

REQ: COM-04, SEC-03, SEC-04 (URL possession never grants permanent access: the signed URL expires, binds the person and the
session, and is RE-CHECKED against the person's current grants, the document's access level and the version's state every time
it is used), INV-01.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, text

from dwaar_common.errors import DependencyUnavailable, NotFound
from dwaar_common.timeutil import utc_now

from ...core.authn import Principal
from ...core.authz import AuthContext, decide, public_route, require
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
from . import documents, files
from .actors import Actor
from .config import CommunityConfig
from .permissions import LEVEL_ROLES
from .routes_notices import actor_of, config_of
from .scanner import MalwareScanner
from .schemas import DocumentCreate, VersionCreate, WithdrawIn
from .storage import ObjectStore, StorageError

router = APIRouter(prefix="/v1", tags=["documents"])
_FILTERS = {
    "doc_type": FilterDef("enum", frozenset({"bye_laws", "minutes", "audit_report", "circular", "policy", "other"})),
    "state": FilterDef("enum", frozenset({"active", "archived"})),
}  # fmt: skip


def store_of(request: Request) -> ObjectStore:
    store = getattr(request.app.state, "community_store", None)
    if store is None:
        raise DependencyUnavailable(retry_after=30)
    return store  # type: ignore[no-any-return]


def scanner_of(request: Request) -> MalwareScanner:
    scanner = getattr(request.app.state, "community_scanner", None)
    if scanner is None:
        raise DependencyUnavailable(retry_after=30)
    return scanner  # type: ignore[no-any-return]


async def raw_body(request: Request) -> bytes:
    return await request.body()


# REQ: COM-04
@router.post("/documents", status_code=201)
def create_document(
    body: DocumentCreate,
    auth: Annotated[AuthContext, Depends(require("document.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(
        auth,
        lambda conn: {
            "document": documents.document_view(documents.create_document(conn, auth.ctx, body))
        },
        status_code=201,
    )


@router.get("/documents")
def list_documents(
    request: Request,
    auth: Annotated[AuthContext, Depends(require("document.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    """Residents see ACTIVE documents whose access level their role may read; staff see all."""
    f = parse_filters(dict(request.query_params), _FILTERS)
    actor = actor_of(auth)
    where: list[str] = []
    params: dict[str, Any] = {}
    if not actor.can_draft:
        levels = sorted(level for level, roles in LEVEL_ROLES.items() if actor.role in roles)
        where += ["d.state = 'active'", "d.access_level = ANY(:levels)"]
        params["levels"] = levels
    for name in ("doc_type", "state"):
        if name in f:
            where.append(f"d.{name} = :f_{name}")
            params[f"f_{name}"] = f[name]
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql="SELECT d.id, d.doc_type, d.title, d.authority, d.access_level, d.state, d.current_version_id, d.version, d.created_at, d.updated_at FROM documents d",
            where=where, params=params,
            sort=[SortColumn("d.created_at", "timestamptz", nullable=False), SortColumn("d.id", "uuid", nullable=False)],
            page=page, society_id=auth.scope.society_id, filters={**f, "_staff": actor.can_draft}, descending=True,
        )  # fmt: skip
        items = [documents.document_view(r) for r in result.items]
    return {"items": items, "next_cursor": result.next_cursor}


@router.get("/documents/{document_id}")
def get_document(
    document_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("document.read"))]
) -> dict[str, Any]:
    actor = actor_of(auth)
    with auth.tx() as conn:
        doc = documents.fetch_document(conn, document_id)
        if doc is None or not documents.doc_visible(actor, doc):
            raise NotFound()
        return {
            "document": documents.document_view(doc),
            "versions": documents.versions_of(conn, document_id, staff=actor.can_draft),
        }


@router.post("/documents/{document_id}/versions", status_code=201)
def add_version(
    document_id: uuid.UUID,
    body: VersionCreate,
    auth: Annotated[AuthContext, Depends(require("document.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """A draft version with its effective date and authority; the file comes next (PUT .../content)."""

    def work(conn: Connection) -> dict[str, Any]:
        return {
            "version": documents.version_view(
                documents.add_version(conn, auth.ctx, document_id, body)
            )
        }

    return idem.run(auth, work, status_code=201)


@router.put("/documents/{document_id}/versions/{version_id}/content")
def upload_content(
    document_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    data: Annotated[bytes, Depends(raw_body)],
    auth: Annotated[AuthContext, Depends(require("document.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[CommunityConfig, Depends(config_of)],
    store: Annotated[ObjectStore, Depends(store_of)],
    scanner: Annotated[MalwareScanner, Depends(scanner_of)],
) -> JSONResponse:
    """The raw file as the request body (``Content-Type`` = its type; ``X-Filename`` = display name). Type and size are
    validated against the bytes, the sha256 is recorded, the scanner runs. Without a configured scanner the file stays
    ``unavailable`` and cannot be published (fail closed)."""
    content_type = request.headers.get("content-type")
    name = request.headers.get("x-filename")

    def work(conn: Connection) -> dict[str, Any]:
        v = documents.upload_content(
            conn, auth.ctx, cfg, store, scanner, document_id, version_id, data, content_type, name
        )
        return {"version": documents.version_view(v)}

    return idem.run(auth, work)


@router.post("/documents/{document_id}/versions/{version_id}/scan")
def rescan(
    document_id: uuid.UUID,
    version_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("document.draft"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    store: Annotated[ObjectStore, Depends(store_of)],
    scanner: Annotated[MalwareScanner, Depends(scanner_of)],
) -> JSONResponse:
    def work(conn: Connection) -> dict[str, Any]:
        return {
            "version": documents.version_view(
                documents.rescan(conn, auth.ctx, store, scanner, document_id, version_id)
            )
        }

    return idem.run(auth, work)


@router.post("/documents/{document_id}/versions/{version_id}/publish")
def publish_version(
    document_id: uuid.UUID,
    version_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("document.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Needs a stored, hashed file whose scan state is CLEAN. A published version is immutable (a new file is a new version)."""

    def work(conn: Connection) -> dict[str, Any]:
        return {
            "version": documents.version_view(
                documents.publish_version(conn, auth.ctx, document_id, version_id)
            )
        }

    return idem.run(auth, work)


@router.post("/documents/{document_id}/versions/{version_id}/withdraw")
def withdraw_version(
    document_id: uuid.UUID,
    version_id: uuid.UUID,
    body: WithdrawIn,
    auth: Annotated[AuthContext, Depends(require("document.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    def work(conn: Connection) -> dict[str, Any]:
        return {
            "version": documents.version_view(
                documents.withdraw_version(conn, auth.ctx, document_id, version_id, body.reason)
            )
        }

    return idem.run(auth, work)


# REQ: SEC-04
@router.post("/documents/{document_id}/versions/{version_id}/download-url")
def download_url(
    document_id: uuid.UUID,
    version_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("document.read"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[CommunityConfig, Depends(config_of)],
) -> JSONResponse:
    """A short-lived signed URL, issued only after a CURRENT access check (role, access level, version state, clean scan)."""
    actor = actor_of(auth)
    now = utc_now()

    def work(conn: Connection) -> dict[str, Any]:
        doc, version = documents.readable_version(conn, actor, document_id, version_id)
        claim = files.DownloadClaim(
            auth.scope.society_id, version["id"], auth.principal.person_id, auth.principal.session_id,
            int(now.timestamp()) + cfg.download_ttl_seconds,
        )  # fmt: skip
        token = files.issue_token(cfg.download_key, claim)
        documents.audit_access(
            conn, auth.ctx, "document.download_url_issued", document_id, version_id
        )
        return {
            "url": f"/v1/downloads/{token}", "expires_at": now + dt.timedelta(seconds=cfg.download_ttl_seconds), "ttl_seconds": cfg.download_ttl_seconds,
            "filename": version["original_filename"], "media_type": version["media_type"], "size_bytes": version["size_bytes"],
            "sha256": version["sha256"], "document": doc["id"],
        }  # fmt: skip

    return idem.run(auth, work)


def _gone() -> NotFound:
    return NotFound()  # expired, forged, revoked, withdrawn, no longer permitted: ONE answer


@router.get(
    "/downloads/{token}",
    dependencies=[
        Depends(
            public_route(
                "signed short-lived download URL: authority is the signature; access is re-checked on use"
            )
        )
    ],
)
def redeem(token: str, request: Request) -> Response:
    """SEC-04. No bearer token is needed because the URL IS the capability, but it is only a short-lived one: the signature and
    expiry are checked, then the person's CURRENT grants (a revoked membership or an elapsed session kills the URL), the
    document's access level and the version's state are checked again. Every failure is the same 404."""
    cfg = config_of(request)
    claim = files.read_token(cfg.download_key, token, int(utc_now().timestamp()))
    if claim is None:
        raise _gone()
    state = request.app.state
    principal = Principal(
        subject=str(claim.person_id), person_id=claim.person_id, session_id=claim.session_id
    )
    try:
        sessions = getattr(state, "session_store", None)
        if sessions is not None and not sessions.is_active(
            session_id=claim.session_id, subject=str(claim.person_id), issued_at=None
        ):
            raise _gone()
        grants = state.grant_resolver.resolve(principal, society_hint=claim.society_id, fresh=True)
        perm = state.permissions.get("document.read")
        scope = decide(perm, grants, society_hint=claim.society_id)
    except Exception as exc:  # any refusal, whatever its class, is the same 404
        if isinstance(exc, DependencyUnavailable):
            raise
        raise _gone() from None
    actor = Actor(claim.person_id, scope.role, scope.society_wide, scope.unit_ids)
    rid = request.scope.get("state", {}).get("request_id")
    ctx = RequestContext(
        claim.society_id, claim.person_id, scope.role, uuid.UUID(str(rid)) if rid else None
    )
    with state.db.app_tx(ctx) as conn:
        row = conn.execute(
            text("SELECT document_id, object_key FROM document_versions WHERE id = :v"),
            {"v": claim.version_id},
        ).first()
        if row is None:
            raise _gone()
        doc = documents.fetch_document(conn, row[0])
        version = documents.fetch_version(conn, row[0], claim.version_id)
        if (
            doc is None
            or version is None
            or row[1] is None
            or not documents.doc_visible(actor, doc)
        ):
            raise _gone()
        documents.ensure_downloadable(actor, doc, version)
        store = store_of(request)
        try:
            data = store.get(row[1])
        except StorageError:
            raise DependencyUnavailable(retry_after=30) from None
        if hashlib.sha256(data).hexdigest() != version["sha256"]:
            raise DependencyUnavailable(
                retry_after=60
            )  # the stored bytes no longer match the recorded hash: never serve them
        documents.audit_access(conn, ctx, "document.downloaded", doc["id"], claim.version_id)
    headers = {
        "Content-Disposition": f'attachment; filename="{files.safe_filename(version["original_filename"])}"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'",
        "X-Document-Sha256": version["sha256"],
    }  # fmt: skip
    return Response(content=data, media_type=version["media_type"], headers=headers)
