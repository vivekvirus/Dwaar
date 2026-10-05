"""HTTP routes of the organisation module (prefix ``/v1``).

REQ: SOC-01, SOC-02, SOC-03, ARCH-01, ARCH-05, INV-01 (scope is derived on the server by ``require``; a body or query
never names the society), PRD 12.2 (errors; 404 where existence would leak membership), PRD 7.4 (Idempotency-Key on
command creation, cursor pagination <= 100, allow-listed filters).
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from typing import Annotated, Any, Final

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.crypto import EnvelopeCipher, KeyRing
from dwaar_common.errors import (
    DependencyUnavailable,
    DwaarError,
    InvalidSchema,
    NotAuthorised,
    NotFound,
)
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.authn import Principal, current_principal
from ...core.authz import (
    AuthContext,
    PermissionRegistry,
    Scope,
    decide,
    idempotency_exempt,
    require,
)
from ...core.db import RequestContext
from ...core.idempotency import IdempotentCall, encode_response, idempotency_required
from ...core.pagination import (
    FilterDef,
    PageParams,
    Paginator,
    SortColumn,
    decode_cursor,
    encode_cursor,
    get_paginator,
    page_params,
    parse_filters,
)
from . import imports, service
from .permissions import GUARD, ORG_ADMIN, PLATFORM_ADMIN
from .schemas import (
    BlockCreate,
    BlockPatch,
    FlagPut,
    QuotasPut,
    SocietyCreate,
    SocietyPatch,
    UnitCreate,
    UnitPatch,
)
from .views import block_view, unit_view

log = logging.getLogger("dwaar_api.organisation")
router = APIRouter(prefix="/v1", tags=["organisation"])
_FLAG_KEY: Final = re.compile(r"^[a-z][a-z0-9_]{1,62}\Z")


def get_cipher(request: Request) -> EnvelopeCipher:
    """Field-level envelope cipher (PRD 7.4). ``app.state.pii_cipher`` wins; otherwise the key ring comes from the
    environment (``DWAAR_PII_KEYS``). Without keys the identifiers cannot be stored: 503, never plaintext."""
    cipher = getattr(request.app.state, "pii_cipher", None)
    if isinstance(cipher, EnvelopeCipher):
        return cipher
    try:
        cipher = EnvelopeCipher(KeyRing.from_env())
    except Exception:
        log.error("PII key ring is not configured; cannot encrypt legal-entity identifiers")
        raise DependencyUnavailable(retry_after=30) from None
    request.app.state.pii_cipher = cipher
    return cipher


# ------------------------------------------------------------------------------------------ societies
# REQ: SOC-01
@router.post(
    "/societies",
    status_code=201,
    dependencies=[
        Depends(
            idempotency_exempt(
                "society creation has no society scope to bind a key to; a retry hits the legal-entity/registration checks"
                " of the operator workflow and creates an auditable, separately visible society"
            )
        )
    ],
)
def create_society(
    body: SocietyCreate,
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    cipher: Annotated[EnvelopeCipher, Depends(get_cipher)],
) -> JSONResponse:
    """SOC-01. Platform admin (any org) or org admin (own org only). Identifiers are encrypted and returned masked."""
    state = request.app.state
    registry: PermissionRegistry = state.permissions
    permission = registry.get("society.create")
    if permission is None:  # pragma: no cover - the module always declares it
        raise NotAuthorised()
    request_state = request.scope.setdefault("state", {})
    request_id = uuid.UUID(str(request_state.get("request_id")))
    grants = state.grant_resolver.resolve(principal, society_hint=None, fresh=True)
    now = utc_now()
    standing = [
        g for g in grants if g.is_active(now) and g.society_wide and g.role in permission.roles
    ]
    if not standing:
        raise NotAuthorised()
    platform = [g for g in standing if g.role == PLATFORM_ADMIN]
    role = PLATFORM_ADMIN
    if not platform:
        # An org admin may create societies only inside the org of the society where the grant is held.
        role = ORG_ADMIN
        if body.org_id is None:
            raise NotAuthorised()
        allowed = False
        for grant in standing:
            with state.db.app_tx(
                RequestContext(grant.society_id, principal.person_id, grant.role, request_id)
            ) as c:
                org = service.fetch_society(c, grant.society_id)
            if org is not None and org["org_id"] == body.org_id:
                allowed = True
                break
        if not allowed:
            raise NotAuthorised()
    society_id = uuid7()
    ctx = RequestContext(society_id, principal.person_id, role, request_id)
    with state.db.app_tx(ctx) as conn:
        value = service.create_society(conn, ctx, society_id, body, cipher)
    return JSONResponse(status_code=201, content=_json({"request_id": request_id, **value}))


def _json(value: Any) -> dict[str, Any]:
    body: dict[str, Any] = encode_response(value)
    return body


# REQ: SOC-01
@router.get("/societies")
def list_societies(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    page: Annotated[PageParams, Depends(page_params)],
) -> dict[str, Any]:
    """Societies where the caller holds a CURRENT grant (membership/role). Scope comes from the grant resolver only."""
    state = request.app.state
    registry: PermissionRegistry = state.permissions
    permission = registry.get("society.view")
    if permission is None:  # pragma: no cover
        raise NotAuthorised()
    request_state = request.scope.setdefault("state", {})
    request_id = uuid.UUID(str(request_state.get("request_id")))
    grants = state.grant_resolver.resolve(principal, society_hint=None, fresh=False)
    now = utc_now()
    key = state.settings.require_cursor_key()
    binding = hashlib.sha256(f"societies.list:{principal.person_id}".encode()).hexdigest()[:24]
    after: uuid.UUID | None = None
    if page.cursor:
        (raw,) = decode_cursor(page.cursor, key=key, binding=binding, width=1)
        try:
            after = uuid.UUID(str(raw))
        except ValueError:
            raise InvalidSchema.for_fields([("cursor", "invalid_cursor")]) from None
    candidates = sorted({g.society_id for g in grants if g.is_active(now)}, key=lambda u: u.int)
    items: list[dict[str, Any]] = []
    last_id: uuid.UUID | None = None
    more = False
    for sid in candidates:
        if after is not None and sid.int <= after.int:
            continue
        try:
            scope = decide(permission, grants, society_hint=sid, now=now)
        except DwaarError:
            continue  # standing without a role that may see the society: not listed
        with state.db.app_tx(
            RequestContext(sid, principal.person_id, scope.role, request_id)
        ) as conn:
            row = service.fetch_basic(conn, sid)
        if row is None:
            continue  # a grant for a society that no longer exists
        if len(items) == page.limit:
            more = True
            break
        items.append(row)
        last_id = sid
    next_cursor = encode_cursor([last_id], key=key, binding=binding) if more and last_id else None
    return {"request_id": str(request_id), "items": items, "next_cursor": next_cursor}


@router.get("/societies/{society_id}")
def get_society(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("society.view"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        row = service.fetch_basic(conn, auth.scope.society_id)
    if row is None:
        raise NotFound()
    return {"request_id": str(auth.request_id), **row}


@router.get("/societies/{society_id}/configuration")
def get_configuration(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("society.read"))],
) -> dict[str, Any]:
    """Legal entity (masked), packs, binding-governance status, flags and quotas."""
    with auth.tx() as conn:
        config = service.society_configuration(conn, auth.scope.society_id)
    if config is None:
        raise NotFound()
    return _json({"request_id": str(auth.request_id), **config})


@router.patch(
    "/societies/{society_id}",
    dependencies=[
        Depends(idempotency_exempt("optimistic concurrency: expected_version makes a replay a 409"))
    ],
)
def patch_society(
    society_id: uuid.UUID,
    body: SocietyPatch,
    auth: Annotated[AuthContext, Depends(require("society.configure"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        value = service.update_society(conn, auth.ctx, auth.scope.society_id, body)
    return _json({"request_id": str(auth.request_id), **value})


@router.get("/societies/{society_id}/feature-flags")
def list_flags(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("society.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        flags = service.fetch_flags(conn, auth.scope.society_id)
    return {"request_id": str(auth.request_id), "items": flags}


# REQ: ARCH-05
@router.put(
    "/societies/{society_id}/feature-flags/{flag_key}",
    dependencies=[
        Depends(idempotency_exempt("PUT sets absolute state; a replay converges to the same state"))
    ],
)
def put_flag(
    society_id: uuid.UUID,
    flag_key: str,
    body: FlagPut,
    auth: Annotated[AuthContext, Depends(require("society.configure"))],
) -> dict[str, Any]:
    if not _FLAG_KEY.match(flag_key):
        raise InvalidSchema.for_fields([("flag_key", "invalid_flag_key")])
    with auth.tx() as conn:
        value = service.put_flag(conn, auth.ctx, auth.scope.society_id, flag_key, body)
    return {"request_id": str(auth.request_id), **value}


@router.get("/societies/{society_id}/quotas")
def get_quotas(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("society.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        quotas = service.fetch_quotas(conn, auth.scope.society_id)
    if quotas is None:
        raise NotFound()
    return {"request_id": str(auth.request_id), **quotas}


# REQ: ARCH-05
@router.put(
    "/societies/{society_id}/quotas",
    dependencies=[
        Depends(idempotency_exempt("PUT sets absolute state; a replay converges to the same state"))
    ],
)
def put_quotas(
    society_id: uuid.UUID,
    body: QuotasPut,
    auth: Annotated[AuthContext, Depends(require("society.configure"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        value = service.put_quotas(conn, auth.ctx, auth.scope.society_id, body)
    return {"request_id": str(auth.request_id), **value}


# ------------------------------------------------------------------------------------------ blocks
# REQ: SOC-02
@router.post("/societies/{society_id}/blocks", status_code=201)
def create_block(
    society_id: uuid.UUID,
    body: BlockCreate,
    auth: Annotated[AuthContext, Depends(require("unit.write"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    def work(conn: Any) -> dict[str, Any]:
        value = service.create_block(conn, auth.ctx, auth.scope.society_id, body)
        return {"request_id": str(auth.request_id), **value}

    return idem.run(auth, work, status_code=201)


@router.get("/societies/{society_id}/blocks")
def list_blocks(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("unit.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    filters = parse_filters(
        dict(request.query_params),
        {"status": FilterDef("enum", frozenset({"active", "archived"}))},
    )
    status = filters.get("status", "active")
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql="SELECT id, name, floors, has_lift, status, version FROM blocks",
            where=["status = :status"],
            params={"status": status},
            sort=[SortColumn("id", "uuid", nullable=False)],
            page=page,
            society_id=auth.scope.society_id,
            filters={"status": status},
            descending=False,
        )
    return {
        "request_id": str(auth.request_id),
        "items": [block_view(r) for r in result.items],
        "next_cursor": result.next_cursor,
    }


@router.get("/societies/{society_id}/blocks/{block_id}")
def get_block(
    society_id: uuid.UUID,
    block_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("unit.read"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        block = service.fetch_block(conn, block_id)
    if block is None:
        raise NotFound()
    return {"request_id": str(auth.request_id), **block_view(block)}


@router.patch(
    "/societies/{society_id}/blocks/{block_id}",
    dependencies=[
        Depends(idempotency_exempt("optimistic concurrency: expected_version makes a replay a 409"))
    ],
)
def patch_block(
    society_id: uuid.UUID,
    block_id: uuid.UUID,
    body: BlockPatch,
    auth: Annotated[AuthContext, Depends(require("unit.write"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        value = service.update_block(conn, auth.ctx, block_id, body)
    return {"request_id": str(auth.request_id), **value}


@router.delete(
    "/societies/{society_id}/blocks/{block_id}",
    dependencies=[Depends(idempotency_exempt("archiving twice is a no-op"))],
)
def archive_block(
    society_id: uuid.UUID,
    block_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("unit.write"))],
    expected_version: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, Any]:
    """Blocks are archived, never deleted (history and later memberships keep referencing them)."""
    with auth.tx() as conn:
        value = service.archive_block(conn, auth.ctx, block_id, expected_version)
    return {"request_id": str(auth.request_id), **value}


# ------------------------------------------------------------------------------------------ units
# REQ: SOC-02
@router.post("/societies/{society_id}/units", status_code=201)
def create_unit(
    society_id: uuid.UUID,
    body: UnitCreate,
    auth: Annotated[AuthContext, Depends(require("unit.write"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    def work(conn: Any) -> dict[str, Any]:
        value = service.create_unit(conn, auth.ctx, auth.scope.society_id, body)
        return {"request_id": str(auth.request_id), **value}

    return idem.run(auth, work, status_code=201)


def _view_for(auth: AuthContext, row: dict[str, Any]) -> dict[str, Any]:
    return unit_view(row, masked=auth.scope.role == GUARD)


@router.get("/societies/{society_id}/units")
def list_units(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("unit.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    """Unit register. A resident-scoped caller sees only the units their grants cover (own records)."""
    filters = parse_filters(
        dict(request.query_params),
        {
            "block_id": FilterDef("uuid"),
            "floor": FilterDef("int"),
            "status": FilterDef("enum", frozenset({"active", "archived"})),
            "label": FilterDef("str", max_length=40),
        },
    )
    status = filters.get("status", "active")
    where = ["u.status = :status"]
    params: dict[str, Any] = {"status": status}
    effective = {**filters, "status": status}
    if "block_id" in filters:
        where.append("u.block_id = :block_id")
        params["block_id"] = filters["block_id"]
    if "floor" in filters:
        where.append("u.floor = :floor")
        params["floor"] = filters["floor"]
    if "label" in filters:
        where.append("lower(u.label) = lower(:label)")
        params["label"] = filters["label"]
    scope: Scope = auth.scope
    if not scope.society_wide:
        where.append("u.id = ANY(CAST(:own AS uuid[]))")
        params["own"] = sorted(scope.unit_ids, key=lambda x: x.int)
        effective["own"] = hashlib.sha256(
            ",".join(str(u) for u in params["own"]).encode()
        ).hexdigest()[:16]
    select_sql = service.UNIT_SELECT
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql=select_sql,
            where=where,
            params=params,
            sort=[SortColumn("u.id", "uuid", nullable=False)],
            page=page,
            society_id=scope.society_id,
            filters=effective,
            descending=False,
        )
    return {
        "request_id": str(auth.request_id),
        "items": [_view_for(auth, r) for r in result.items],
        "next_cursor": result.next_cursor,
    }


@router.get("/societies/{society_id}/units/{unit_id}")
def get_unit(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("unit.read", unit_param="unit_id"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        unit = service.fetch_unit(conn, unit_id)
    if unit is None:
        raise NotFound()
    return _json({"request_id": str(auth.request_id), **_view_for(auth, unit)})


@router.patch(
    "/societies/{society_id}/units/{unit_id}",
    dependencies=[
        Depends(idempotency_exempt("optimistic concurrency: expected_version makes a replay a 409"))
    ],
)
def patch_unit(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    body: UnitPatch,
    auth: Annotated[AuthContext, Depends(require("unit.write"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        value = service.update_unit(conn, auth.ctx, unit_id, body)
    return _json({"request_id": str(auth.request_id), **value})


@router.delete(
    "/societies/{society_id}/units/{unit_id}",
    dependencies=[Depends(idempotency_exempt("archiving twice is a no-op"))],
)
def archive_unit(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("unit.write"))],
    expected_version: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        value = service.archive_unit(conn, auth.ctx, unit_id, expected_version)
    return _json({"request_id": str(auth.request_id), **value})


# REQ: SOC-03
@router.post("/societies/{society_id}/units:import")
def import_units(
    society_id: uuid.UUID,
    raw: Annotated[bytes, Body(media_type="text/csv")],
    auth: Annotated[AuthContext, Depends(require("unit.import"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    dry_run: Annotated[bool, Query()] = False,
    create_missing_blocks: Annotated[bool, Query()] = False,
) -> JSONResponse:
    """SOC-03 subset. Body: the raw CSV (``Content-Type: text/csv``). All-or-nothing; ``dry_run=true`` only reports."""

    def work(conn: Any) -> dict[str, Any]:
        value = imports.run_import(
            conn,
            auth.ctx,
            auth.scope.society_id,
            raw,
            dry_run=dry_run,
            create_missing_blocks=create_missing_blocks,
        )
        return {"request_id": str(auth.request_id), **value}

    return idem.run(auth, work, status_code=200)
