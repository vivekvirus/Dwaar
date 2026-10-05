"""Inline authorisation for flows where the standard ``require(...)`` dependency is not enough.

REQ: INV-01 (scope derived on the server; unknown and not-yours answer identically), IAM-03, IAM-04 (privileged reads
log purpose and scope), IAM-12.

``require(action)`` answers "may this caller do X in the society named by the path". Some identity flows must first
LOAD the object to learn its society, unit or owner (``/memberships/{id}/owner-confirm``), or serve a caller who has no
standing yet (a person applying to join). Those flows call :func:`authorize` here, which runs exactly the core's
resolver + ``decide`` and so can never be more permissive than ``require``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any, Final

from fastapi import Request
from sqlalchemy import Connection

from dwaar_common.errors import InvalidSchema, NotAuthorised, NotFound
from dwaar_common.timeutil import utc_now

from ...core.audit import record_audit
from ...core.authn import Principal
from ...core.authz import (
    AuthContext,
    Grant,
    GrantResolver,
    PermissionRegistry,
    Scope,
    decide,
)
from ...core.db import RequestContext

MAX_PURPOSE: Final = 200
MIN_PURPOSE: Final = 3


def request_id_of(request: Request) -> uuid.UUID:
    raw = request.scope.get("state", {}).get("request_id")
    try:
        return uuid.UUID(str(raw))
    except ValueError:
        return uuid.UUID(int=0)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def authorize(
    request: Request,
    principal: Principal,
    actions: Iterable[str],
    society_id: uuid.UUID,
    *,
    unit_id: uuid.UUID | None = None,
    person_id: uuid.UUID | None = None,
) -> AuthContext:
    """First action of ``actions`` the caller may do in ``society_id`` (for ``unit_id``), as a full ``AuthContext``.

    Fails with 404 when the caller has no standing at all or the target is outside their coverage, 403 when they have
    standing but no listed role may do it: the same mapping as ``require``.
    """
    state = request.app.state
    registry: PermissionRegistry = state.permissions
    resolver: GrantResolver = state.grant_resolver
    grants = resolver.resolve(principal, society_hint=society_id, fresh=True)
    best: Exception | None = None
    for action in actions:
        permission = registry.get(action)
        if permission is None:
            raise NotAuthorised()
        try:
            scope = decide(
                permission, grants, society_hint=society_id, unit_target=unit_id, person_target=person_id
            )
        except NotFound as exc:
            best = best or exc
        except NotAuthorised as exc:
            best = exc
        else:
            return AuthContext(principal, scope, permission, request_id_of(request), state.db)
    raise best or NotFound()


def grants_in(
    request: Request, principal: Principal, society_id: uuid.UUID
) -> list[Grant]:
    """The caller's CURRENT active grants inside one society (fresh from the database)."""
    resolver: GrantResolver = request.app.state.grant_resolver
    now = utc_now()
    return [g for g in resolver.resolve(principal, society_hint=society_id, fresh=True) if g.is_active(now)]


def owns_unit(grants: Iterable[Grant], unit_id: uuid.UUID) -> bool:
    return any(g.role in ("owner_occ", "owner_nr") and g.unit_id == unit_id for g in grants)


def applicant_context(
    society_id: uuid.UUID, principal: Principal, request: Request
) -> RequestContext:
    """RLS context for a caller WITHOUT standing (applying to join). The society is the caller's untrusted selector and is
    used only for rows that name the caller themselves: a membership request for their own person, never a read of
    anyone else's data."""
    return RequestContext(society_id, principal.person_id, "applicant", request_id_of(request))


def clean_purpose(raw: str | None) -> str:
    purpose = (raw or "").strip()
    if not MIN_PURPOSE <= len(purpose) <= MAX_PURPOSE:
        raise InvalidSchema.for_fields([("purpose", "purpose_required")])
    return purpose


def log_privileged_read(
    conn: Connection,
    ctx: RequestContext,
    *,
    object_type: str,
    purpose: str,
    scope: dict[str, Any],
    returned: int,
) -> uuid.UUID:
    """IAM-04: a privileged read or export leaves an audit row with its PURPOSE and SCOPE (never the data itself)."""
    return record_audit(
        conn,
        ctx,
        operation=f"read.{object_type}",
        object_type=object_type,
        diff={"purpose": purpose, "scope": scope, "rows_returned": returned},
        reason=purpose,
    )


def ensure_distinct(maker: uuid.UUID, checker: uuid.UUID, *, what: str = "maker_checker") -> None:
    """Maker != checker (IAM-03, PRD 5.1). Finance and procurement reuse this helper."""
    from .makerchecker import require_distinct

    require_distinct(maker, checker, what=what)
