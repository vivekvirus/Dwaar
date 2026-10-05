"""Authorisation framework: permission registry, grant resolver protocol, ``require(action, scope)``.

REQ: INV-01 (server-derived society + role scope on every object/query), IAM-03/IAM-13 (no self-granted
elevation; no sign-up path to roles), IAM-08 (sensitive actions re-check CURRENT grants, never stale
JWT claims), PRD 12 / 12.2 (authorisation derived on the server; forbidden-to-reveal => 404 not_found).

How scope is derived (and what is never trusted)
------------------------------------------------
1. ``current_principal`` proves WHO is calling (verified token). Roles in the token are ignored.
2. A :class:`GrantResolver` returns the caller's CURRENT grants from the database (memberships and role
   grants with effective dates). That list is the ONLY source of society, unit, person and role scope.
3. The client may NAME a society (path parameter, or ``X-Society-Id``) and a target unit/person. These
   are untrusted selectors: they are honoured only if one of the caller's active grants covers them,
   otherwise the answer is ``404 not_found``, identical for "does not exist" and "not yours". A
   ``society_id`` in a request BODY is never read by this module.
4. The result is an :class:`AuthContext` whose :class:`Scope` the handler uses for every query and for
   the RLS context of its transaction.

Status mapping: no standing in the society or target outside the caller's coverage => 404; standing but
the role may not do this => 403 ``not_authorised``.
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Final, Protocol, runtime_checkable

from fastapi import Depends, FastAPI, Request
from fastapi.routing import APIRoute
from sqlalchemy import Connection

from dwaar_common.errors import InvalidSchema, NotAuthorised, NotFound
from dwaar_common.logging import society_log_token
from dwaar_common.timeutil import utc_now

from .authn import Principal, current_principal
from .config import ConfigError
from .db import Database, RequestContext

log = logging.getLogger("dwaar_api.authz")

_ACTION: Final = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_ROLE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SOCIETY_HEADER: Final = "X-Society-Id"
REQUIREMENT_ATTR: Final = "__dwaar_requirement__"


class ScopeKind(StrEnum):
    """How broad a grant must be for a permission."""

    SOCIETY = "society"  # only society-wide grants qualify
    UNIT = "unit"  # a society-wide grant, or a grant on the targeted unit
    PERSON = "person"  # a society-wide grant, or a grant restricted to the targeted person (self-service)


@dataclass(frozen=True)
class Permission:
    """An action a module protects, and which roles may perform it (PRD 5.2 matrix)."""

    action: str
    roles: frozenset[str]
    scope: ScopeKind = ScopeKind.SOCIETY
    description: str = ""
    sensitive: bool = False  # force a fresh grant lookup (no resolver caching), IAM-08

    def __post_init__(self) -> None:
        if not _ACTION.match(self.action):
            raise ValueError(f"permission action {self.action!r} must look like 'module.verb'")
        if not self.roles:
            raise ValueError(f"permission {self.action!r} needs at least one role")
        bad = [r for r in self.roles if not _ROLE.match(r)]
        if bad:
            raise ValueError(f"invalid role name(s) for {self.action!r}: {sorted(bad)}")
        object.__setattr__(self, "roles", frozenset(self.roles))


class PermissionRegistry:
    """All declared permissions. Modules contribute theirs through ``permissions`` (see registry)."""

    def __init__(self, permissions: Iterable[Permission] = ()) -> None:
        self._items: dict[str, Permission] = {}
        self.extend(permissions)

    def register(self, permission: Permission) -> None:
        existing = self._items.get(permission.action)
        if existing is not None and existing != permission:
            raise ConfigError(
                f"permission {permission.action!r} is declared twice with different definitions"
            )
        self._items[permission.action] = permission

    def extend(self, permissions: Iterable[Permission]) -> None:
        for permission in permissions:
            self.register(permission)

    def get(self, action: str) -> Permission | None:
        return self._items.get(action)

    def __contains__(self, action: object) -> bool:
        return action in self._items

    def __iter__(self) -> Any:
        return iter(sorted(self._items.values(), key=lambda p: p.action))

    def __len__(self) -> int:
        return len(self._items)


# --------------------------------------------------------------------------------------- grants
@dataclass(frozen=True)
class Grant:
    """One effective-dated grant of a role. Produced by a resolver from DB state, never from a token."""

    role: str
    society_id: uuid.UUID
    unit_id: uuid.UUID | None = None
    person_id: uuid.UUID | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None

    @property
    def society_wide(self) -> bool:
        return self.unit_id is None and self.person_id is None

    def is_active(self, now: datetime) -> bool:
        if self.not_before is not None and now < self.not_before:
            return False
        return self.expires_at is None or now < self.expires_at


@runtime_checkable
class GrantResolver(Protocol):
    """Looks up the caller's CURRENT grants. The identity module provides the database-backed one.

    ``society_hint`` is an UNTRUSTED client selector, passed only so an implementation can narrow its
    query; it must not widen the result. ``fresh=True`` (sensitive actions) means: bypass any cache.
    """

    def resolve(
        self, principal: Principal, *, society_hint: uuid.UUID | None, fresh: bool
    ) -> Sequence[Grant]: ...


class DenyAllGrantResolver:
    """Default when nothing is configured: nobody is authorised (fail closed)."""

    def resolve(
        self, principal: Principal, *, society_hint: uuid.UUID | None, fresh: bool
    ) -> Sequence[Grant]:
        return ()


class InMemoryGrantResolver:
    """Fake resolver for tests and the local demonstrator's unit tests."""

    def __init__(self) -> None:
        self._grants: dict[uuid.UUID, list[Grant]] = {}
        self.calls: list[tuple[uuid.UUID, uuid.UUID | None, bool]] = []
        self._lock = threading.Lock()

    def add(self, person_id: uuid.UUID, grant: Grant) -> Grant:
        with self._lock:
            self._grants.setdefault(person_id, []).append(grant)
        return grant

    def clear(self, person_id: uuid.UUID | None = None) -> None:
        with self._lock:
            if person_id is None:
                self._grants.clear()
            else:
                self._grants.pop(person_id, None)

    def resolve(
        self, principal: Principal, *, society_hint: uuid.UUID | None, fresh: bool
    ) -> Sequence[Grant]:
        with self._lock:
            self.calls.append((principal.person_id, society_hint, fresh))
            return tuple(self._grants.get(principal.person_id, ()))


# --------------------------------------------------------------------------------------- scope
@dataclass(frozen=True)
class Scope:
    """Server-derived scope of one authorised request."""

    society_id: uuid.UUID
    role: str  # effective role: the role of the grant that authorised the action
    kind: ScopeKind  # breadth of that grant (society-wide grants report SOCIETY)
    unit_id: uuid.UUID | None = None  # the validated target unit, if the request named one
    person_id: uuid.UUID | None = None  # the validated target person, if the request named one
    society_wide: bool = False
    unit_ids: frozenset[uuid.UUID] = (
        frozenset()
    )  # units covered by the authorising grants (empty if society_wide)
    self_person_ids: frozenset[uuid.UUID] = frozenset()  # person-restricted coverage (self-service)

    def covers_unit(self, unit_id: uuid.UUID) -> bool:
        return self.society_wide or unit_id in self.unit_ids


def _covers(
    permission: Permission,
    grant: Grant,
    unit_target: uuid.UUID | None,
    person_target: uuid.UUID | None,
) -> bool:
    if grant.society_wide:
        return True
    if permission.scope is ScopeKind.UNIT:
        return grant.unit_id is not None and (unit_target is None or grant.unit_id == unit_target)
    if permission.scope is ScopeKind.PERSON:
        return grant.person_id is not None and (
            person_target is None or grant.person_id == person_target
        )
    return False


def decide(
    permission: Permission,
    grants: Sequence[Grant],
    *,
    society_hint: uuid.UUID | None,
    unit_target: uuid.UUID | None = None,
    person_target: uuid.UUID | None = None,
    now: datetime | None = None,
) -> Scope:
    """Pure decision: raise ``NotFound`` / ``NotAuthorised`` / ``InvalidSchema`` or return the derived scope."""
    moment = now or utc_now()
    active = [g for g in grants if g.is_active(moment)]
    societies = {g.society_id for g in active}
    if society_hint is not None:
        if society_hint not in societies:
            raise NotFound()  # same answer whether the society exists or the caller is just not in it
        society = society_hint
    elif len(societies) == 1:
        (society,) = societies
    elif not societies:
        raise NotFound()
    else:
        raise InvalidSchema.for_fields([("society_id", "required")])

    in_society = [g for g in active if g.society_id == society]
    allowed = [g for g in in_society if g.role in permission.roles]
    if not allowed:
        raise NotAuthorised()
    covering = [g for g in allowed if _covers(permission, g, unit_target, person_target)]
    if not covering:
        explicit_target = (permission.scope is ScopeKind.UNIT and unit_target is not None) or (
            permission.scope is ScopeKind.PERSON and person_target is not None
        )
        if explicit_target:
            raise NotFound()  # target outside the caller's coverage: indistinguishable from "no such target"
        raise NotAuthorised()
    covering.sort(key=lambda g: (not g.society_wide, g.role, str(g.unit_id), str(g.person_id)))
    chosen = covering[0]
    wide = any(g.society_wide for g in covering)
    return Scope(
        society_id=society,
        role=chosen.role,
        kind=ScopeKind.SOCIETY if chosen.society_wide else permission.scope,
        unit_id=unit_target if permission.scope is ScopeKind.UNIT else None,
        person_id=person_target if permission.scope is ScopeKind.PERSON else None,
        society_wide=wide,
        unit_ids=frozenset()
        if wide
        else frozenset(g.unit_id for g in covering if g.unit_id is not None),
        self_person_ids=frozenset()
        if wide
        else frozenset(g.person_id for g in covering if g.person_id is not None),
    )


# --------------------------------------------------------------------------------------- context
@dataclass(frozen=True)
class AuthContext:
    """The authorised request: who, effective role, derived scope, and a scoped transaction factory."""

    principal: Principal
    scope: Scope
    permission: Permission
    request_id: uuid.UUID
    db: Database

    @property
    def ctx(self) -> RequestContext:
        return RequestContext(
            self.scope.society_id, self.principal.person_id, self.scope.role, self.request_id
        )

    def tx(self) -> AbstractContextManager[Connection]:
        """One transaction as ``dwaar_app`` with the RLS context for THIS scope."""
        return self.db.app_tx(self.ctx)


def get_database(request: Request) -> Database:
    """Dependency for flows without a society scope (sign-in, public meta)."""
    db: Database = request.app.state.db
    return db


@dataclass(frozen=True)
class RequirementInfo:
    action: str
    society_param: str
    unit_param: str | None
    person_param: str | None


def _uuid_or_none(raw: object) -> uuid.UUID | None:
    if raw is None or raw == "":
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError:
        raise NotFound() from None  # a malformed selector can only mean "not yours"


def require(
    action: str,
    *,
    society_param: str = "society_id",
    unit_param: str | None = None,
    person_param: str | None = None,
) -> Callable[..., AuthContext]:
    """Dependency factory: ``auth: AuthContext = Depends(require("billing.post"))``.

    ``society_param`` names a PATH parameter (falling back to the ``X-Society-Id`` header) used only as an
    untrusted selector. ``unit_param`` / ``person_param`` name path or query parameters holding a target.
    """
    info = RequirementInfo(action, society_param, unit_param, person_param)

    def dependency(
        request: Request, principal: Annotated[Principal, Depends(current_principal)]
    ) -> AuthContext:
        state = request.app.state
        registry: PermissionRegistry = state.permissions
        permission = registry.get(action)
        if permission is None:
            log.error("action is not registered; denying", extra={"action": action})
            raise NotAuthorised()
        hint = _uuid_or_none(
            request.path_params.get(society_param) or request.headers.get(SOCIETY_HEADER)
        )
        unit_target = _target(request, unit_param)
        person_target = _target(request, person_param)
        resolver: GrantResolver = state.grant_resolver
        grants = resolver.resolve(principal, society_hint=hint, fresh=permission.sensitive)
        scope = decide(
            permission,
            grants,
            society_hint=hint,
            unit_target=unit_target,
            person_target=person_target,
        )
        request_state = request.scope.setdefault("state", {})
        request_state["society_token"] = society_log_token(scope.society_id)
        request_id = uuid.UUID(str(request_state.get("request_id")))
        return AuthContext(principal, scope, permission, request_id, state.db)

    setattr(dependency, REQUIREMENT_ATTR, info)
    return dependency


def _target(request: Request, name: str | None) -> uuid.UUID | None:
    if name is None:
        return None
    return _uuid_or_none(request.path_params.get(name) or request.query_params.get(name))


def iter_api_routes(owner: Any) -> Iterator[APIRoute]:
    """Every ``APIRoute`` reachable from an app/router, including routers included lazily.

    Newer FastAPI keeps included routers as wrapper objects exposing ``original_router``; older versions
    flatten them. Both shapes are handled without importing private classes.
    """
    for route in owner.routes:
        nested = getattr(route, "original_router", None)
        if nested is not None:
            yield from iter_api_routes(nested)
        elif isinstance(route, APIRoute):
            yield route


def declared_requirements(app: FastAPI) -> list[RequirementInfo]:
    """Every ``require(...)`` attached to a route of ``app`` (used for the startup consistency check)."""
    found: list[RequirementInfo] = []

    def walk(dependant: Any) -> None:
        info = getattr(dependant.call, REQUIREMENT_ATTR, None)
        if isinstance(info, RequirementInfo):
            found.append(info)
        for sub in dependant.dependencies:
            walk(sub)

    for route in iter_api_routes(app):
        walk(route.dependant)
    return found


def check_requirements(app: FastAPI, registry: PermissionRegistry) -> None:
    """Fail closed at startup if a route requires an action nobody declared."""
    missing = sorted({r.action for r in declared_requirements(app) if r.action not in registry})
    if missing:
        raise ConfigError("routes require undeclared permissions: " + ", ".join(missing))


__all__ = [
    "SOCIETY_HEADER",
    "AuthContext",
    "DenyAllGrantResolver",
    "Grant",
    "GrantResolver",
    "InMemoryGrantResolver",
    "Permission",
    "PermissionRegistry",
    "Scope",
    "ScopeKind",
    "check_requirements",
    "decide",
    "declared_requirements",
    "get_database",
    "iter_api_routes",
    "require",
]
