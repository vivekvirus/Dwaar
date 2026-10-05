"""Route helpers shared by the visits routers: configuration, unit coverage, the canonical-replay fix, role audiences."""

from __future__ import annotations

import json
import uuid
from typing import Any, Final

from fastapi import Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import DependencyUnavailable, NotFound

from ...core.authz import AuthContext
from ...core.idempotency import ORIGINAL_REQUEST_HEADER, REPLAY_HEADER
from .config import VisitsConfig
from .permissions import GATE_READERS, GATE_STAFF, HOUSEHOLD

GUARD_ROLES: Final = frozenset(GATE_STAFF)
STAFF_READ_ROLES: Final = frozenset(GATE_READERS)
HOUSEHOLD_ROLES: Final = frozenset(HOUSEHOLD)


def visits_config(request: Request) -> VisitsConfig:
    """The module configuration. Without the pass key (non-local environment) the endpoints that need it answer 503."""
    cfg = getattr(request.app.state, "visits_config", None)
    if isinstance(cfg, VisitsConfig):
        return cfg
    raise DependencyUnavailable(retry_after=30)


def covered(auth: AuthContext, unit_id: uuid.UUID) -> None:
    """The unit must be one the caller's grants cover, else 404 (not yours looks exactly like unknown)."""
    if not auth.scope.covers_unit(unit_id):
        raise NotFound()


def audience(role: str) -> str:
    """Which view of a visit/request this effective role gets: guard (masked), household (own unit only), full."""
    if role in GUARD_ROLES:
        return "guard"
    if role in HOUSEHOLD_ROLES:
        return "household"
    return "full"


def restore_canonical(response: JSONResponse) -> JSONResponse:
    """Idempotent replay rewrites a ``request_id`` member of a stored body to the replaying HTTP request's id (the core
    convention: ``request_id`` = correlation id). The PRD 12.3 canonical decision response uses ``request_id`` for the
    APPROVAL REQUEST id, so on a replay the original value (kept by the core in ``Idempotent-Original-Request-Id``) is put
    back and the correlation id stays in ``X-Request-ID``."""
    if response.headers.get(REPLAY_HEADER) != "true":
        return response
    original = response.headers.get(ORIGINAL_REQUEST_HEADER)
    if original is None:
        return response
    body: Any = json.loads(bytes(response.body))
    if isinstance(body, dict) and "request_id" in body:
        body["request_id"] = original
    headers = {
        k: v
        for k, v in response.headers.items()
        if k.lower() not in ORIGINAL_REQUEST_HEADER.lower()
        and k.lower() not in {"content-length", "content-type"}
    }
    return JSONResponse(status_code=response.status_code, content=body, headers=headers)
