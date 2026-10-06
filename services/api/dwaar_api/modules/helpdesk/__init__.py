"""Helpdesk module: tickets, SLA clocks, duplicates, hazards, emergency procedures (PRD 9.7, slice 4).

REQ: OPS-01, OPS-02, OPS-03, OPS-04, OPS-09, UX-07, INV-06, INV-07, INV-10, INV-01. See docs/adr/0022-helpdesk-and-community.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router`` and ``permissions``. Assets, PM plans and work orders are M2 and
are NOT built here.
"""

from __future__ import annotations

from fastapi import APIRouter

from ...core.authz import Permission, ScopeKind
from ..identity import matrix
from . import routes
from .permissions import permissions as _core_permissions

router = APIRouter()
router.include_router(routes.router)

#: UX-07 documents who may raise a support or privacy issue. The route does NOT use ``require`` for it: a person with only a
#: pending membership has no effective grant (ADR-0011), so standing is read from the access overview instead.
permissions = (
    *_core_permissions,
    Permission(
        "helpdesk.support.create",
        matrix.RESIDENT_ROLES,
        scope=ScopeKind.UNIT,
        description="UX-07: raise a support or privacy issue, also while the membership is pending or DISPUTED "
        "(authorised from the access overview in the route, not from a grant)",
    ),
)

__all__ = ["permissions", "router"]
