"""Visits module: gates, devices, invitations, approval requests, visits, observations, exceptions (PRD 9.2, slice 2).

REQ: GATE-01, GATE-02, GATE-03, GATE-04, GATE-05, GATE-07, GATE-08, GATE-11, GATE-13, SOC-05 (subset), INV-03, INV-07, INV-01.
See docs/adr/0013-visits-module.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router``, ``permissions`` and ``register``; adds nothing to shared files.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI

from ...core.config import ConfigError
from ...core.errors import register_society_scoped_unique
from . import routes_approvals, routes_gates, routes_invitations, routes_visits
from .config import VisitsConfig
from .permissions import permissions

log = logging.getLogger("dwaar_api.visits")

# A collision inside the caller's own society may say "already exists": these names are per-society (ADR-0004).
register_society_scoped_unique(
    "gates_society_name_ci_uq", "lanes_gate_label_ci_uq", "devices_society_key_uq"
)

router = APIRouter()
router.include_router(routes_gates.router)
router.include_router(routes_invitations.router)
router.include_router(routes_approvals.router)
router.include_router(routes_visits.router)

__all__ = ["permissions", "register", "router"]


def register(app: FastAPI) -> None:
    """Load the pass keys. An explicit ``app.state.visits_config`` (tests) wins. Outside local/test a missing key leaves the
    key-dependent endpoints answering 503 instead of stopping the whole application."""
    if isinstance(getattr(app.state, "visits_config", None), VisitsConfig):
        return
    try:
        app.state.visits_config = VisitsConfig.from_environment(app.state.settings)
    except ConfigError as exc:
        app.state.visits_config = None
        log.error(
            "visits keys are not configured; pass and visitor-token endpoints will answer 503: %s",
            exc,
        )
