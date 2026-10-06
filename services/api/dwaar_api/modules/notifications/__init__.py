"""Notifications and calling module: categories, templates, push tokens, the approval cascade, proxy calls, budgets, device health (PRD 9.4, slice 4).

REQ: NOTIF-01, NOTIF-02, NOTIF-03, NOTIF-04, NOTIF-05, NOTIF-06, NOTIF-07, NOTIF-09, CALL-01, CALL-02, D-14, D-15, D-21, AT-11, AT-40, INV-01,
INV-03, INV-05, INV-07. NOT built: NOTIF-08 (spoken yes/no is M2), real provider adapters (D-21 vendors are TBD). See docs/adr/0020-notifications-and-calling.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router``, ``permissions`` and ``register``; adds nothing to shared files. The cascade itself runs in
``services/worker`` (job functions over ``runner.run_tick``); the API only records, shows and refuses.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI

from ...core.errors import register_society_scoped_unique
from . import routes_ops, routes_resident
from .config import NotificationsConfig
from .permissions import permissions

log = logging.getLogger("dwaar_api.notifications")

register_society_scoped_unique(
    "notification_templates_key_uq",
    "unit_notification_settings_unit_uq",
    "notification_preferences_person_uq",
)

router = APIRouter()
router.include_router(routes_resident.router)
router.include_router(routes_ops.router)

__all__ = ["permissions", "register", "router"]


def register(app: FastAPI) -> None:
    """Load the configuration. An explicit ``app.state.notifications_config`` (tests) wins. No provider credential exists in this build: outside
    local and test every provider kind reports ``not configured`` and the cascade degrades to the guard-assisted options."""
    if isinstance(getattr(app.state, "notifications_config", None), NotificationsConfig):
        return
    app.state.notifications_config = NotificationsConfig.from_environment(app.state.settings)
