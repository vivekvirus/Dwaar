"""Community module: notices, translations, emergency broadcast, document vault, opinion polls (PRD 9.8, slice 4).

REQ: COM-01..COM-06, SEC-03, SEC-04, INV-05, INV-06, INV-10, INV-01. See docs/adr/0022-helpdesk-and-community.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router``, ``permissions`` and ``register``. Amenity booking (AMEN) and
binding votes (GOV) are M2 and are NOT built here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI

from ...core.config import ConfigError
from . import routes_documents, routes_notices, routes_polls
from .config import CommunityConfig
from .permissions import permissions
from .scanner import scanner_for
from .storage import LocalDiskStore

log = logging.getLogger("dwaar_api.community")

router = APIRouter()
router.include_router(routes_notices.router)
router.include_router(routes_documents.router)
router.include_router(routes_polls.router)

__all__ = ["permissions", "register", "router"]


def register(app: FastAPI) -> None:
    """Load the configuration, the object store and the scanner. Anything already on ``app.state`` (tests) wins. Outside local
    and test a missing key or directory leaves the file endpoints answering 503 instead of stopping the application."""
    state = app.state
    if not isinstance(getattr(state, "community_config", None), CommunityConfig):
        try:
            state.community_config = CommunityConfig.from_environment(state.settings)
        except ConfigError as exc:
            state.community_config = None
            log.error("community is not configured; file endpoints will answer 503: %s", exc)
    cfg = state.community_config
    if cfg is not None:
        if getattr(state, "community_store", None) is None:
            state.community_store = LocalDiskStore(cfg.storage_dir)
        if getattr(state, "community_scanner", None) is None:
            state.community_scanner = scanner_for(cfg.scanner_kind)
        # one raised body limit for the document routes only (default 1 MiB everywhere else)
        limits = getattr(state, "body_limits", None)
        if limits is None:
            state.body_limits = limits = {}
        limits["/v1/documents"] = cfg.max_upload_bytes + 4096
