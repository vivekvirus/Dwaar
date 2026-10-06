"""Edge module: device-signed policy distribution and event sync for the on-site gateway (PRD 9.3, EDGE-01..10; slice 3, cloud side).

REQ: EDGE-02, EDGE-03, EDGE-04, EDGE-05, EDGE-07, EDGE-09 (device identity part), EDGE-10 (tombstones), GATE-06, GATE-14, OBS-02, INV-01,
INV-03, INV-07. See docs/adr/0017-edge-sync-and-policy-snapshots.md and docs/contracts/edge-sync.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router``, ``permissions`` and ``register``; adds nothing to shared files.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI

from ...core.config import ConfigError
from . import routes_admin, routes_device
from .config import MAX_BATCH_BYTES, EdgeConfig
from .metrics import EdgeMetrics
from .permissions import permissions

log = logging.getLogger("dwaar_api.edge")

router = APIRouter()
router.include_router(routes_device.router)
router.include_router(routes_admin.router)

__all__ = ["permissions", "register", "router"]


def register(app: FastAPI) -> None:
    """Load the policy issuer and reference keys. An explicit ``app.state.edge_config`` (tests) wins. Outside local/test a missing key
    leaves the edge endpoints answering 503 instead of stopping the application."""
    if not isinstance(getattr(app.state, "edge_metrics", None), EdgeMetrics):
        app.state.edge_metrics = EdgeMetrics()
    app.state.body_limits["/v1/edge/sync/batches"] = MAX_BATCH_BYTES
    if isinstance(getattr(app.state, "edge_config", None), EdgeConfig):
        return
    try:
        app.state.edge_config = EdgeConfig.from_environment(app.state.settings)
    except ConfigError as exc:
        app.state.edge_config = None
        log.error("edge keys are not configured; the edge endpoints will answer 503: %s", exc)
