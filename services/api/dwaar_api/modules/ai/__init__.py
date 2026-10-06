"""AI module: ``/v1/ai`` proposals, confirmation, feedback, controls and audit (PRD 10, 11, 12.1, slice 4).

REQ: AI-SYS-01..08, AT-25, AT-26, AT-29, NFR-13, ARCH-05, G1..G12, INV-03, INV-06. See docs/adr/0023-ai-gateway-and-guardrails.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router``, ``permissions`` and ``register``; adds nothing to shared files. The gateway
itself (``dwaar_ai_gateway``) holds no database handle; this module owns persistence (ai_runs, action_proposals, drafts, feedback, controls)
and the deterministic execution of confirmed commands. The gate control path never imports this module.
"""

from __future__ import annotations

import dataclasses
import logging

from fastapi import APIRouter, FastAPI

from dwaar_ai_gateway.config import GatewayConfig
from dwaar_ai_gateway.pipeline import Gateway

from .permissions import permissions
from .ports import AiRuntime
from .routes import router as _routes

log = logging.getLogger("dwaar_api.ai")

router = APIRouter()
router.include_router(_routes)

__all__ = ["permissions", "register", "router"]


def register(app: FastAPI) -> None:
    """Build the runtime: the simulator in local/test only; the Anthropic adapter only with ``DWAAR_AI_ANTHROPIC_API_KEY``. An explicit
    ``app.state.ai`` (tests) wins. Audio can exceed the default body limit, so the proposals prefix gets its own (still bounded) limit."""
    limits = getattr(app.state, "body_limits", None)
    if limits is None:
        limits = {}
        app.state.body_limits = limits
    limits.setdefault("/v1/ai/proposals", 4_000_000)
    if isinstance(getattr(app.state, "ai", None), AiRuntime):
        return
    config = dataclasses.replace(GatewayConfig.from_env(), environment=app.state.settings.env.value)
    app.state.ai = AiRuntime(gateway=Gateway(config))
    log.info(
        "ai gateway ready: provider=%s simulators_allowed=%s",
        config.provider,
        config.simulators_allowed,
    )
