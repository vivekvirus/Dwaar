"""Organisation module: societies, legal entities, blocks and units (PRD 8.1 Organisation aggregate).

REQ: SOC-01, SOC-02, SOC-03 (units subset), ARCH-01, ARCH-05. See docs/adr/0010-organisation-module.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router`` and ``permissions``; adds nothing to shared files.
"""

from __future__ import annotations

from .permissions import permissions
from .routes import router

__all__ = ["permissions", "router"]
