"""Parcels module: expectations, receipt, custody chain, single-use pickup, courier claims, reminders, custody reports (PRD 9.5, slice 4).

REQ: PAR-01, PAR-02, PAR-03, PAR-04, PAR-05, PAR-08, INV-07, INV-01. NOT built (by scope): PAR-06 (label OCR, M2), PAR-07 (partner token
contract, M3, disabled), AI-R04 (order-screenshot parsing, M2). See docs/adr/0021-parcels-staff-shifts.md.

Discovered by ``dwaar_api.core.registry``: exposes ``router`` and ``permissions``; adds nothing to shared files.
"""

from __future__ import annotations

from .permissions import permissions
from .routes import router

__all__ = ["permissions", "router"]
