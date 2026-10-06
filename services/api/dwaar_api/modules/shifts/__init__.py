"""Shifts module: guard shifts, checklists, handovers, supervisor override, guard language and training (PRD 9.6, UX-08, UX-09, slice 4).

REQ: SHIFT-01, SHIFT-02, UX-08, UX-09, Appendix C, INV-08, INV-06, INV-01. NOT built (by scope): the AI-G08 summary itself (the ai-gateway engineer
registers ``service.set_summary_provider`` or calls ``service.attach_summary``; no model is called here) and the practice-mode client UI (UX-09).

Nothing in this module is read by a gate decision: a missing next guard escalates and never locks the kiosk (INV-08). See
docs/adr/0021-parcels-staff-shifts.md.
"""

from __future__ import annotations

from .permissions import permissions
from .routes import router

__all__ = ["permissions", "router"]
