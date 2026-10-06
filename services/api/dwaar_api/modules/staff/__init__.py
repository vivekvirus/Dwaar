"""Staff module: consent receipts, the staff register, per-household engagements, attendance, payroll adjustments (PRD 9.6, slice 4).

REQ: STAFF-01, STAFF-02, STAFF-03, STAFF-04, STAFF-05, PRIV-03, PRIV-04, INV-01. NOT built (by scope): STAFF-06 (contractor passes, M2),
STAFF-07 (agency reconciliation, M2), IVR consent (M2: only ``service.simulate_ivr_consent``, a labelled simulator hook, exists). Face matching
is EXCLUDED from M1 to M3 (STAFF-05): there is no such field, column or route, and ``tests/integration/staff/test_no_face_matching.py`` asserts it.

``authorisation.edge_staff_input`` is what the edge policy publisher consumes (AT-12). See docs/adr/0021-parcels-staff-shifts.md.
"""

from __future__ import annotations

from .permissions import permissions
from .routes import router

__all__ = ["permissions", "router"]
