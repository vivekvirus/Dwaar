"""Permission declarations of the parcels module (PRD 5.2 row "Gate operations").

REQ: PAR-01..PAR-05, PAR-08, IAM-08, INV-01, PRD 5.1/5.2.

The role sets derive from the identity matrix (``matrix.roles_for``), like the visits module: GUARD is F (and the supervisor stands at
the gate), the household (OWNER_OCC, TENANT, FAMILY) is O (own unit only), SECRETARY / COMMITTEE / ESTATE_MGR are R. The matrix has
no "parcels" row of its own; parcels are part of Gate operations in PRD 9.5, so those cells are the source. Matrix gap (reported as a
blocked request): PRD 5.2 has no explicit cell for the delegated-family pickup nor for declaring a parcel lost.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix
from ..visits.permissions import GATE_READERS, GATE_STAFF, HOUSEHOLD

SECRETARY: Final = matrix.SECRETARY
GUARD_SUP: Final = matrix.GUARD_SUP
ESTATE_MGR: Final = matrix.ESTATE_MGR

permissions: Final = (
    Permission(
        "parcel.expect",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Pre-approve an expected delivery for the own unit by brand and time window (PAR-01)",
    ),
    Permission(
        "parcel.consent",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Grant or revoke leave-at-gate consent for the own unit's parcel, before custody (PAR-03)",
    ),
    Permission(
        "parcel.pickup_token.issue",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Issue the single-use pickup token; a family member only when delegated (PAR-03)",
    ),
    Permission(
        "parcel.read",
        GATE_STAFF | GATE_READERS | HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Read parcels: the household its own unit's, the guard the society's open ones, society roles with a purpose",
    ),
    Permission(
        "parcel.handle",
        GATE_STAFF,
        description="Receive a parcel at the gate, store it, collect it against a token, record courier claims (PAR-02, PAR-03, PAR-04)",
    ),
    Permission(
        "parcel.collect.supervised",
        frozenset({GUARD_SUP}),
        description="Hand a parcel over against a supervised alternate proof (no token): the local authority only (PAR-03)",
        sensitive=True,
    ),
    Permission(
        "parcel.resolve",
        GATE_STAFF | {SECRETARY, ESTATE_MGR},
        description="Record a refusal or a return to the carrier; declaring a parcel lost needs the supervisor or the secretary (PAR-02)",
    ),
    Permission(
        "parcel.report.create",
        GATE_STAFF,
        description="Submit a physical count reconciled against the system's custody list (PAR-05)",
    ),
    Permission(
        "parcel.report.read",
        GATE_STAFF | GATE_READERS,
        description="Read custody reports",
    ),
)
