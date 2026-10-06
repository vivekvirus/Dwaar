"""Permission declarations of the staff module (PRD 9.6). Module-local: PRD 5.2 has NO staff row.

REQ: STAFF-01..STAFF-05, PRIV-03/PRIV-04, IAM-08, INV-01.

Matrix gap (reported as a blocked request): PRD 5.2 lists no capability for the staff register, engagements, attendance or payroll
adjustments, and PRD 5.1 gives GUARD_SUP no column. These actions are declared HERE with the narrowest sets that make the flows work:

* the household (OWNER_OCC, TENANT; FAMILY may read) manages ITS OWN engagements, attendance corrections and payroll adjustments (UNIT scope);
* SECRETARY / ESTATE_MGR / GUARD_SUP run the register (consent, registration, credentials);
* GUARD records attendance and sees only the staff currently authorised for a destination (STAFF-01);
* payroll amounts are the household's private matter: the secretary has no payroll permission at all.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix

SECRETARY: Final = matrix.SECRETARY
ESTATE_MGR: Final = matrix.ESTATE_MGR
GUARD: Final = matrix.GUARD
GUARD_SUP: Final = matrix.GUARD_SUP
OWNER_OCC: Final = matrix.OWNER_OCC
TENANT: Final = matrix.TENANT
FAMILY: Final = matrix.FAMILY

REGISTER_ROLES: Final = frozenset({SECRETARY, ESTATE_MGR, GUARD_SUP})
HOUSEHOLD_MANAGERS: Final = frozenset({OWNER_OCC, TENANT})
GUARD_ROLES: Final = frozenset({GUARD, GUARD_SUP})

permissions: Final = (
    Permission(
        "staff.consent.capture",
        REGISTER_ROLES | {GUARD},
        description="Capture the staff member's consent on the assisted tablet BEFORE any data capture (STAFF-04)",
    ),
    Permission(
        "staff.register.manage",
        REGISTER_ROLES,
        description="Register staff, record ID capture (masked) and a police-verification STATUS, issue check-in credentials, "
        "withdraw consent (STAFF-01, STAFF-04, STAFF-05, PRIV-04)",
        sensitive=True,
    ),
    Permission(
        "staff.read",
        REGISTER_ROLES | GUARD_ROLES | HOUSEHOLD_MANAGERS | {FAMILY},
        scope=ScopeKind.UNIT,
        description="Read staff: society roles the register, a guard only staff authorised NOW (destinations only), a household only "
        "the staff engaged by its own unit (STAFF-01)",
    ),
    Permission(
        "staff.engagement.manage",
        frozenset({SECRETARY, ESTATE_MGR}) | HOUSEHOLD_MANAGERS,
        scope=ScopeKind.UNIT,
        description="Create, change and end engagements: society roles for any unit, a household for its OWN unit (STAFF-01, STAFF-03)",
    ),
    Permission(
        "staff.attendance.record",
        GUARD_ROLES,
        description="Record a check-in or check-out by code or card (an observation; STAFF-02, STAFF-05)",
    ),
    Permission(
        "staff.attendance.read",
        REGISTER_ROLES | HOUSEHOLD_MANAGERS | {FAMILY},
        scope=ScopeKind.UNIT,
        description="Read attendance: society roles all, a household its own engagements only",
    ),
    Permission(
        "staff.attendance.correct",
        REGISTER_ROLES | HOUSEHOLD_MANAGERS,
        scope=ScopeKind.UNIT,
        description="Append a correction (who, why, when) to an attendance event; the original is never edited (STAFF-02)",
    ),
    Permission(
        "staff.payroll.propose",
        frozenset({ESTATE_MGR}) | HOUSEHOLD_MANAGERS,
        scope=ScopeKind.UNIT,
        description="Propose a payroll adjustment for an engagement (integer paise); it takes effect only when the household approves (STAFF-02)",
    ),
    Permission(
        "staff.payroll.decide",
        HOUSEHOLD_MANAGERS,
        scope=ScopeKind.UNIT,
        description="Approve or reject a payroll adjustment of the own household (STAFF-02)",
        sensitive=True,
    ),
    Permission(
        "staff.payroll.read",
        frozenset({ESTATE_MGR}) | HOUSEHOLD_MANAGERS,
        scope=ScopeKind.UNIT,
        description="Read payroll adjustments: the household its own, the estate manager who proposed",
    ),
)
