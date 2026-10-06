"""Permission declarations of the shifts module (PRD 9.6). Module-local: PRD 5.2 has no shift row and PRD 5.1 gives GUARD_SUP no column.

REQ: SHIFT-01, SHIFT-02, UX-08, UX-09, Appendix C, IAM-08, INV-01.

Matrix gap (reported as a blocked request): shifts, handovers, supervisor overrides, guard language and training have no cell in PRD 5.2.
The sets below follow PRD 5.1 (GUARD_SUP: security exceptions, device status, authorised emergency override; GUARD: gate operations) and keep the
secretary able to schedule and read. Guards act only on their OWN shifts and handovers (checked by the service, 404 otherwise).
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission
from ..identity import matrix

SECRETARY: Final = matrix.SECRETARY
ESTATE_MGR: Final = matrix.ESTATE_MGR
COMMITTEE: Final = matrix.COMMITTEE
GUARD: Final = matrix.GUARD
GUARD_SUP: Final = matrix.GUARD_SUP

SUPERVISORS: Final = frozenset({GUARD_SUP, SECRETARY})
GUARDS: Final = frozenset({GUARD, GUARD_SUP})

permissions: Final = (
    Permission(
        "shift.manage",
        frozenset({GUARD_SUP, SECRETARY, ESTATE_MGR}),
        description="Schedule guard shifts (gate, guard, planned window)",
    ),
    Permission(
        "shift.read",
        GUARDS | {SECRETARY, ESTATE_MGR, COMMITTEE},
        description="Read shifts and handovers: a guard only its own, supervisors and society roles all (purpose logged)",
    ),
    Permission(
        "shift.operate",
        GUARDS,
        description="Start and end the OWN shift with its checklist (a supervisor may do it for a guard); never blocks the gate (INV-08)",
    ),
    Permission(
        "shift.handover.acknowledge",
        GUARDS,
        description="Acknowledge a handover: the outgoing guard, the incoming guard, or the supervisor on their behalf (SHIFT-01)",
    ),
    Permission(
        "shift.override.grant",
        frozenset({GUARD_SUP}),
        description="Grant a supervisor override that expires at shift end at the latest (Appendix C)",
        sensitive=True,
    ),
    Permission(
        "guard.profile.write",
        GUARDS | {SECRETARY},
        description="Set a guard's language (UX-08): a guard its own, a supervisor or the secretary anyone's",
    ),
    Permission(
        "guard.profile.read",
        GUARDS | {SECRETARY, ESTATE_MGR},
        description="Read a guard profile and training record: a guard its own, supervisors and society roles any",
    ),
    Permission(
        "guard.training.record",
        GUARDS,
        description="Record a practice-mode training completion (UX-09): a guard its own, a supervisor anyone's",
    ),
)
