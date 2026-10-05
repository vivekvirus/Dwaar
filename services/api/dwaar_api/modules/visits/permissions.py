"""Permission declarations of the visits module (PRD 5.2 rows "Gate operations" and "Create visitor passes").

REQ: GATE-01, GATE-02, GATE-03, GATE-07, GATE-13, IAM-08, INV-01, PRD 5.1/5.2.

The role sets of the resident and society-wide actions are DERIVED from the identity matrix (``matrix.roles_for``), so the
registry cannot drift from the PRD table (a test compares them cell by cell):

* "Gate operations": SECRETARY R, COMMITTEE R, ESTATE_MGR R, GUARD F, OWNER_OCC O, TENANT O, FAMILY O (OWNER_NR N,
  TREASURER N, AUDITOR N).  ``matrix.gate_ops.read`` / ``manage`` / ``read_own``.
* "Create visitor passes": OWNER_OCC O, TENANT O, FAMILY O.  ``matrix.visitor_passes.read_own``.

The matrix has no column for GUARD_SUP (PRD 5.1: "Security exceptions, device status, authorised emergency override").
Those actions are declared HERE, module-locally; a later step can fold them into the matrix data (recorded as a request in
the slice 2 report).

Scope: resident actions are UNIT-scoped (a membership grant covers the member's own unit). Guard actions are society-wide;
the "current gate" restriction is applied by the services (a guard names the gate and sees active items of that gate only).
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix

GUARD: Final = matrix.GUARD
GUARD_SUP: Final = matrix.GUARD_SUP
SECRETARY: Final = matrix.SECRETARY

#: roles that stand at the gate: the matrix's F cell for Gate operations plus the supervisor
GATE_STAFF: Final = matrix.roles_for("gate_ops", "manage") | {GUARD_SUP}
#: PRD 5.2 "Gate operations" R cells (secretary, committee, estate manager) - read-mostly, purpose logged
GATE_READERS: Final = matrix.roles_for("gate_ops", "read") - {GUARD}
#: PRD 5.2 "Gate operations" O cells: the household that lives in the unit
HOUSEHOLD: Final = matrix.roles_for("gate_ops", "read_own")
#: PRD 5.2 "Create visitor passes" O cells
PASS_HOLDERS: Final = matrix.roles_for("visitor_passes", "read_own")

permissions: Final = (
    # ------------------------------------------------------------------------------------ configuration
    Permission(
        "gate.configure",
        frozenset({SECRETARY}),
        description="Create gates and lanes, set the gate policy (PRD 5.2 'Society configuration' F)",
        sensitive=True,
    ),
    Permission(
        "gate.configure.read",
        GATE_READERS | GATE_STAFF,
        description="Read gates, lanes and the gate policy",
    ),
    Permission(
        "gate.device.request",
        GATE_STAFF,
        description="Request enrolment of a gate device (SOC-05 subset); it is inactive until approved",
    ),
    Permission(
        "gate.device.decide",
        frozenset({GUARD_SUP, SECRETARY}),
        description="Approve, reject or revoke a device (never the person who requested it)",
        sensitive=True,
    ),
    Permission(
        "gate.device.read",
        GATE_READERS | {GUARD_SUP},
        description="Read the device list and status (PRD 5.1 GUARD_SUP: device status)",
    ),
    # ------------------------------------------------------------------------------------ invitations
    Permission(
        "gate.invitation.create",
        PASS_HOLDERS,
        scope=ScopeKind.UNIT,
        description="Create, list and revoke visitor passes for the own unit (PRD 5.2 'Create visitor passes' O)",
    ),
    Permission(
        "gate.invitation.redeem",
        GATE_STAFF,
        description="Redeem a presented pass (signed QR or 6-digit code) into an authorised visit",
    ),
    # ------------------------------------------------------------------------------------ approval requests
    Permission(
        "gate.request.create",
        GATE_STAFF,
        description="Raise an approval request for an unannounced visitor; add a stop; cancel a pending request",
    ),
    Permission(
        "gate.request.decide",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Decide an approval request of the own household (a delegated family member only when "
        "memberships.is_primary_approver)",
    ),
    Permission(
        "gate.request.read",
        GATE_STAFF | HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Read approval requests: the household its own, the guard the current gate's, masked (GATE-13)",
    ),
    # ------------------------------------------------------------------------------------ visits
    Permission(
        "gate.visit.observe",
        GATE_STAFF,
        description="Record an entry or exit observation (an observation never creates permission)",
    ),
    Permission(
        "gate.visit.manage",
        GATE_STAFF,
        description="Cancel a visit before entry, add a stop (which creates a new approval request)",
    ),
    Permission(
        "gate.visit.read",
        GATE_READERS | GATE_STAFF,
        description="Society-wide visit register: guard = current gate, active only, masked; others need a purpose",
    ),
    Permission(
        "gate.history.read",
        GATE_READERS | GATE_STAFF | HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Visitor history of one unit (PRD 5.2 'Gate operations' own-unit read; AT-02): the household of "
        "THAT unit, society roles with a purpose, the guard (current gate, active, masked). Never OWNER_NR.",
    ),
    Permission(
        "gate.destination.read",
        GATE_STAFF,
        description="Destination selection helpers: masked surname hint, recent destinations (GATE-02, GATE-13)",
    ),
    # ------------------------------------------------------------------------------------ exceptions
    Permission(
        "gate.exception.raise",
        GATE_STAFF,
        description="Raise a gate exception with a reason (a guard cannot self-authorise manual or emergency entry)",
    ),
    Permission(
        "gate.exception.authorise_entry",
        frozenset({GUARD_SUP}),
        description="Authorise an emergency or manual entry: the defined local authority (GATE-07, PRD 5.1 GUARD_SUP)",
        sensitive=True,
    ),
    Permission(
        "gate.exception.manage",
        frozenset({GUARD_SUP, SECRETARY}),
        description="Review, escalate and resolve exceptions",
        sensitive=True,
    ),
    Permission(
        "gate.exception.read",
        GATE_READERS | {GUARD_SUP},
        description="Read the exception queue",
    ),
)
