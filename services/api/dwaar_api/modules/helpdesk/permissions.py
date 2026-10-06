"""Permission declarations of the helpdesk module (PRD 5.2 row "Helpdesk tickets").

REQ: OPS-01..OPS-04, OPS-09, UX-07, IAM-08, INV-01, PRD 5.1/5.2.

PRD 5.2 "Helpdesk tickets": SECRETARY F, TREASURER R, COMMITTEE R, ESTATE_MGR F, GUARD Create, AUDITOR N, OWNER_OCC O, OWNER_NR O,
TENANT O, FAMILY O. The role sets are DERIVED from the identity matrix (``matrix.roles_for``), so the registry cannot drift from
the PRD table (a test compares them cell by cell). Resident ("O") actions are UNIT-scoped (a membership grant covers the
member's own unit); the finer rules (a household sees its own private tickets, common-area tickets show status to everyone,
a non-resident owner sees only tickets that person raised) are applied by ``views``.

The matrix has no column for TECHNICIAN or STAFF; they get nothing here until work orders (M2) declare their own actions.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix

SECRETARY: Final = matrix.SECRETARY
#: PRD 5.2 F cells: full control (secretary, estate manager)
MANAGE: Final = matrix.roles_for("helpdesk", "manage")
#: F and R cells: society-wide readers (secretary, treasurer, committee, estate manager)
READERS: Final = matrix.roles_for("helpdesk", "read")
#: "Create" cell (guard) plus F: who may create tickets without being a household
CREATORS: Final = matrix.roles_for("helpdesk", "create")
#: O cells: the household roles
OWN: Final = matrix.roles_for("helpdesk", "read_own")

permissions: Final = (
    Permission(
        "helpdesk.ticket.create",
        CREATORS | OWN,
        scope=ScopeKind.UNIT,
        description="Raise a ticket: households for their own unit or common areas, the guard (create only), managers",
    ),
    Permission(
        "helpdesk.ticket.read",
        READERS | OWN,
        scope=ScopeKind.UNIT,
        description="Read tickets: society roles all, households their own private tickets and common-area status; "
        "never the guard (create only) or the auditor",
    ),
    Permission(
        "helpdesk.ticket.act",
        OWN | MANAGE,
        scope=ScopeKind.UNIT,
        description="Follow-up on a ticket the caller raised or the household owns: submit a draft, respond, confirm, "
        "reopen within the window, cancel",
    ),
    Permission(
        "helpdesk.ticket.manage",
        MANAGE,
        description="Acknowledge, triage, assign, progress, change priority (approver recorded), merge, close",
    ),
    Permission(
        "helpdesk.sla.read",
        READERS,
        description="Read the SLA clocks, pause log, breaches and priority history of a ticket",
    ),
    Permission(
        "helpdesk.settings.read",
        READERS,
        description="Read the SLA targets and the business calendar",
    ),
    Permission(
        "helpdesk.settings.manage",
        MANAGE,
        description="Change SLA targets, business calendar, feedback and reopen windows (configuration, INV-10)",
        sensitive=True,
    ),
    Permission(
        "helpdesk.emergency.read",
        CREATORS | READERS | OWN,
        scope=ScopeKind.UNIT,
        description="Read the site emergency procedures and accountable contacts (OPS-09)",
    ),
    Permission(
        "helpdesk.emergency.manage",
        frozenset({SECRETARY}),
        description="Record the society's emergency procedure and accountable contacts per hazard (OPS-09)",
        sensitive=True,
    ),
)
