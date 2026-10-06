"""Who sees what of a ticket (OPS-02) and the response shapes.

REQ: OPS-02 (private household / block / society scope; common-area tickets show status to all residents; duplicates never
expose another household's private complaint), PRD 5.2 "Helpdesk tickets" (O = own records), UX-07, INV-01, GATE-13 spirit
(a resident never learns who else raised a ticket).

Audiences:

* ``manager``   - society roles with read or full access: everything, including who raised it and who is assigned.
* ``household`` - the person who raised it, and (for a PRIVATE ticket) the other members of that household, except a non-resident
                  owner, who sees only the tickets that person raised themself. Description, photos, notes, SLA dates.
* ``common``    - every other resident, for block and society (common-area) tickets: status only: number, category, title,
                  state, priority, dates. No description, no photos, no raiser, no assignee, no notes.
* ``None``      - not visible: the caller gets 404 ``not_found`` (never 403), identical to an unknown id.
Drafts are visible to their raiser only. A ``support_privacy`` ticket (UX-07) is visible to its raiser and the secretary only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, text

from ..identity import matrix
from .permissions import MANAGE, OWN, READERS

SECRETARY: Final = matrix.SECRETARY
OWNER_NR: Final = matrix.OWNER_NR


@dataclass(frozen=True)
class Actor:
    """The authorised caller as the service layer needs it (derived from the server-side scope, never from a body)."""

    person_id: uuid.UUID
    role: str
    society_wide: bool = False
    unit_ids: frozenset[uuid.UUID] = frozenset()

    @property
    def is_manager(self) -> bool:
        return self.role in MANAGE

    @property
    def is_society_reader(self) -> bool:
        return self.society_wide and self.role in READERS

    @property
    def is_resident(self) -> bool:
        return self.role in OWN and not self.is_society_reader


def my_blocks(conn: Connection, actor: Actor) -> list[uuid.UUID]:
    if not actor.unit_ids:
        return []
    rows = conn.execute(
        text("SELECT DISTINCT block_id FROM units WHERE id = ANY(:u)"),
        {"u": sorted(actor.unit_ids, key=lambda x: x.int)},
    ).all()
    return [r[0] for r in rows]


def audience(ticket: Any, actor: Actor, blocks: list[uuid.UUID]) -> str | None:
    """'manager' | 'household' | 'common' | None for one ticket row (mapping with the ticket columns)."""
    mine = ticket["raised_by"] == actor.person_id
    if ticket["state"] == "draft":
        return "household" if mine else None
    if ticket["category"] == "support_privacy":
        if mine:
            return "household"
        return "manager" if actor.role == SECRETARY and actor.society_wide else None
    if actor.is_society_reader:
        return "manager"
    if actor.role not in OWN:
        return None
    if mine:
        return "household"
    if ticket["scope"] == "private":
        if ticket["unit_id"] in actor.unit_ids and actor.role != OWNER_NR:
            return "household"
        return None
    if ticket["scope"] == "block":
        return "common" if ticket["block_id"] in blocks else None
    return "common"


def list_filter(actor: Actor, blocks: list[uuid.UUID]) -> tuple[list[str], dict[str, Any]]:
    """SQL fragments (bind parameters only) selecting exactly the rows ``audience`` would let this caller see."""
    params: dict[str, Any] = {"me": actor.person_id}
    if actor.is_society_reader:
        params["secretary"] = actor.role == SECRETARY
        return (
            [
                "(t.state <> 'draft' OR t.raised_by = :me)",
                "(t.category <> 'support_privacy' OR t.raised_by = :me OR CAST(:secretary AS boolean))",
            ],
            params,
        )
    params["units"] = sorted(actor.unit_ids, key=lambda x: x.int)
    params["blocks"] = sorted(blocks, key=lambda x: x.int)
    params["household"] = actor.role != OWNER_NR
    clause = (
        "(t.raised_by = :me OR (t.state <> 'draft' AND t.category <> 'support_privacy' AND ("
        "(t.scope = 'private' AND CAST(:household AS boolean) AND t.unit_id = ANY(CAST(:units AS uuid[])))"
        " OR (t.scope = 'block' AND t.block_id = ANY(CAST(:blocks AS uuid[])))"
        " OR t.scope = 'society')))"
    )
    return [clause], params


def view(ticket: Any, aud: str, actor: Actor) -> dict[str, Any]:
    """The response body of a ticket for an audience."""
    mine = ticket["raised_by"] == actor.person_id
    base: dict[str, Any] = {
        "id": ticket["id"],
        "ticket_no": ticket["ticket_no"],
        "scope": ticket["scope"],
        "block_id": ticket["block_id"],
        "category": ticket["category"],
        "priority": ticket["priority"],
        "state": ticket["state"],
        "title": ticket["title"],
        "merged_into": ticket["parent_ticket_id"],
        "mine": mine,
        "version": ticket["version"],
        "created_at": ticket["created_at"],
        "updated_at": ticket["updated_at"],
    }
    if aud == "common":
        return base
    base.update(
        {
            "unit_id": ticket["unit_id"],
            "description": ticket["description"],
            "photo_refs": list(ticket["photo_refs"]),
            "routing": ticket["routing"],
            "hazard_kind": ticket["hazard_kind"],
            "assigned": ticket["assignee_id"] is not None or ticket["contractor_name"] is not None,
            "contractor_name": ticket["contractor_name"],
            "sla": {
                "started_at": ticket["sla_started_at"],
                "ack_by": ticket["sla_ack_by"],
                "fix_by": ticket["sla_fix_by"],
                "ack_at": ticket["ack_at"],
                "paused": ticket["sla_paused_since"] is not None,
                "breaches": sorted(ticket.get("breaches") or []),
            },
            "submitted_at": ticket["submitted_at"],
            "resolved_at": ticket["resolved_at"],
            "feedback_due_at": ticket["feedback_due_at"],
            "closed_at": ticket["closed_at"],
            "closed_basis": ticket["closed_basis"],
            "reopen_count": ticket["reopen_count"],
        }
    )
    if aud == "manager":
        base.update(
            {
                "raised_by": ticket["raised_by"],
                "raised_channel": ticket["raised_channel"],
                "assignee_id": ticket["assignee_id"],
                "beyond_staff_competence": ticket["beyond_staff_competence"],
                "hazard_rule": ticket["hazard_rule"],
            }
        )
    return base
