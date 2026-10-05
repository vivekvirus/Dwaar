"""Maker-checker helper (IAM-03: maker and checker on one transaction must be different people).

REQ: IAM-03, DB-03 (a bill run cannot be approved by its maker), PRD 5.1 (SECRETARY denied "self-approved privilege
escalation"; ESTATE_MGR denied "approve own invoice or payment"). Reusable by finance/procurement: call
``require_distinct(maker, checker)`` before recording an approval; the database CHECK constraints (e.g.
``role_grants_no_self_grant``) remain the backstop.
"""

from __future__ import annotations

import uuid

from dwaar_common.errors import PolicyViolation


def require_distinct(*people: uuid.UUID | None, what: str = "maker_checker") -> None:
    """Raise ``PolicyViolation(reason=<what>_same_person)`` when any two of the given people are the same person."""
    seen: set[uuid.UUID] = set()
    for person in people:
        if person is None:
            continue
        if person in seen:
            raise PolicyViolation(details={"reason": f"{what}_same_person"})
        seen.add(person)
