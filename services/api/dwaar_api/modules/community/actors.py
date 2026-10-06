"""The authorised caller as the community services need it (derived from the server-side scope, never from a body)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from .permissions import DRAFT, MANAGE, RESIDENTS


@dataclass(frozen=True)
class Actor:
    person_id: uuid.UUID
    role: str
    society_wide: bool = False
    unit_ids: frozenset[uuid.UUID] = frozenset()

    @property
    def can_manage(self) -> bool:
        return self.society_wide and self.role in MANAGE

    @property
    def can_draft(self) -> bool:
        return self.society_wide and self.role in DRAFT

    @property
    def is_resident(self) -> bool:
        return self.role in RESIDENTS and not self.society_wide

    @property
    def sees_everything(self) -> bool:
        """Society-wide roles (secretary, treasurer, committee, estate manager) are not filtered by audience."""
        return self.society_wide
