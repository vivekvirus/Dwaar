"""PackRepository interface plus file-backed and in-memory implementations.

The API layer depends on the Protocol; the DB-backed implementation (``legal_packs`` table, PRD 8.2) can be
added later without touching callers.
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Protocol

from .approvals import ApprovalRegistry, default_registry
from .binding import in_effective_range
from .errors import RuleNotFound
from .loader import discover_pack_files, load_pack
from .models import LegalPack, PackHeader


class PackRepository(Protocol):
    def list_packs(self) -> list[PackHeader]: ...

    def get_pack(self, pack_id: str, version: str | None = None) -> PackHeader: ...

    def find_legal_pack(
        self, jurisdiction: str, entity_type: str, at_date: date, *, include_disabled: bool = False
    ) -> LegalPack: ...


class InMemoryPackRepository:
    def __init__(self, packs: list[PackHeader]) -> None:
        self._packs = list(packs)

    def list_packs(self) -> list[PackHeader]:
        return list(self._packs)

    def get_pack(self, pack_id: str, version: str | None = None) -> PackHeader:
        matches = [p for p in self._packs if p.pack_id == pack_id and version in (None, p.version)]
        if not matches:
            raise RuleNotFound(f"no pack {pack_id!r} version {version!r}")
        return sorted(matches, key=lambda p: p.effective_from)[-1]

    def find_legal_pack(
        self, jurisdiction: str, entity_type: str, at_date: date, *, include_disabled: bool = False
    ) -> LegalPack:
        """Latest-effective pack for a jurisdiction and entity type; ``any`` entity packs are a fallback.

        Disabled packs (e.g. a pending Bill variant) are never selected unless explicitly requested.
        An approved pack always outranks an unapproved one, whatever their dates: dropping a newer draft
        file next to an approved pack must not silently switch every caller to a non-binding pack (GOV-01).
        """
        cands = [
            p
            for p in self._packs
            if isinstance(p, LegalPack)
            and p.jurisdiction == jurisdiction
            and (include_disabled or p.enabled)
            and in_effective_range(p, at_date)
        ]
        exact = [p for p in cands if p.entity_type == entity_type]
        pool = exact or [p for p in cands if p.entity_type == "any"]
        if not pool:
            raise RuleNotFound(f"no legal pack for {jurisdiction}/{entity_type} on {at_date}")
        return sorted(pool, key=lambda p: (p.is_approved, p.effective_from))[-1]


log = logging.getLogger("dwaar_packs")


def without_unproven_approval(pack: PackHeader, registry: ApprovalRegistry) -> PackHeader:
    """A pack file that CLAIMS approval without registry evidence is served as unapproved (GOV-01).

    Typing ``status: approved`` and an approver's name into a YAML file proves nothing; see
    ``dwaar_packs.approvals``. The downgrade is logged (pack id and version only).
    """
    if not pack.is_approved or registry.has_evidence(pack):
        return pack
    log.warning(
        "pack claims approval without registry evidence; served as unapproved",
        extra={"pack_id": pack.pack_id, "pack_version": pack.version},
    )
    return pack.model_copy(
        update={"status": "unapproved", "approved_by": None, "approved_at": None}
    )


class FilePackRepository(InMemoryPackRepository):
    """Loads and validates every shipped pack file (schema + model) at construction.

    Approval claims without evidence in the approval registry are downgraded to unapproved.
    """

    def __init__(self, registry: ApprovalRegistry | None = None) -> None:
        reg = registry or default_registry()
        super().__init__(
            [without_unproven_approval(load_pack(p), reg) for p in discover_pack_files()]
        )
