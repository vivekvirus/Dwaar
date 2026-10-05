"""Permission declarations of the organisation module (PRD 5.2 matrix).

REQ: SOC-01, SOC-02, SOC-03, IAM-08 (authorisation from current grants), PRD 5.2.

Role codes are the lower-case snake-case form of the PRD matrix columns (see BLOCKING_DECISIONS, "PRD role codes"):
SECRETARY=secretary, TREASURER=treasurer, COMMITTEE=committee, ESTATE_MGR=estate_mgr, GUARD=guard,
AUDITOR=auditor, OWNER_OCC=owner_occ, OWNER_NR=owner_nr, TENANT=tenant, FAMILY=family.

Matrix rows used here
---------------------
* "Society configuration": SECRETARY F, TREASURER R, COMMITTEE R, ESTATE_MGR R, GUARD N, AUDITOR R, residents N
  -> ``society.read`` (R roles), ``society.configure`` (F = secretary).
* "Unit and member register": SECRETARY F, TREASURER R, COMMITTEE R, ESTATE_MGR R, GUARD masked R, AUDITOR R,
  owners/tenant/family O (own records) -> ``unit.read`` (UNIT scope: a resident's grant covers only own unit(s); the
  guard receives the masked view, see ``views.unit_view``), ``unit.write`` / ``unit.import`` (F = secretary).
* ``society.view`` is the minimal "which society am I in" read (name, city, timezone) that every member needs to use
  the app at all; it carries no configuration. ``society.create`` is platform-level: it is not tied to one society.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind

SECRETARY: Final = "secretary"
TREASURER: Final = "treasurer"
COMMITTEE: Final = "committee"
ESTATE_MGR: Final = "estate_mgr"
GUARD: Final = "guard"
AUDITOR: Final = "auditor"
OWNER_OCC: Final = "owner_occ"
OWNER_NR: Final = "owner_nr"
TENANT: Final = "tenant"
FAMILY: Final = "family"
PLATFORM_ADMIN: Final = "platform_admin"
ORG_ADMIN: Final = "org_admin"

CONFIG_READERS: Final = frozenset({SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, AUDITOR})
RESIDENT_ROLES: Final = frozenset({OWNER_OCC, OWNER_NR, TENANT, FAMILY})
ALL_SOCIETY_ROLES: Final = CONFIG_READERS | {GUARD} | RESIDENT_ROLES

permissions: Final = (
    Permission(
        "society.create",
        frozenset({PLATFORM_ADMIN, ORG_ADMIN}),
        description="Create a society (platform operator, or an org admin within the org)",
        sensitive=True,
    ),
    Permission(
        "society.view",
        ALL_SOCIETY_ROLES,
        scope=ScopeKind.UNIT,
        description="See the societies the caller belongs to (name, city, timezone)",
    ),
    Permission(
        "society.read",
        CONFIG_READERS,
        description="Read society configuration (legal entity masked, packs, flags, quotas)",
    ),
    Permission(
        "society.configure",
        frozenset({SECRETARY}),
        description="Change society configuration, feature flags and budgets",
        sensitive=True,
    ),
    Permission(
        "unit.read",
        CONFIG_READERS | {GUARD} | RESIDENT_ROLES,
        scope=ScopeKind.UNIT,
        description="Read blocks and units (guard: masked view; residents: own unit only)",
    ),
    Permission(
        "unit.write", frozenset({SECRETARY}), description="Create or change blocks and units"
    ),
    Permission(
        "unit.import",
        frozenset({SECRETARY}),
        description="Bulk import of units from CSV (all-or-nothing)",
    ),
)
