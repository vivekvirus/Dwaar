"""Permission declarations of the community module (PRD 5.2 row "Notices"; documents and polls follow the same row).

REQ: COM-01..COM-06, IAM-08, INV-01, PRD 5.1/5.2.

PRD 5.2 "Notices": SECRETARY F, TREASURER R, COMMITTEE Draft, ESTATE_MGR Draft, GUARD N, AUDITOR N, OWNER_OCC R, OWNER_NR R,
TENANT R, FAMILY R. The role sets are DERIVED from the identity matrix, so the registry cannot drift from the PRD table (a test
compares them cell by cell):

* read   - everybody except GUARD and AUDITOR (residents: UNIT scope, filtered to their audience by the services);
* draft  - SECRETARY (F includes it), COMMITTEE, ESTATE_MGR: write drafts, add translations, create document drafts and polls;
* manage - SECRETARY: approve, publish, archive, review translations, publish and withdraw documents, open and close polls.

Gaps the matrix leaves (recorded as requests in the slice report): the emergency broadcast (COM-05) is "privileged roles only"
without naming them: SECRETARY, ESTATE_MGR and the guard supervisor (GUARD_SUP, the defined local authority of PRD 5.1) are
declared here. AUDITOR has no access to notices or the vault under the printed matrix; an auditor-only audit-report access level
would need a matrix change. Documents and polls have no matrix row of their own: they follow "Notices".
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix

SECRETARY: Final = matrix.SECRETARY
READ: Final = matrix.roles_for("notices", "read")
DRAFT: Final = matrix.roles_for("notices", "draft")
MANAGE: Final = matrix.roles_for("notices", "manage")
RESIDENTS: Final = READ & matrix.RESIDENT_ROLES
EMERGENCY: Final = frozenset({matrix.SECRETARY, matrix.ESTATE_MGR, matrix.GUARD_SUP})
#: documents: who may see which access level (the printed matrix gives the auditor nothing)
LEVEL_ROLES: Final = {
    "all_residents": READ,
    "owners": frozenset({matrix.OWNER_OCC, matrix.OWNER_NR}) | (READ - matrix.RESIDENT_ROLES),
    "committee": READ - matrix.RESIDENT_ROLES,
    "managers": frozenset({matrix.SECRETARY, matrix.ESTATE_MGR}),
}

permissions: Final = (
    Permission(
        "notice.read",
        READ,
        scope=ScopeKind.UNIT,
        description="Read published notices addressed to the caller (residents: their audience; society roles: all)",
    ),
    Permission(
        "notice.draft",
        DRAFT,
        description="Draft notices and revisions, add translations (PRD 5.2 Draft)",
    ),
    Permission(
        "notice.manage",
        MANAGE,
        description="Approve, publish, archive notices; review translations (PRD 5.2 F)",
        sensitive=True,
    ),
    Permission(
        "notice.receipts.read",
        DRAFT,
        description="Read delivery attempts and read/acknowledgement counts",
    ),
    Permission(
        "notice.emergency",
        EMERGENCY,
        description="COM-05: issue an emergency broadcast on the emergency channel (privileged roles, rate-limited)",
        sensitive=True,
    ),
    Permission(
        "document.read",
        READ,
        scope=ScopeKind.UNIT,
        description="Read the document vault entries the caller's role is allowed (access level), COM-04",
    ),
    Permission(
        "document.draft", DRAFT, description="Create documents and draft versions, upload files"
    ),
    Permission(
        "document.manage",
        MANAGE,
        description="Publish and withdraw document versions",
        sensitive=True,
    ),
    Permission(
        "poll.read",
        READ,
        scope=ScopeKind.UNIT,
        description="Read opinion polls (COM-06, never binding)",
    ),
    Permission(
        "poll.draft", DRAFT, description="Draft an opinion poll and run the neutral-wording check"
    ),
    Permission("poll.manage", MANAGE, description="Open and close an opinion poll", sensitive=True),
    Permission(
        "poll.respond",
        RESIDENTS,
        scope=ScopeKind.UNIT,
        description="Answer an opinion poll (owners-only polls additionally need an owner role)",
    ),
)
