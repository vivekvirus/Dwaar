"""The PRD 5.2 permission matrix and the 5.1 role list, as DATA.

REQ: PRD 5.1 (roles; allowed and denied by default), PRD 5.2 (matrix), IAM-03 (elevated roles), IAM-13, INV-01.

``MATRIX`` holds the cells exactly as printed in the PRD, one string per role. ``permissions`` is generated from it,
so the registry cannot drift from the document. The cell vocabulary is: F full, R read, O own records only,
A approve, M maker, C checker, N none, plus the printed qualifiers ("Masked R", "A (own unit)", "O (bills)",
"O (if liable)", "O (about them)", "Create", "Draft", "M (requests)", "Vote if entitled").

Decisions recorded where the printed table is silent or ambiguous (see ADR-0011):

* "Unit and member register" prints nine values for ten columns; the AUDITOR cell is empty in the source text and is
  treated as N (denied by default).
* "O" (own records) is a UNIT-scoped permission for unit capabilities and a PERSON-scoped one for privacy requests
  and the audit log ("about them"). "(if liable)" and "Vote if entitled" are entitlements owned by finance and
  governance (INV-04): the matrix grants the role, the owning module checks the entitlement.
* Roles that have no column in 5.2 (GUARD_SUP, TECHNICIAN, VENDOR_TECH, ORG_ADMIN, PLAT_SUPPORT, STAFF) get no
  matrix permission: denied by default until their own module declares one.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind

# Role codes: lower-case form of the PRD 5.1 codes.
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
GUARD_SUP: Final = "guard_sup"
TECHNICIAN: Final = "technician"
VENDOR_TECH: Final = "vendor_tech"
ORG_ADMIN: Final = "org_admin"
PLAT_SUPPORT: Final = "plat_support"
STAFF: Final = "staff"

MATRIX_ROLES: Final = (
    SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, GUARD, AUDITOR, OWNER_OCC, OWNER_NR, TENANT, FAMILY,
)  # fmt: skip
ALL_ROLES: Final = frozenset(
    {*MATRIX_ROLES, GUARD_SUP, TECHNICIAN, VENDOR_TECH, ORG_ADMIN, PLAT_SUPPORT, STAFF}
)
RESIDENT_ROLES: Final = frozenset({OWNER_OCC, OWNER_NR, TENANT, FAMILY})

#: Roles that need a fresh MFA step-up in the session (IAM-03). Must equal iam.is_elevated_role() in migration 0133.
ELEVATED_ROLES: Final = frozenset(
    {SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, GUARD_SUP, AUDITOR, ORG_ADMIN, PLAT_SUPPORT}
)
#: Roles a secretary may grant through the role-grant API (IAM-13: platform roles are never assignable here).
ASSIGNABLE_ROLES: Final = frozenset(
    {SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, GUARD, GUARD_SUP, AUDITOR, TECHNICIAN, VENDOR_TECH}
)
PLATFORM_ROLES: Final = frozenset({ORG_ADMIN, PLAT_SUPPORT})
#: Roles whose grant must carry an expiry (time-bound by PRD 5.1).
TIME_BOUND_ROLES: Final = frozenset({AUDITOR, PLAT_SUPPORT, VENDOR_TECH})

#: capability -> (label, scope kind of the "own" cells, cells in MATRIX_ROLES order)
_RAW: Final[dict[str, tuple[str, ScopeKind, tuple[str, ...]]]] = {
    "society_config": ("Society configuration", ScopeKind.UNIT,
                       ("F", "R", "R", "R", "N", "R", "N", "N", "N", "N")),
    "unit_register": ("Unit and member register", ScopeKind.UNIT,
                      ("F", "R", "R", "R", "Masked R", "N", "O", "O", "O", "O")),
    "verify_tenancy": ("Verify tenancy / membership", ScopeKind.UNIT,
                       ("A", "N", "N", "N", "N", "N", "A (own unit)", "A (own unit)", "N", "N")),
    "gate_ops": ("Gate operations", ScopeKind.UNIT,
                 ("R", "N", "R", "R", "F", "N", "O", "N", "O", "O")),
    "visitor_passes": ("Create visitor passes", ScopeKind.UNIT,
                       ("N", "N", "N", "N", "N", "N", "O", "N", "O", "O")),
    "helpdesk": ("Helpdesk tickets", ScopeKind.UNIT,
                 ("F", "R", "R", "F", "Create", "N", "O", "O", "O", "O")),
    "bill_runs": ("Bill runs", ScopeKind.UNIT,
                  ("M", "C", "R", "N", "N", "R", "O (bills)", "O (bills)", "O (if liable)", "N")),
    "journals": ("Journals and vendor payments", ScopeKind.UNIT,
                 ("M", "C", "R", "M (requests)", "N", "R", "N", "N", "N", "N")),
    "meetings": ("Meetings and binding votes", ScopeKind.UNIT,
                 ("F", "R", "R", "N", "N", "R", "Vote if entitled", "Vote if entitled", "N", "N")),
    "notices": ("Notices", ScopeKind.UNIT,
                ("F", "R", "Draft", "Draft", "N", "N", "R", "R", "R", "R")),
    "privacy": ("Privacy requests and retention", ScopeKind.PERSON,
                ("F", "N", "N", "N", "N", "N", "O", "O", "O", "O")),
    "audit_log": ("Audit log", ScopeKind.PERSON,
                  ("R", "R", "R", "N", "N", "R", "O (about them)", "O", "O", "O")),
}  # fmt: skip

MATRIX: Final[dict[str, dict[str, str]]] = {
    cap: dict(zip(MATRIX_ROLES, cells, strict=True)) for cap, (_l, _s, cells) in _RAW.items()
}
LABELS: Final[dict[str, str]] = {cap: label for cap, (label, _s, _c) in _RAW.items()}
OWN_SCOPE: Final[dict[str, ScopeKind]] = {cap: scope for cap, (_l, scope, _c) in _RAW.items()}

# cell -> verbs it grants. A cell that is not listed (N) grants nothing.
_VERBS: Final[dict[str, tuple[str, ...]]] = {
    "F": ("read", "manage"),
    "R": ("read",),
    "A": ("read", "approve"),
    "M": ("read", "make"),
    "C": ("read", "check"),
    "M (requests)": ("make",),
    "Create": ("create",),
    "Draft": ("read", "draft"),
    "Masked R": ("read_masked",),
    "O": ("read_own",),
    "O (bills)": ("read_own",),
    "O (if liable)": ("read_own",),
    "O (about them)": ("read_own",),
    "A (own unit)": ("approve_own",),
    "Vote if entitled": ("vote",),
}
_UNIT_VERBS: Final = frozenset({"read_own", "approve_own", "vote"})


def action_name(capability: str, verb: str) -> str:
    return f"matrix.{capability}.{verb}"


def verbs_of(cell: str, capability: str | None = None) -> tuple[str, ...]:
    """Verbs a cell grants. Full control (F) also covers ``create`` / ``draft`` where the row has such cells."""
    verbs = _VERBS.get(cell, ())
    if cell == "F" and capability is not None:
        row = set(MATRIX[capability].values())
        verbs = verbs + tuple(v for v, marker in (("create", "Create"), ("draft", "Draft")) if marker in row)
    return verbs


def roles_for(capability: str, verb: str) -> frozenset[str]:
    return frozenset(r for r, cell in MATRIX[capability].items() if verb in verbs_of(cell, capability))


def _build() -> tuple[Permission, ...]:
    built: list[Permission] = []
    for cap, (label, own_scope, _cells) in _RAW.items():
        verbs = sorted({v for cell in MATRIX[cap].values() for v in verbs_of(cell, cap)})
        for verb in verbs:
            roles = roles_for(cap, verb)
            if not roles:
                continue
            # Resident roles hold unit-bound grants (memberships), so any permission a resident may use must be
            # satisfiable by a unit-scoped grant; society-wide grants (staff, committee) always qualify as well.
            scope = (
                own_scope if verb in _UNIT_VERBS or roles & RESIDENT_ROLES else ScopeKind.SOCIETY
            )
            if verb in ("read_own", "approve_own") and cap in ("privacy", "audit_log"):
                scope = ScopeKind.PERSON
            built.append(
                Permission(
                    action_name(cap, verb),
                    roles,
                    scope=scope,
                    description=f"PRD 5.2 {label}: {verb}",
                    sensitive=verb in {"approve", "manage", "check", "make"},
                )
            )
    return tuple(built)


MATRIX_PERMISSIONS: Final = _build()

#: PRD 5.1 "denied by default" cells that the 5.2 matrix alone does not express. (role, action) pairs that MUST be
#: refused; the identity test-suite asserts each one against the live registry (AT-02 and friends).
DENIED_BY_DEFAULT: Final[tuple[tuple[str, str, str], ...]] = (
    (OWNER_NR, action_name("gate_ops", "read_own"), "non-resident owner cannot see the tenant's visitor history"),
    (OWNER_NR, action_name("visitor_passes", "read_own"), "non-resident owner has no household visitor passes"),
    (TREASURER, action_name("gate_ops", "read"), "treasurer sees no visitors by virtue of a finance role"),
    (TREASURER, action_name("verify_tenancy", "approve"), "treasurer cannot override residency"),
    (TREASURER, "iam.residency.override", "treasurer cannot override residency"),
    (GUARD, action_name("unit_register", "read"), "guard sees masked directories only"),
    (GUARD, "iam.directory.read_phone", "guard has no phone directory"),
    (FAMILY, action_name("bill_runs", "read_own"), "family has no financial actions unless delegated"),
    (TENANT, action_name("meetings", "vote"), "tenant has no statutory vote unless separately entitled"),
    (COMMITTEE, action_name("bill_runs", "check"), "committee is not the finance checker unless granted"),
    (AUDITOR, action_name("journals", "make"), "auditor cannot mutate books"),
    (ESTATE_MGR, action_name("journals", "check"), "estate manager cannot approve payments"),
)  # fmt: skip

# ------------------------------------------------------------------------------------- identity's own permissions
IDENTITY_PERMISSIONS: Final = (
    Permission(
        "iam.membership.manage",
        frozenset({SECRETARY}),
        description="Create memberships for other people (always pending until verified)",
        sensitive=True,
    ),
    Permission(
        "iam.membership.read_register",
        roles_for("unit_register", "read"),
        description="Read the member register: PRD 5.2 'Unit and member register' R/F cells (purpose logged, IAM-04)",
        sensitive=True,
    ),
    Permission(
        "iam.membership.read_masked",
        roles_for("unit_register", "read_masked"),
        description="Read the masked member directory (names reduced to initials): PRD 5.2 'Masked R'",
    ),
    Permission(
        "iam.case.read",
        frozenset({SECRETARY, COMMITTEE}),
        description="List verification cases of the society",
    ),
    Permission(
        "iam.role_grant.issue",
        frozenset({SECRETARY}),
        description="Issue a role grant (reason mandatory; never to self)",
        sensitive=True,
    ),
    Permission(
        "iam.role_grant.revoke",
        frozenset({SECRETARY}),
        description="Revoke a role grant (reason mandatory)",
        sensitive=True,
    ),
    Permission(
        "iam.role_grant.read",
        frozenset({SECRETARY, COMMITTEE}),
        description="List role grants (purpose logged)",
        sensitive=True,
    ),
    Permission(
        "iam.hold.place",
        frozenset({SECRETARY, COMMITTEE}),
        description="Place a committee hold on a pending tenant onboarding (reason mandatory)",
        sensitive=True,
    ),
    Permission(
        "iam.hold.decide",
        frozenset({SECRETARY, COMMITTEE}),
        description="Decide a hold appeal (never the person who placed the hold)",
        sensitive=True,
    ),
    Permission(
        "iam.dispute.raise",
        frozenset({SECRETARY}),
        description="Open an owner-tenant dispute review on a membership",
        sensitive=True,
    ),
    Permission(
        "iam.dispute.raise_own",
        frozenset({OWNER_OCC, OWNER_NR, TENANT}),
        scope=ScopeKind.UNIT,
        description="Open an owner-tenant dispute review for one's own unit",
    ),
    Permission(
        "iam.residency.override",
        frozenset({SECRETARY}),
        description="Override a residency decision (never the treasurer, PRD 5.1)",
        sensitive=True,
    ),
    Permission(
        "iam.directory.read_phone",
        frozenset({SECRETARY}),
        description="Read phone numbers of members (never the guard, PRD 5.1)",
        sensitive=True,
    ),
)

permissions: Final = (*MATRIX_PERMISSIONS, *IDENTITY_PERMISSIONS)
