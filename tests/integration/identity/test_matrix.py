"""PRD 5.2 permission matrix and 5.1 denied-by-default rules, table-driven from the printed rows (SEC-10 role-matrix tests).

The PRD table below is transcribed INDEPENDENTLY of ``dwaar_api.modules.identity.matrix``: cells are the strings as
printed, expectations are written per cell kind here, so a wrong cell in the module (or a wrong reading of one) fails.
"""

from __future__ import annotations

import uuid

import pytest

from dwaar_api.core.authz import Grant, PermissionRegistry, ScopeKind, decide
from dwaar_api.modules.identity import matrix, permissions
from dwaar_common.errors import NotAuthorised, NotFound
from tests.integration.identity._support import IdentityHarness

ROLES = ["secretary", "treasurer", "committee", "estate_mgr", "guard", "auditor", "owner_occ", "owner_nr", "tenant", "family"]
RESIDENTS = {"owner_occ", "owner_nr", "tenant", "family"}
# PRD 5.2, columns SECRETARY TREASURER COMMITTEE ESTATE_MGR GUARD AUDITOR OWNER_OCC OWNER_NR TENANT FAMILY
PRD_5_2 = {
    "society_config": ["F", "R", "R", "R", "N", "R", "N", "N", "N", "N"],
    "unit_register": ["F", "R", "R", "R", "Masked R", "N", "O", "O", "O", "O"],  # AUDITOR cell empty in the source: N
    "verify_tenancy": ["A", "N", "N", "N", "N", "N", "A (own unit)", "A (own unit)", "N", "N"],
    "gate_ops": ["R", "N", "R", "R", "F", "N", "O", "N", "O", "O"],
    "visitor_passes": ["N", "N", "N", "N", "N", "N", "O", "N", "O", "O"],
    "helpdesk": ["F", "R", "R", "F", "Create", "N", "O", "O", "O", "O"],
    "bill_runs": ["M", "C", "R", "N", "N", "R", "O (bills)", "O (bills)", "O (if liable)", "N"],
    "journals": ["M", "C", "R", "M (requests)", "N", "R", "N", "N", "N", "N"],
    "meetings": ["F", "R", "R", "N", "N", "R", "Vote if entitled", "Vote if entitled", "N", "N"],
    "notices": ["F", "R", "Draft", "Draft", "N", "N", "R", "R", "R", "R"],
    "privacy": ["F", "N", "N", "N", "N", "N", "O", "O", "O", "O"],
    "audit_log": ["R", "R", "R", "N", "N", "R", "O (about them)", "O", "O", "O"],
}
WRITE_VERBS = ("manage", "make", "check", "approve", "create", "draft")
SOC = uuid.UUID("0192f300-0000-7000-8000-00000000000a")
U1 = uuid.UUID("0192f300-0000-7000-8000-0000000000a1")
U2 = uuid.UUID("0192f300-0000-7000-8000-0000000000a2")
ME = uuid.UUID("0192f300-0000-7000-8000-0000000000e1")
registry = PermissionRegistry(permissions)

pytestmark = pytest.mark.req("IAM-03", "INV-01")


def grant(role: str) -> Grant:
    if role in RESIDENTS:
        return Grant(role, SOC, unit_id=U1, person_id=ME)  # what a verified membership resolves to
    return Grant(role, SOC)


def allowed(role: str, action: str) -> bool:
    perm = registry.get(action)
    if perm is None:
        return False
    try:
        decide(perm, [grant(role)], society_hint=SOC, unit_target=U1 if perm.scope is ScopeKind.UNIT else None,
               person_target=ME if perm.scope is ScopeKind.PERSON else None)
    except (NotAuthorised, NotFound):
        return False
    return True


def act(cap: str, verb: str) -> str:
    return f"matrix.{cap}.{verb}"


CELLS = [(cap, role, cell) for cap, row in PRD_5_2.items() for role, cell in zip(ROLES, row, strict=True)]


@pytest.mark.parametrize(("cap", "role", "cell"), CELLS, ids=[f"{c}-{r}-{x}" for c, r, x in CELLS])
def test_every_cell_of_the_prd_matrix(cap: str, role: str, cell: str) -> None:
    # REQ: IAM-03 INV-01 (PRD 5.2)
    def verbs_allowed(*verbs: str) -> None:
        for v in verbs:
            assert allowed(role, act(cap, v)), f"{role} should {v} {cap} ({cell})"

    def verbs_denied(*verbs: str) -> None:
        for v in verbs:
            assert not allowed(role, act(cap, v)), f"{role} must NOT {v} {cap} ({cell})"

    if cell == "N":
        verbs_denied("read", "read_own", "read_masked", *WRITE_VERBS, "approve_own", "vote")
    elif cell == "F":
        verbs_allowed("read", "manage")
        verbs_denied("read_masked", "read_own") if False else None
    elif cell == "R":
        verbs_allowed("read")
        verbs_denied(*WRITE_VERBS)
    elif cell == "Masked R":
        verbs_allowed("read_masked")
        verbs_denied("read", *WRITE_VERBS)
    elif cell.startswith("O"):
        verbs_allowed("read_own")
        verbs_denied("read", *WRITE_VERBS)
    elif cell == "A":
        verbs_allowed("approve")
        verbs_denied("manage", "make", "check")
    elif cell == "A (own unit)":
        verbs_allowed("approve_own")
        verbs_denied("approve", "manage", "read")
    elif cell == "M":
        verbs_allowed("make")
        verbs_denied("check", "approve", "manage")
    elif cell == "C":
        verbs_allowed("check")
        verbs_denied("make", "approve", "manage")
    elif cell == "M (requests)":
        verbs_allowed("make")
        verbs_denied("check", "approve", "manage")
    elif cell == "Create":
        verbs_allowed("create")
        verbs_denied("manage", "read")
    elif cell == "Draft":
        verbs_allowed("draft")
        verbs_denied("manage")
    elif cell == "Vote if entitled":
        verbs_allowed("vote")
        verbs_denied("manage", "read")
    else:  # pragma: no cover
        raise AssertionError(f"unmodelled cell {cell!r}")


def test_module_data_equals_the_transcribed_prd_table() -> None:
    # REQ: IAM-03
    assert list(matrix.MATRIX_ROLES) == ROLES
    assert {cap: [matrix.MATRIX[cap][r] for r in ROLES] for cap in PRD_5_2} == PRD_5_2


def test_own_scope_cells_do_not_reach_other_units_or_other_people() -> None:
    # REQ: INV-01
    perm = registry.get(act("unit_register", "read_own"))
    assert perm is not None and perm.scope is ScopeKind.UNIT
    with pytest.raises(NotFound):
        decide(perm, [grant("tenant")], society_hint=SOC, unit_target=U2)  # another household's unit
    priv = registry.get(act("privacy", "read_own"))
    assert priv is not None and priv.scope is ScopeKind.PERSON
    with pytest.raises(NotFound):
        decide(priv, [grant("tenant")], society_hint=SOC, person_target=uuid.uuid4())  # someone else's record


def test_roles_without_a_matrix_column_have_no_matrix_permission() -> None:
    # REQ: IAM-03 (denied by default)
    for role in ("guard_sup", "technician", "vendor_tech", "org_admin", "plat_support", "staff"):
        assert not any(role in p.roles for p in matrix.MATRIX_PERMISSIONS), role


DENIED = list(matrix.DENIED_BY_DEFAULT)


@pytest.mark.parametrize(("role", "action", "why"), DENIED, ids=[f"{r}-{a}" for r, a, _w in DENIED])
def test_prd_5_1_denied_by_default_list(role: str, action: str, why: str) -> None:
    # REQ: IAM-03 INV-01 (AT-02: non-resident owner cannot see the tenant's visitor history)
    assert registry.get(action) is not None, f"{action} must exist so the denial is a decision, not an absence"
    assert not allowed(role, action), why


def test_at02_non_resident_owner_vs_resident_tenant_on_visitor_history() -> None:
    # REQ: IAM-03 INV-01
    history = act("gate_ops", "read_own")
    assert allowed("tenant", history) and allowed("owner_occ", history) and allowed("family", history)
    assert not allowed("owner_nr", history)
    # ... while the non-resident owner keeps their own financial rights
    assert allowed("owner_nr", act("bill_runs", "read_own"))


def test_unknown_action_is_never_allowed_and_registry_has_no_duplicates() -> None:
    # REQ: INV-01
    assert not allowed("secretary", "matrix.nonsense.read")
    assert len({p.action for p in permissions}) == len(permissions)


def test_elevated_role_list_equals_the_database_function(idh: IdentityHarness) -> None:
    # REQ: IAM-03
    for role in sorted(matrix.ALL_ROLES | {"platform_admin", "nonsense"}):
        row = idh.admin_rows("SELECT iam.is_elevated_role(%s)", (role,))[0][0]
        assert row == (role in matrix.ELEVATED_ROLES), role


def test_role_grant_check_constraint_covers_every_assignable_and_platform_role(idh: IdentityHarness) -> None:
    # REQ: IAM-13
    definition = idh.admin_rows(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'role_grants_role_check'"
    )[0][0]
    for role in matrix.ASSIGNABLE_ROLES | matrix.PLATFORM_ROLES:
        assert f"'{role}'" in definition
    for role in matrix.RESIDENT_ROLES:
        assert f"'{role}'" not in definition  # resident roles come from memberships only, never from grants
