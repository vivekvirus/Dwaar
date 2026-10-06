"""Every module-local permission is classified against the PRD 5.2 matrix, and docs/permissions-gaps.md lists everything the PRD does not specify.

REQ: PRD 5.1, PRD 5.2, IAM-08, IAM-13, INV-01.

No database: the registry is built from the module discovery with throw-away settings (nothing connects).
"""

from __future__ import annotations

import pathlib

import pytest

from dwaar_api.core.config import load_settings
from dwaar_api.main import create_app
from dwaar_api.modules.identity import matrix
from dwaar_api.modules.identity.permission_basis import BASIS, GENERATED_PREFIXES

pytestmark = pytest.mark.req("IAM-08", "IAM-13", "INV-01")

DOC = pathlib.Path(__file__).resolve().parents[3] / "docs" / "permissions-gaps.md"


@pytest.fixture(scope="module")
def registry():  # type: ignore[no-untyped-def]
    settings = load_settings(
        {
            "DWAAR_ENV": "test",
            "DWAAR_DATABASE_URL": "postgresql://dwaar_app:x@127.0.0.1:1/x",
            "DWAAR_CURSOR_SIGNING_KEY": "k" * 40,
        }
    )
    return create_app(settings).state.permissions


def local(registry) -> dict[str, frozenset[str]]:  # type: ignore[no-untyped-def]
    items = registry.all() if hasattr(registry, "all") else list(registry)
    return {
        p.action: frozenset(p.roles) for p in items if not p.action.startswith(GENERATED_PREFIXES)
    }


def test_every_local_permission_is_classified_and_nothing_stale_is_listed(registry) -> None:  # type: ignore[no-untyped-def]
    actual = local(registry)
    assert set(actual) - set(BASIS) == set(), (
        f"permissions without a reviewed basis: {sorted(set(actual) - set(BASIS))}"
    )
    assert set(BASIS) - set(actual) == set(), (
        f"basis lines for permissions that no longer exist: {sorted(set(BASIS) - set(actual))}"
    )


def test_the_registered_roles_are_exactly_what_the_basis_derives(registry) -> None:  # type: ignore[no-untyped-def]
    actual = local(registry)
    wrong = {
        action: (sorted(actual[action]), sorted(basis.roles()))
        for action, basis in BASIS.items()
        if action in actual and actual[action] != basis.roles()
    }
    assert wrong == {}, (
        f"role sets that drifted from their PRD cells (registered, derived): {wrong}"
    )


def test_a_basis_never_claims_a_role_the_cells_already_give_and_only_known_roles(registry) -> None:  # type: ignore[no-untyped-def]
    for action, basis in BASIS.items():
        derived = (
            frozenset().union(*(matrix.roles_for(c, v) for c, v in basis.cells))
            if basis.cells
            else frozenset()
        )
        assert not (basis.extra & derived), (
            f"{action}: extra {sorted(basis.extra & derived)} is already given by the cells"
        )
        assert basis.narrowed <= derived, (
            f"{action}: narrows roles no cell gives: {sorted(basis.narrowed - derived)}"
        )
        known = matrix.ALL_ROLES | {"platform_admin"}
        assert (basis.extra | basis.narrowed) <= known, f"{action}: unknown role names"
        for capability, verb in basis.cells:
            assert matrix.roles_for(capability, verb), (
                f"{action}: no such matrix cell {capability}.{verb}"
            )


def test_guard_sup_has_no_matrix_column_so_every_grant_to_it_is_a_listed_gap(registry) -> None:  # type: ignore[no-untyped-def]
    actual = local(registry)
    for action, roles in actual.items():
        if matrix.GUARD_SUP in roles:
            assert matrix.GUARD_SUP in BASIS[action].extra, action
    text = DOC.read_text(encoding="utf-8")
    for action, roles in actual.items():
        if matrix.GUARD_SUP in roles:
            assert f"`{action}`" in text, (
                f"{action} grants GUARD_SUP but is missing from docs/permissions-gaps.md"
            )


def test_the_gaps_document_lists_every_permission_that_needs_the_owners_confirmation() -> None:
    text = DOC.read_text(encoding="utf-8")
    missing = [a for a, b in BASIS.items() if b.needs_owner_confirmation and f"`{a}`" not in text]
    assert missing == [], f"docs/permissions-gaps.md does not list: {missing}"
    exact = [a for a, b in BASIS.items() if not b.needs_owner_confirmation]
    assert exact, "some permissions are derived exactly from a PRD cell"
    assert "owner" in text.lower()
    assert "confirm" in text.lower()
