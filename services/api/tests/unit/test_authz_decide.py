"""The pure authorisation decision: which grant authorises an action, and what derived scope results."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from dwaar_api.core.authn import Principal
from dwaar_api.core.authz import (
    Grant,
    InMemoryGrantResolver,
    Permission,
    PermissionRegistry,
    ScopeKind,
    decide,
)
from dwaar_api.core.config import ConfigError
from dwaar_common.errors import InvalidSchema, NotAuthorised, NotFound

pytestmark = pytest.mark.req("INV-01", "IAM-08", "IAM-13")

A, B, C = (uuid.UUID(int=n) for n in (0xA, 0xB, 0xC))
U1, U2 = uuid.UUID(int=0x11), uuid.UUID(int=0x12)
P1, P2 = uuid.UUID(int=0x21), uuid.UUID(int=0x22)
NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.UTC)
HOUR = dt.timedelta(hours=1)

SOCIETY_ACTION = Permission("billing.post", frozenset({"committee", "treasurer"}))
UNIT_ACTION = Permission("dues.read", frozenset({"committee", "owner"}), scope=ScopeKind.UNIT)
PERSON_ACTION = Permission(
    "profile.read", frozenset({"committee", "owner"}), scope=ScopeKind.PERSON
)


def run(permission: Permission, grants: list[Grant], **kwargs: object):  # type: ignore[no-untyped-def]
    kwargs.setdefault("society_hint", None)
    return decide(permission, grants, now=NOW, **kwargs)  # type: ignore[arg-type]


def test_society_wide_grant_authorises_society_scoped_action() -> None:
    scope = run(SOCIETY_ACTION, [Grant("committee", A)])
    assert (scope.society_id, scope.role, scope.kind, scope.society_wide) == (
        A,
        "committee",
        ScopeKind.SOCIETY,
        True,
    )
    assert scope.unit_ids == frozenset()


def test_unit_scoped_grant_does_not_authorise_a_society_scoped_action() -> None:
    with pytest.raises(NotAuthorised):
        run(SOCIETY_ACTION, [Grant("committee", A, unit_id=U1)])


def test_a_role_that_may_not_do_it_is_not_authorised() -> None:
    with pytest.raises(NotAuthorised):
        run(SOCIETY_ACTION, [Grant("owner", A, unit_id=U1)])


def test_no_standing_at_all_is_not_found_never_forbidden() -> None:
    with pytest.raises(NotFound):
        run(SOCIETY_ACTION, [])
    with pytest.raises(NotFound):
        run(
            SOCIETY_ACTION, [Grant("committee", B)], society_hint=A
        )  # a hint cannot create standing
    with pytest.raises(NotFound):
        run(SOCIETY_ACTION, [Grant("committee", A, expires_at=NOW - HOUR)])
    with pytest.raises(NotFound):
        run(SOCIETY_ACTION, [Grant("committee", A, not_before=NOW + HOUR)])


def test_grant_boundaries_are_half_open() -> None:
    assert (
        run(SOCIETY_ACTION, [Grant("committee", A, not_before=NOW)]).society_id == A
    )  # active from not_before
    with pytest.raises(NotFound):
        run(SOCIETY_ACTION, [Grant("committee", A, expires_at=NOW)])  # expires AT expires_at


def test_several_societies_need_an_explicit_valid_hint() -> None:
    grants = [Grant("committee", A), Grant("committee", B)]
    with pytest.raises(InvalidSchema):
        run(SOCIETY_ACTION, grants)
    assert run(SOCIETY_ACTION, grants, society_hint=B).society_id == B
    with pytest.raises(NotFound):
        run(SOCIETY_ACTION, grants, society_hint=C)


def test_hint_for_a_society_where_the_role_lacks_the_permission_is_forbidden_not_hidden() -> None:
    grants = [Grant("committee", A), Grant("owner", B, unit_id=U1)]
    with pytest.raises(NotAuthorised):
        run(SOCIETY_ACTION, grants, society_hint=B)


def test_unit_scope_coverage() -> None:
    owner = [Grant("owner", A, unit_id=U1)]
    scope = run(UNIT_ACTION, owner, unit_target=U1)
    assert (scope.role, scope.unit_id, scope.society_wide) == ("owner", U1, False)
    assert scope.unit_ids == frozenset({U1})
    assert scope.covers_unit(U1)
    assert not scope.covers_unit(U2)
    with pytest.raises(NotFound):  # someone else's unit looks exactly like a missing one
        run(UNIT_ACTION, owner, unit_target=U2)
    assert run(UNIT_ACTION, [Grant("committee", A)], unit_target=U2).society_wide is True


def test_unit_action_without_a_target_lists_what_the_caller_may_see() -> None:
    scope = run(UNIT_ACTION, [Grant("owner", A, unit_id=U1), Grant("owner", A, unit_id=U2)])
    assert scope.unit_ids == frozenset({U1, U2})
    assert scope.unit_id is None
    with pytest.raises(NotAuthorised):  # a person-only grant covers no unit at all
        run(UNIT_ACTION, [Grant("owner", A, person_id=P1)])


def test_person_scope_is_self_service() -> None:
    own = [Grant("owner", A, person_id=P1)]
    assert run(PERSON_ACTION, own, person_target=P1).person_id == P1
    with pytest.raises(NotFound):
        run(PERSON_ACTION, own, person_target=P2)
    assert run(PERSON_ACTION, [Grant("committee", A)], person_target=P2).society_wide is True


def test_most_specific_privilege_wins_deterministically() -> None:
    grants = [Grant("owner", A, unit_id=U1), Grant("committee", A), Grant("treasurer", A)]
    first = run(UNIT_ACTION, grants, unit_target=U1)
    assert first.role == "committee"  # the society-wide grant is preferred
    assert run(UNIT_ACTION, list(reversed(grants)), unit_target=U1).role == first.role
    assert run(SOCIETY_ACTION, grants).role == "committee"  # alphabetical among society-wide grants


def test_kind_reports_the_breadth_of_the_authorising_grant() -> None:
    assert run(UNIT_ACTION, [Grant("committee", A)], unit_target=U1).kind is ScopeKind.SOCIETY
    assert run(UNIT_ACTION, [Grant("owner", A, unit_id=U1)], unit_target=U1).kind is ScopeKind.UNIT


# ----------------------------------------------------------------------------- registry and fakes
def test_permission_validation() -> None:
    for action in ("nodots", "Upper.case", "a..b", ".a", "a.", "a b.c", ""):
        with pytest.raises(ValueError, match=r"module\.verb"):
            Permission(action, frozenset({"x"}))
    with pytest.raises(ValueError, match="at least one role"):
        Permission("a.b", frozenset())
    with pytest.raises(ValueError, match="invalid role"):
        Permission("a.b", frozenset({"Bad Role"}))
    assert Permission("a.b_c.d", frozenset({"x"})).roles == frozenset({"x"})


def test_registry_is_idempotent_for_identical_and_strict_for_conflicting_definitions() -> None:
    registry = PermissionRegistry([SOCIETY_ACTION])
    registry.extend([SOCIETY_ACTION, UNIT_ACTION])
    assert len(registry) == 2
    assert "billing.post" in registry
    assert registry.get("nope.nope") is None
    assert [p.action for p in registry] == ["billing.post", "dues.read"]
    with pytest.raises(ConfigError):
        registry.register(Permission("billing.post", frozenset({"anyone"})))


def test_in_memory_resolver_records_calls_and_isolates_people() -> None:
    resolver = InMemoryGrantResolver()
    me = Principal("s", P1)
    other = Principal("t", P2)
    resolver.add(P1, Grant("owner", A))
    assert [g.role for g in resolver.resolve(me, society_hint=A, fresh=True)] == ["owner"]
    assert resolver.resolve(other, society_hint=None, fresh=False) == ()
    assert resolver.calls == [(P1, A, True), (P2, None, False)]
    resolver.clear(P1)
    assert resolver.resolve(me, society_hint=None, fresh=False) == ()
