"""Authorisation scope is derived ONLY on the server from current grants (INV-01, IAM-08, IAM-13, PRD 12.2).

Never from a society id the client submits, never from role claims in the JWT. Forbidden-to-reveal cases
are indistinguishable 404 not_found responses (no membership oracle).
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api.core.authz import Grant
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    COMMITTEE_B,
    OUTSIDER,
    RESIDENT_A,
    RESIDENT_A2,
    SOCIETY_A,
    SOCIETY_B,
    UNIT_1,
    UNIT_2,
    CoreHarness,
    core_harness,
)

pytestmark = pytest.mark.req("INV-01", "IAM-08", "IAM-13", "ARCH-03")

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


def strip(body: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if k != "request_id"}


def test_roles_in_the_jwt_are_ignored(core: CoreHarness) -> None:
    """A resident whose token CLAIMS to be a platform admin/committee still gets exactly the resident's rights."""
    forged = core.auth(
        RESIDENT_A,
        extra={
            "role": "committee",
            "roles": ["committee", "platform_admin"],
            "society_id": str(SOCIETY_B),
            "permissions": ["*"],
        },
    )
    with core.client() as client:
        denied = client.get(
            f"/v1/probe/{SOCIETY_A}/whoami", headers=forged
        )  # probe.read: committee only
        other_society = client.get(f"/v1/probe/{SOCIETY_B}/whoami", headers=forged)
    assert denied.status_code == 403
    assert denied.json()["code"] == "not_authorised"
    assert other_society.status_code == 404  # no standing in B whatever the token says


def test_client_submitted_society_id_never_selects_the_scope(core: CoreHarness) -> None:
    hostile_body = {"society_id": str(SOCIETY_B), "societyId": str(SOCIETY_B), "role": "committee"}
    with core.client() as client:
        res = client.post(
            f"/v1/probe/{SOCIETY_A}/echo-society", json=hostile_body, headers=core.auth(COMMITTEE_A)
        )
    assert res.status_code == 200
    body = res.json()
    assert body["scope_society_id"] == str(SOCIETY_A)
    assert body["db_context"] == str(
        SOCIETY_A
    )  # and the database context follows the derived scope
    assert str(SOCIETY_B) not in res.text


def test_path_and_header_selectors_are_validated_against_grants(core: CoreHarness) -> None:
    with core.client() as client:
        cross_path = client.get(f"/v1/probe/{SOCIETY_B}/whoami", headers=core.auth(COMMITTEE_A))
        nonexistent = client.get(f"/v1/probe/{uuid.uuid4()}/whoami", headers=core.auth(COMMITTEE_A))
        not_a_uuid = client.get("/v1/probe/not-a-uuid/whoami", headers=core.auth(COMMITTEE_A))
        ok_path = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=core.auth(COMMITTEE_A))
    assert cross_path.status_code == nonexistent.status_code == 404
    assert strip(cross_path.json()) == strip(
        nonexistent.json()
    )  # existing-but-foreign == does-not-exist
    assert not_a_uuid.status_code in (400, 404)
    assert ok_path.status_code == 200
    assert ok_path.json()["society_id"] == str(SOCIETY_A)


def test_header_selector_is_only_a_hint(core: CoreHarness) -> None:
    core.resolver.add(COMMITTEE_A, Grant("committee", SOCIETY_B))  # one person in two societies
    with core.client() as client:
        ambiguous = client.get("/v1/probe/context", headers=core.auth(COMMITTEE_A))
        pick_a = client.get(
            "/v1/probe/context", headers={**core.auth(COMMITTEE_A), "X-Society-Id": str(SOCIETY_A)}
        )
        pick_b = client.get(
            "/v1/probe/context", headers={**core.auth(COMMITTEE_A), "X-Society-Id": str(SOCIETY_B)}
        )
        # a person in ONE society cannot select another one with the header
        sole = client.get("/v1/probe/context", headers=core.auth(COMMITTEE_B))
        foreign = client.get(
            "/v1/probe/context", headers={**core.auth(COMMITTEE_B), "X-Society-Id": str(SOCIETY_A)}
        )
        garbage = client.get(
            "/v1/probe/context", headers={**core.auth(COMMITTEE_B), "X-Society-Id": "x"}
        )
    assert ambiguous.status_code == 400
    assert ambiguous.json()["code"] == "invalid_schema"
    assert pick_a.json()["society_id"] == str(SOCIETY_A)
    assert pick_b.json()["society_id"] == str(SOCIETY_B)
    assert sole.json()["society_id"] == str(SOCIETY_B)  # no hint needed when there is exactly one
    assert foreign.status_code == garbage.status_code == 404
    assert strip(foreign.json()) == strip(garbage.json())


def test_unknown_member_and_forbidden_to_reveal_are_indistinguishable(core: CoreHarness) -> None:
    """Reading a person: committee may read anyone; a resident only themself. Everything else is the same 404."""

    def person_url(person: uuid.UUID) -> str:
        return f"/v1/probe/{SOCIETY_A}/people/{person}"

    with core.client() as client:
        committee_reads_member = client.get(person_url(RESIDENT_A2), headers=core.auth(COMMITTEE_A))
        resident_reads_self = client.get(person_url(RESIDENT_A), headers=core.auth(RESIDENT_A))
        resident_reads_real_neighbour = client.get(
            person_url(RESIDENT_A2), headers=core.auth(RESIDENT_A)
        )
        resident_reads_nobody = client.get(person_url(uuid.uuid4()), headers=core.auth(RESIDENT_A))
        outsider_reads_real_member = client.get(person_url(RESIDENT_A), headers=core.auth(OUTSIDER))
        outsider_reads_nobody = client.get(person_url(uuid.uuid4()), headers=core.auth(OUTSIDER))
    assert committee_reads_member.status_code == 200
    assert resident_reads_self.status_code == 200
    replies = [
        resident_reads_real_neighbour,
        resident_reads_nobody,
        outsider_reads_real_member,
        outsider_reads_nobody,
    ]
    assert [r.status_code for r in replies] == [404] * 4
    assert all(strip(r.json()) == strip(replies[0].json()) for r in replies)
    assert replies[0].json()["code"] == "not_found"


def test_unit_scope_is_checked_against_the_residents_own_units(core: CoreHarness) -> None:
    def unit_url(unit: uuid.UUID) -> str:
        return f"/v1/probe/{SOCIETY_A}/units/{unit}"

    with core.client() as client:
        own = client.get(unit_url(UNIT_1), headers=core.auth(RESIDENT_A))
        neighbour = client.get(unit_url(UNIT_2), headers=core.auth(RESIDENT_A))
        nonexistent = client.get(unit_url(uuid.uuid4()), headers=core.auth(RESIDENT_A))
        committee = client.get(unit_url(UNIT_2), headers=core.auth(COMMITTEE_A))
    assert own.status_code == 200
    assert own.json()["role"] == "resident"
    assert neighbour.status_code == nonexistent.status_code == 404
    assert strip(neighbour.json()) == strip(nonexistent.json())
    assert committee.status_code == 200
    assert committee.json()["kind"] == "society"  # society-wide grant


def test_role_without_the_permission_is_403_but_only_for_members(core: CoreHarness) -> None:
    with core.client() as client:
        member = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=core.auth(RESIDENT_A))
        outsider = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=core.auth(OUTSIDER))
    assert member.status_code == 403
    assert (
        outsider.status_code == 404
    )  # an outsider learns nothing, not even that the society exists


def test_expired_and_future_grants_confer_nothing(core: CoreHarness) -> None:
    expired = uuid.UUID(int=0xE1)
    future = uuid.UUID(int=0xF1)
    core.resolver.add(
        expired, Grant("committee", SOCIETY_A, expires_at=NOW - dt.timedelta(minutes=1))
    )
    core.resolver.add(future, Grant("committee", SOCIETY_A, not_before=NOW + dt.timedelta(hours=1)))
    with core.client() as client:
        a = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=core.auth(expired))
        b = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=core.auth(future))
    assert a.status_code == b.status_code == 404


def test_grants_are_re_resolved_on_every_request_not_cached_in_the_token(core: CoreHarness) -> None:
    """IAM-08: revoking a grant takes effect at once even though the token is still valid for 10 minutes."""
    person = uuid.UUID(int=0xAB)
    core.resolver.add(person, Grant("committee", SOCIETY_A))
    token_headers = core.auth(person, ttl=600)
    with core.client() as client:
        assert client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=token_headers).status_code == 200
        core.resolver.clear(person)
        revoked = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=token_headers)
        core.resolver.add(person, Grant("resident", SOCIETY_A, unit_id=UNIT_1, person_id=person))
        downgraded = client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=token_headers)
    assert revoked.status_code == 404
    assert downgraded.status_code == 403  # now a resident: standing, but no committee rights


def test_sensitive_permissions_force_a_fresh_lookup(core: CoreHarness) -> None:
    with core.client() as client:
        client.get(f"/v1/probe/{SOCIETY_A}/whoami", headers=core.auth(COMMITTEE_A))
        client.get(f"/v1/probe/{SOCIETY_A}/sensitive", headers=core.auth(COMMITTEE_A))
    flags = [fresh for person, _hint, fresh in core.resolver.calls if person == COMMITTEE_A]
    assert flags == [False, True]


def test_effective_role_is_set_in_the_database_context_from_the_grant(core: CoreHarness) -> None:
    with core.client() as client:
        res = client.post(
            f"/v1/probe/{SOCIETY_A}/things",
            json={"name": "ctx"},
            headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "ctx-key-" + uuid.uuid4().hex},
        )
    assert res.status_code == 201
    with core.db.admin_conn() as conn:
        row = conn.execute("SELECT actor_id, effective_role, society_id FROM audit_log").fetchone()
    assert row == (
        COMMITTEE_A,
        "committee",
        SOCIETY_A,
    )  # from the grant, not from anything the client sent


def test_unauthenticated_requests_never_reach_the_resolver(core: CoreHarness) -> None:
    with core.client() as client:
        res = client.get(f"/v1/probe/{SOCIETY_A}/whoami")
    assert res.status_code == 401
    assert core.resolver.calls == []
