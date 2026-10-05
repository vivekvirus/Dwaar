"""The seed dataset itself (PRD 8.3, slice 1 part): shape, honesty, determinism, idempotency, refusal outside local.

These are not acceptance tests of the matrix; they keep the data that AT-01 and AT-02 stand on from rotting.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

import pytest

from dwaar_api import seed
from dwaar_api.seed.dataset import ELEVATED, KA, MH, STAFF_GRANTS
from dwaar_api.seed.people import all_people, by_key, totp_secret
from dwaar_api.seed.runtime import SeedRefused
from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment

pytestmark = [
    pytest.mark.req("SOC-01", "SOC-02", "IAM-01", "IAM-05", "IAM-07", "IAM-12", "ARCH-01")
]


def test_two_societies_with_the_prd_shape(world: World) -> None:
    rows = world.admin_rows(
        "SELECT s.name, s.state, (SELECT count(*) FROM blocks b WHERE b.society_id = s.id),"
        " (SELECT count(*) FROM units u WHERE u.society_id = s.id) FROM societies s ORDER BY s.state"
    )
    assert rows == [
        (KA.name, "Karnataka", 2, 180),
        (MH.name, "Maharashtra", 3, 240),
    ]
    per_block = world.admin_rows(
        "SELECT s.state, b.name, count(u.id) FROM blocks b JOIN societies s ON s.id = b.society_id"
        " JOIN units u ON u.block_id = b.id GROUP BY 1, 2 ORDER BY 1, 2"
    )
    assert per_block == [
        ("Karnataka", "Tower 1", 100),
        ("Karnataka", "Tower 2", 80),
        ("Maharashtra", "A", 100),
        ("Maharashtra", "B", 80),
        ("Maharashtra", "C", 60),
    ]


def test_unit_labels_repeat_across_blocks_but_never_inside_one(world: World) -> None:
    dup = world.admin_rows(
        "SELECT u.society_id, u.label, count(DISTINCT u.block_id) FROM units u GROUP BY 1, 2 HAVING count(DISTINCT u.block_id) > 1"
    )
    assert len(dup) >= 80, "label 101.. must exist in every block of a society"
    inside = world.admin_rows(
        "SELECT 1 FROM units GROUP BY block_id, lower(label) HAVING count(*) > 1"
    )
    assert inside == []


def test_legal_packs_are_selected_and_the_maharashtra_pack_stays_unapproved(world: World) -> None:
    rows = world.admin_rows(
        "SELECT s.state, p.pack_key, p.pack_status, p.approved_by, p.approved_at FROM societies s"
        " JOIN legal_packs p ON p.id = s.legal_pack_id ORDER BY 1"
    )
    assert [(r[0], r[1], r[2], r[3], r[4]) for r in rows] == [
        ("Karnataka", "karnataka-aoa-1972", "unapproved", None, None),
        ("Maharashtra", "maharashtra-chs", "unapproved", None, None),
    ]
    secretary = world.login("mh.secretary")
    mh = world.objects("mh").society
    config = world.call(secretary, "GET", f"/v1/societies/{mh}/configuration").json()
    assert config["binding_governance"]["enabled"] is False
    assert "legal_pack_not_approved" in config["binding_governance"]["blockers"]
    refused = world.call(
        secretary,
        "PUT",
        f"/v1/societies/{mh}/feature-flags/binding_governance",
        json={"enabled": True},
    )
    assert refused.status_code == 422 and refused.json()["code"] == "legal_pack_not_approved"


def test_only_invented_identities_on_reserved_fictional_numbers(world: World) -> None:
    people = all_people()
    assert len(people) == len({p.phone for p in people}) == len({p.key for p in people})
    assert all(re.fullmatch(r"\+9199999\d{5}", p.phone) for p in people)
    assert all(re.fullmatch(r"\+91999990\d{4}", p.phone) for p in people), (
        "reserved block is +91 99999 0nnnn"
    )
    # no real phone number or e-mail is stored in the clear anywhere the API or a dump would show it
    leaked = world.admin_rows("SELECT 1 FROM iam.persons WHERE phone_token ~ '^\\+?[0-9]{10,13}$'")
    assert leaked == []
    vault = world.admin_rows("SELECT phone_enc FROM iam.person_vault LIMIT 5")
    assert all(not str(r[0]).lstrip("+").isdigit() and str(r[0]).startswith("v") for r in vault)
    assert world.admin_rows("SELECT count(*) FROM iam.persons")[0][0] == len(people)


def test_the_people_scenarios_of_prd_8_3_exist_with_the_right_states(world: World) -> None:
    mh = world.objects("mh")

    def one(person: str, block: str, label: str, kind: str) -> dict[str, Any]:
        mid = world.membership_of(mh.society, person, block, label, kind)
        row = world.admin_rows(
            "SELECT verification, lives_in_unit, billing_liable, owner_decision, ended_at IS NOT NULL FROM memberships WHERE id = %s",
            (mid,),
        )[0]
        return dict(
            zip(("verification", "lives", "liable", "owner_decision", "ended"), row, strict=True)
        )

    # owners with multiple memberships (one lives there, one is let out)
    assert one("sanjay", "A", "402", "owner")["lives"] is True
    assert one("sanjay", "C", "101", "owner")["lives"] is False
    # active tenant with an absent owner: verified by a reasoned waiver, and NO owner membership on that unit
    assert one("imran", "C", "203", "tenant")["verification"] == "verified"
    owners = world.admin_rows(
        "SELECT count(*) FROM memberships WHERE unit_id = %s AND kind IN ('owner', 'joint_owner')",
        (mh.ref.unit("C", "203"),),
    )
    assert owners == [(0,)]
    # disputed move-out: the owner contests, occupancy continues (the tenant is still a grant holder)
    dev = one("dev", "A", "305", "tenant")
    assert dev["verification"] == "disputed" and dev["owner_decision"] == "disputed"
    assert world.admin_rows(
        "SELECT effective FROM iam.person_access_index WHERE source_id = %s",
        (world.membership_of(mh.society, "dev", "A", "305", "tenant"),),
    ) == [(True,)]
    # family approvals: two approved by the owner, one pending, one rejected
    family = Counter(
        one(p, "A", "203", "family")["verification"]
        for p in ("rekha", "aarav", "mohini", "unknown")
    )
    assert family == Counter({"verified": 2, "pending": 1, "rejected": 1})
    # the mover: owner of A-108 ended
    mover = one("vikram", "A", "108", "owner")
    assert mover["ended"] is True
    # a committee hold on a pending tenant onboarding
    held = world.admin_rows(
        "SELECT h.state, m.verification FROM membership_holds h JOIN memberships m ON m.id = h.membership_id"
    )
    assert held == [("active", "pending")]
    # non-resident owners carry liability, tenants do not (recorded, INV-04)
    assert one("smita", "A", "305", "owner")["liable"] is True and dev["liable"] is False


def test_elevated_role_holders_have_a_confirmed_synthetic_second_factor(world: World) -> None:
    holders = sorted({g.person for g in STAFF_GRANTS if g.role in ELEVATED})
    assert len(holders) == 13
    factors = world.admin_rows(
        "SELECT person_id, confirmed_at IS NOT NULL FROM iam.mfa_factors WHERE revoked_at IS NULL"
    )
    assert len(factors) == len(holders) and all(r[1] for r in factors)
    for key in ("mh.secretary", "ka.treasurer", "mh.auditor"):
        session = world.login(key)  # the genuine step-up with the synthetic code works
        me = world.call(session, "GET", "/v1/me").json()
        assert me["mfa"]["confirmed"] is True and me["mfa"]["session_verified"] is True
    guard = world.login("mh.guard1")  # guards are not elevated: no factor, no step-up needed
    assert world.call(guard, "GET", "/v1/me").json()["mfa"]["enrolled"] is False
    assert totp_secret(by_key()["mh.secretary"].phone) != totp_secret(
        by_key()["ka.secretary"].phone
    )


def test_seed_went_through_the_domain_paths_so_audit_and_outbox_exist(world: World) -> None:
    """Every domain row has its audit row and its outbox event (no shortcut skipped them)."""
    audit = Counter(
        r[0]
        for r in world.admin_rows(
            "SELECT operation FROM audit_log WHERE operation NOT LIKE 'read.%%'"
        )
    )
    assert audit["society.create"] == 2
    assert audit["block.create"] == 5
    assert audit["unit.import"] == 2
    memberships = world.admin_rows("SELECT count(*) FROM memberships")[0][0]
    assert audit["membership.request"] == memberships
    assert audit["role_grant.issue"] == len(STAFF_GRANTS)
    assert audit["auth.mfa_seeded"] == 13
    outbox = world.admin_rows("SELECT count(*) FROM outbox")[0][0]
    assert outbox >= memberships * 2
    # grants carry a different issuer than the person (no self-grant), the first secretary from the operator
    self_issued = world.admin_rows("SELECT 1 FROM role_grants WHERE person_id = issued_by")
    assert self_issued == []


def test_a_second_run_changes_nothing(fresh_world: World) -> None:
    w = fresh_world
    before = w.admin_rows(
        "SELECT (SELECT count(*) FROM audit_log), (SELECT count(*) FROM outbox), (SELECT count(*) FROM memberships),"
        " (SELECT count(*) FROM units), (SELECT count(*) FROM role_grants), (SELECT count(*) FROM iam.persons)"
    )
    again = seed.run(seed_environment(w.db), say=lambda _l: None)
    after = w.admin_rows(
        "SELECT (SELECT count(*) FROM audit_log), (SELECT count(*) FROM outbox), (SELECT count(*) FROM memberships),"
        " (SELECT count(*) FROM units), (SELECT count(*) FROM role_grants), (SELECT count(*) FROM iam.persons)"
    )
    assert before == after
    created = {
        k: v
        for k, v in again.counts.items()
        if v
        and k.endswith(
            (
                "_created",
                "_issued",
                "_enrolled",
                "_verified",
                "_ended",
                "_opened",
                "_rejected",
                "_placed",
            )
        )
    }
    assert created == {}, created
    assert again.counts["societies_existing"] == 2 and again.counts["persons_existing"] == len(
        all_people()
    )


def test_ids_are_deterministic_across_databases(
    pg_server: PgServer, template_db: str, world: World
) -> None:
    """Two independent seeds name every society, block, unit and person with the same ids (fixed UUIDv7 time + seed)."""

    def snapshot(w: World) -> dict[str, list[tuple[Any, ...]]]:
        return {
            "societies": w.admin_rows("SELECT id, name FROM societies ORDER BY name"),
            "blocks": w.admin_rows("SELECT id, name FROM blocks ORDER BY society_id, name"),
            "units": w.admin_rows("SELECT id, label FROM units ORDER BY block_id, label"),
            "persons": w.admin_rows(
                "SELECT id, display_name FROM iam.persons ORDER BY display_name, id"
            ),
        }

    first = snapshot(world)
    for handle in _clone(pg_server, template_db):
        other = build_world(handle)
        try:
            second = snapshot(other)
        finally:
            other.database.dispose()
    assert first == second
    assert len(first["units"]) == 420
    # the fixed time is visible in the id itself: 2026-01-01T00:00:00Z = 0x019b7... in the first 48 bits
    assert all(str(r[0]).startswith("019b76da-a800-7") for r in first["units"])


@pytest.mark.parametrize("env", ["test", "staging", "production", "", "LOCAL-ish", "development"])
def test_seed_refuses_outside_local(env: str) -> None:
    with pytest.raises(SeedRefused, match="refusing to seed"):
        seed.run({"DWAAR_ENV": env} if env else {})
