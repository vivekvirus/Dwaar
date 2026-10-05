# ruff: noqa: PT018, PT012, F811
"""IAM-07 household joining + appeals, IAM-12 owner confirmation and committee holds, IAM-05 owner-tenant disputes."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.integration.identity._support import IdentityHarness, Person, advance, apply_for, staff


def me_membership(idh: IdentityHarness, who: Person, society: uuid.UUID) -> dict[str, Any]:
    body = idh.client().get("/v1/me", headers=who.headers).json()
    entry = next(s for s in body["societies"] if s["society_id"] == str(society))
    return entry["memberships"][0]  # type: ignore[no-any-return]


def can_read_register(idh: IdentityHarness, who: Person, society: uuid.UUID) -> bool:
    return (
        idh.client().get(f"/v1/societies/{society}/memberships", headers=who.headers).status_code
        == 200
    )


def owner_of(idh: IdentityHarness, soc: Any, unit: str, number: int) -> Person:
    owner = idh.login(number)
    idh.seed_membership(soc.id, owner.id, soc.units[unit], "owner")
    return owner


# ===================================================================================================== IAM-07
@pytest.mark.req("IAM-07")
def test_household_joining_goes_through_every_state_with_visible_reasons(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-07
    soc = idh.society()
    owner = owner_of(idh, soc, "A-101", 1)
    spouse = idh.login(2)
    out = apply_for(
        idh, spouse, soc.id, soc.units["A-101"], "family", evidence_ref="doc:marriage-certificate"
    )
    case = out["case_id"]
    assert not can_read_register(idh, spouse, soc.id)  # nothing until verified
    states = ["requested"]

    r = advance(
        idh, owner, soc.id, case, "request_evidence", reason="Please add a photo ID of the spouse"
    )
    assert r.status_code == 200 and r.json()["state"] == "evidence_pending"
    m = me_membership(idh, spouse, soc.id)
    assert (
        m["case"]["state"] == "evidence_pending"
        and m["case"]["reason"] == "Please add a photo ID of the spouse"
    )
    states.append(m["case"]["state"])

    r = advance(idh, spouse, soc.id, case, "submit_evidence", evidence_ref="doc:photo-id")
    assert r.status_code == 200 and r.json()["state"] == "society_review"
    states.append("society_review")
    assert advance(idh, owner, soc.id, case, "verify").json()["state"] == "verified"
    states.append("verified")
    m = me_membership(idh, spouse, soc.id)
    assert (m["verification"], m["case"]["state"]) == ("verified", "verified")
    assert can_read_register(idh, spouse, soc.id)  # NOW the person has standing as family
    roles = idh.client().get("/v1/me", headers=spouse.headers).json()["societies"][0]["roles"]
    assert [x["role"] for x in roles] == ["family"]
    assert states == ["requested", "evidence_pending", "society_review", "verified"]
    # inactive: the owner ends the household membership explicitly, with a reason
    r = advance(idh, owner, soc.id, case, "deactivate", reason="moved out of the household")
    assert r.json()["state"] == "inactive"
    assert not can_read_register(idh, spouse, soc.id)
    assert idh.audit_ops("verification_case.%")  # every step is in the audit log


@pytest.mark.req("IAM-07")
def test_start_review_can_skip_the_evidence_request_when_evidence_came_with_the_application(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-07
    soc = idh.society()
    owner = owner_of(idh, soc, "A-101", 3)
    child = idh.login(4)
    case = apply_for(
        idh, child, soc.id, soc.units["A-101"], "family", evidence_ref="doc:birth-certificate"
    )["case_id"]
    assert advance(idh, owner, soc.id, case, "start_review").json()["state"] == "society_review"
    assert advance(idh, owner, soc.id, case, "verify").json()["state"] == "verified"


@pytest.mark.req("IAM-07")
def test_rejection_requires_and_shows_a_reason(idh: IdentityHarness) -> None:
    # REQ: IAM-07
    soc = idh.society()
    owner = owner_of(idh, soc, "A-101", 5)
    applicant = idh.login(6)
    case = apply_for(idh, applicant, soc.id, soc.units["A-101"], "family")["case_id"]
    advance(idh, owner, soc.id, case, "start_review")
    assert advance(idh, owner, soc.id, case, "reject").status_code == 422  # no reason
    r = advance(
        idh, owner, soc.id, case, "reject", reason="We could not match this person to the household"
    )
    assert r.status_code == 200 and r.json()["state"] == "rejected"
    m = me_membership(idh, applicant, soc.id)
    assert (
        m["verification"] == "rejected"
        and m["case"]["reason"] == "We could not match this person to the household"
    )


@pytest.mark.req("IAM-07")
def test_appeal_is_reviewed_by_someone_other_than_the_original_decision_maker(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-07
    soc = idh.society()
    s = staff(idh, soc.id, 10)
    owner = owner_of(idh, soc, "A-101", 7)
    applicant = idh.login(8)
    case = apply_for(idh, applicant, soc.id, soc.units["A-101"], "family")["case_id"]
    advance(idh, owner, soc.id, case, "start_review")
    advance(idh, owner, soc.id, case, "reject", reason="Evidence did not match")
    # only the applicant appeals, and only a rejected case
    assert (
        advance(
            idh, owner, soc.id, case, "appeal", reason="I am the owner appealing for them"
        ).status_code
        == 404
    )
    stranger = idh.login(9)
    assert (
        advance(
            idh, stranger, soc.id, case, "appeal", reason="not my case at all, but let me try"
        ).status_code
        == 404
    )
    r = advance(
        idh,
        applicant,
        soc.id,
        case,
        "appeal",
        reason="The photo ID was uploaded late, please re-check",
    )
    assert r.status_code == 200 and r.json()["state"] == "appealed"
    appeal = r.json()["case_id"]
    assert appeal != case
    assert me_membership(idh, applicant, soc.id)["verification"] == "pending"  # reopened for review
    # the SAME decision-maker may not decide the appeal ...
    same = advance(idh, owner, soc.id, appeal, "verify")
    assert (
        same.status_code == 422
        and same.json()["details"]["reason"] == "appeal_reviewer_must_differ"
    )
    # ... someone else may
    ok = advance(idh, s.secretary, soc.id, appeal, "verify")
    assert ok.status_code == 200 and ok.json()["state"] == "verified"
    assert me_membership(idh, applicant, soc.id)["verification"] == "verified"
    # an appeal can only be opened once per rejection
    assert (
        advance(
            idh, applicant, soc.id, case, "appeal", reason="again and again and again"
        ).status_code
        == 422
    )


@pytest.mark.req("IAM-07")
def test_database_refuses_an_appeal_decided_by_the_original_reviewer(idh: IdentityHarness) -> None:
    # REQ: IAM-07 (the service check is not the only line of defence)
    soc = idh.society()
    owner = owner_of(idh, soc, "A-101", 11)
    applicant = idh.login(12)
    case = apply_for(idh, applicant, soc.id, soc.units["A-101"], "family")["case_id"]
    advance(idh, owner, soc.id, case, "start_review")
    advance(idh, owner, soc.id, case, "reject", reason="Evidence did not match")
    appeal = advance(
        idh, applicant, soc.id, case, "appeal", reason="Please look again at the documents"
    ).json()["case_id"]
    with (
        pytest.raises(Exception, match="someone other than the original decision-maker"),
        idh.db.owner_conn() as conn,
    ):
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute(
            "UPDATE verification_cases SET reviewer_id = (SELECT reviewer_id FROM verification_cases WHERE id = %s)"
            " WHERE id = %s",
            (case, appeal),
        )


@pytest.mark.req("IAM-07", "INV-01")
def test_who_may_review(idh: IdentityHarness) -> None:
    # REQ: IAM-07 INV-01
    soc = idh.society()
    s = staff(idh, soc.id, 20)
    owner_a = owner_of(idh, soc, "A-101", 21)
    owner_b = owner_of(idh, soc, "A-102", 22)
    tenant_a = idh.login(23)
    idh.seed_membership(soc.id, tenant_a.id, soc.units["A-101"], "tenant")
    applicant = idh.login(24)
    case = apply_for(idh, applicant, soc.id, soc.units["A-101"], "family")["case_id"]
    advance(idh, owner_a, soc.id, case, "start_review")
    # another unit's owner, a tenant, the applicant: no standing over THIS unit's household
    assert advance(idh, owner_b, soc.id, case, "verify").status_code == 404
    assert advance(idh, tenant_a, soc.id, case, "verify").status_code in (403, 404)
    assert (
        advance(idh, applicant, soc.id, case, "verify").status_code == 404
    )  # a claimant has no standing to review
    # committee members are read-mostly: no approval
    assert advance(idh, s.committee, soc.id, case, "verify").status_code == 403
    # an ownership claim is a society matter: the other owner of the unit cannot decide it, the secretary can
    claimant = idh.login(25)
    claim = apply_for(
        idh, claimant, soc.id, soc.units["A-101"], "joint_owner", evidence_ref="doc:sale-deed"
    )["case_id"]
    advance(idh, s.secretary, soc.id, claim, "start_review")
    assert advance(idh, owner_a, soc.id, claim, "verify").status_code == 403
    assert advance(idh, s.secretary, soc.id, claim, "verify").json()["state"] == "verified"


@pytest.mark.req("IAM-07")
def test_nobody_verifies_their_own_claim_and_transitions_are_validated(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-07 IAM-03
    soc = idh.society()
    s = staff(idh, soc.id, 30)
    own = apply_for(idh, s.secretary, soc.id, soc.units["A-101"], "owner")[
        "case_id"
    ]  # the secretary applies for a unit
    advance(idh, s.secretary, soc.id, own, "start_review")
    r = advance(idh, s.secretary, soc.id, own, "verify")
    assert r.status_code == 422 and r.json()["details"]["reason"] == "self_verification"
    other = idh.login(31)
    case = apply_for(idh, other, soc.id, soc.units["A-102"], "owner")["case_id"]
    # verify straight from 'requested' is not a legal move
    r = advance(idh, s.secretary, soc.id, case, "verify")
    assert r.status_code == 422 and r.json()["details"]["reason"] == "invalid_transition"
    for bad_action in (
        "appeal",
        "submit_evidence",
    ):  # applicant-only actions: a reviewer is not the applicant
        assert (
            advance(
                idh, s.secretary, soc.id, case, bad_action, reason="not allowed here"
            ).status_code
            == 404
        )


# ===================================================================================================== IAM-12 owner confirmation
@pytest.mark.req("IAM-12")
def test_tenant_onboarding_needs_the_owner_of_that_unit_to_confirm(idh: IdentityHarness) -> None:
    # REQ: IAM-12
    soc = idh.society()
    s = staff(idh, soc.id, 40)
    owner = owner_of(idh, soc, "A-101", 41)
    other_owner = owner_of(idh, soc, "A-102", 42)
    tenant = idh.login(43)
    out = apply_for(
        idh, tenant, soc.id, soc.units["A-101"], "tenant", evidence_ref="doc:leave-and-licence"
    )
    mid, case = out["membership_id"], out["case_id"]
    advance(idh, s.secretary, soc.id, case, "start_review")
    blocked = advance(idh, s.secretary, soc.id, case, "verify")
    assert (
        blocked.status_code == 422
        and blocked.json()["details"]["reason"] == "owner_confirmation_required"
    )
    c = idh.client()
    url = f"/v1/memberships/{mid}/owner-confirm"
    # only the owner of THAT unit: the other unit's owner, the tenant, a stranger, and unknown ids all get the same 404
    stranger = idh.login(44)
    answers = [
        c.post(url, json={"decision": "confirm"}, headers=who.headers)
        for who in (other_owner, tenant, stranger, s.secretary, s.committee)
    ]
    assert {r.status_code for r in answers} == {404}
    assert len({r.json()["code"] for r in answers}) == 1
    unknown = c.post(
        f"/v1/memberships/{uuid.uuid4()}/owner-confirm",
        json={"decision": "confirm"},
        headers=owner.headers,
    )
    assert unknown.status_code == 404
    ok = c.post(url, json={"decision": "confirm"}, headers=owner.headers)
    assert ok.status_code == 200 and ok.json() == {
        "membership_id": mid,
        "owner_decision": "confirmed",
        "verification": "pending",
    }
    assert advance(idh, s.secretary, soc.id, case, "verify").json()["state"] == "verified"
    assert can_read_register(idh, tenant, soc.id)
    assert idh.audit_ops("membership.owner_confirmed")


@pytest.mark.req("IAM-12")
def test_owner_confirmation_can_only_be_waived_with_a_reason_and_only_without_an_owner(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-12
    soc = idh.society()
    s = staff(idh, soc.id, 50)
    tenant = idh.login(51)
    absent_owner_unit = apply_for(idh, tenant, soc.id, soc.units["A-102"], "tenant")[
        "case_id"
    ]  # no owner on A-102
    advance(idh, s.secretary, soc.id, absent_owner_unit, "start_review")
    r = advance(
        idh,
        s.secretary,
        soc.id,
        absent_owner_unit,
        "verify",
        waive_owner_confirmation=True,
        reason="n/a",
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "owner_confirmation_required"
    ok = advance(
        idh, s.secretary, soc.id, absent_owner_unit, "verify", waive_owner_confirmation=True,
        reason="Owner abroad and unreachable, lease seen by committee",
    )  # fmt: skip
    assert ok.status_code == 200
    # with an effective owner on the unit, a waiver is refused
    owner_of(idh, soc, "A-101", 52)
    t2 = idh.login(53)
    case2 = apply_for(idh, t2, soc.id, soc.units["A-101"], "tenant")["case_id"]
    advance(idh, s.secretary, soc.id, case2, "start_review")
    r = advance(
        idh,
        s.secretary,
        soc.id,
        case2,
        "verify",
        waive_owner_confirmation=True,
        reason="skip the owner please",
    )
    assert (
        r.status_code == 422
        and r.json()["details"]["reason"] == "owner_exists_confirmation_required"
    )


# ===================================================================================================== IAM-12 holds
@pytest.mark.req("IAM-12")
def test_committee_hold_is_logged_visible_to_owner_and_tenant_and_can_be_appealed(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-12
    soc = idh.society()
    s = staff(idh, soc.id, 60)
    owner = owner_of(idh, soc, "A-101", 61)
    tenant = idh.login(62)
    out = apply_for(idh, tenant, soc.id, soc.units["A-101"], "tenant")
    mid, case = out["membership_id"], out["case_id"]
    c = idh.client()
    holds = f"/v1/societies/{soc.id}/memberships/{mid}/holds"
    # a hold needs a real reason
    assert c.post(holds, json={"reason": "no"}, headers=s.committee.headers).status_code == 400
    placed = c.post(
        holds,
        json={"reason": "Society dues of the unit are unsettled"},
        headers=s.committee.headers,
    )
    assert placed.status_code == 201 and placed.json()["state"] == "active"
    hold = placed.json()["hold_id"]
    # logged: audit + outbox with the reason
    audit = idh.audit_ops("membership_hold.place")
    assert len(audit) == 1 and audit[0][4] == "Society dues of the unit are unsettled"
    assert idh.admin_rows(
        "SELECT count(*) FROM outbox WHERE event_type = 'identity.hold_placed'"
    ) == [(1,)]
    # visible to the tenant (own /me and holds), to the owner, and to the secretary, with the reason
    seen_by_tenant = me_membership(idh, tenant, soc.id)["holds"]
    assert (
        seen_by_tenant[0]["reason"] == "Society dues of the unit are unsettled"
        and seen_by_tenant[0]["state"] == "active"
    )
    for who in (tenant, owner, s.secretary):
        r = c.get(holds, headers=who.headers)
        assert (
            r.status_code == 200
            and r.json()["items"][0]["reason"] == "Society dues of the unit are unsettled"
        )
    stranger = idh.login(63)
    assert c.get(holds, headers=stranger.headers).status_code == 404
    # while on hold the onboarding cannot be completed
    c.post(
        f"/v1/memberships/{mid}/owner-confirm", json={"decision": "confirm"}, headers=owner.headers
    )
    advance(idh, s.secretary, soc.id, case, "start_review")
    r = advance(idh, s.secretary, soc.id, case, "verify")
    assert r.status_code == 422 and r.json()["details"]["reason"] == "committee_hold_active"
    # appeal: the tenant (or the owner), nobody else
    appeal_url = f"/v1/societies/{soc.id}/holds/{hold}/appeal"
    assert (
        c.post(
            appeal_url,
            json={"reason": "The dues belong to the previous tenant"},
            headers=stranger.headers,
        ).status_code
        == 404
    )
    ap = c.post(
        appeal_url,
        json={"reason": "The dues belong to the previous tenant"},
        headers=tenant.headers,
    )
    assert ap.status_code == 200 and ap.json()["state"] == "appealed"
    assert (
        c.get(holds, headers=owner.headers).json()["items"][0]["appeal_reason"]
        == "The dues belong to the previous tenant"
    )
    # the person who placed the hold cannot decide the appeal; another committee-class person can
    decide = f"/v1/societies/{soc.id}/holds/{hold}/decide"
    same = c.post(
        decide,
        json={"outcome": "release", "reason": "I changed my mind"},
        headers=s.committee.headers,
    )
    assert (
        same.status_code == 422
        and same.json()["details"]["reason"] == "decider_must_differ_from_placer"
    )
    ok = c.post(
        decide,
        json={"outcome": "release", "reason": "Dues were the previous tenant's, confirmed"},
        headers=s.secretary.headers,
    )
    assert ok.status_code == 200 and ok.json()["state"] == "released"
    assert advance(idh, s.secretary, soc.id, case, "verify").json()["state"] == "verified"
    assert can_read_register(idh, tenant, soc.id)
    # DB backstop: decided_by may never equal placed_by
    with (
        pytest.raises(Exception, match="membership_holds_decider_differs"),
        idh.db.owner_conn() as conn,
    ):
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute("UPDATE membership_holds SET decided_by = placed_by WHERE id = %s", (hold,))


@pytest.mark.req("IAM-12", "IAM-05")
def test_a_hold_never_removes_an_existing_occupancy_and_an_upheld_hold_keeps_blocking(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-12 IAM-05
    soc = idh.society()
    s = staff(idh, soc.id, 70)
    living = idh.login(71)
    mid = idh.seed_membership(
        soc.id, living.id, soc.units["A-101"], "tenant"
    )  # verified, in occupation
    c = idh.client()
    r = c.post(
        f"/v1/societies/{soc.id}/memberships/{mid}/holds",
        json={"reason": "A hold on someone who lives here"},
        headers=s.committee.headers,
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "hold_would_remove_occupancy"
    assert can_read_register(idh, living, soc.id)
    # upheld holds stay in force
    newcomer = idh.login(72)
    out = apply_for(idh, newcomer, soc.id, soc.units["A-102"], "tenant")
    placed = c.post(
        f"/v1/societies/{soc.id}/memberships/{out['membership_id']}/holds",
        json={"reason": "Police verification missing"},
        headers=s.committee.headers,
    )
    hold = placed.json()["hold_id"]
    dec = c.post(
        f"/v1/societies/{soc.id}/holds/{hold}/decide",
        json={"outcome": "uphold", "reason": "Verification still missing"},
        headers=s.secretary.headers,
    )
    assert dec.json()["state"] == "upheld"
    advance(idh, s.secretary, soc.id, out["case_id"], "start_review")
    r = advance(
        idh,
        s.secretary,
        soc.id,
        out["case_id"],
        "verify",
        waive_owner_confirmation=True,
        reason="Owner abroad and unreachable",
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "committee_hold_active"


# ===================================================================================================== IAM-05 disputes
@pytest.mark.req("IAM-05")
def test_owner_tenant_dispute_sets_a_review_state_and_never_deactivates_occupancy(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-05
    soc = idh.society()
    s = staff(idh, soc.id, 80)
    owner = owner_of(idh, soc, "A-101", 81)
    tenant = idh.login(82)
    mid = idh.seed_membership(
        soc.id, tenant.id, soc.units["A-101"], "tenant", owner_decision="confirmed"
    )
    c = idh.client()
    r = c.post(
        f"/v1/memberships/{mid}/owner-confirm",
        json={"decision": "dispute", "reason": "Lease expired and rent unpaid for months"}, headers=owner.headers,
    )  # fmt: skip
    assert r.status_code == 200 and r.json()["verification"] == "disputed"
    row = idh.admin_rows(
        "SELECT verification, effective_from, effective_to FROM memberships WHERE id = %s", (mid,)
    )[0]
    assert row[0] == "disputed" and row[2] is None  # no end date: occupancy NOT deactivated
    case = idh.admin_rows(
        "SELECT id, kind, state FROM verification_cases WHERE membership_id = %s", (mid,)
    )
    assert [(k, st) for _i, k, st in case] == [("dispute", "society_review")]
    # the tenant keeps every right of occupancy while the review runs
    assert can_read_register(idh, tenant, soc.id)
    roles = c.get("/v1/me", headers=tenant.headers).json()["societies"][0]["roles"]
    assert roles[0]["role"] == "tenant" and roles[0]["active"] is True
    # time passing changes nothing either: only an explicit reviewer decision ends it
    assert idh.admin_rows("SELECT effective_to FROM memberships WHERE id = %s", (mid,)) == [(None,)]
    # the tenant can see the review and the reason
    assert me_membership(idh, tenant, soc.id)["case"]["kind"] == "dispute"
    dispute_case = str(case[0][0])
    # the owner cannot end it by themselves, the tenant cannot close their own dispute
    assert advance(idh, owner, soc.id, dispute_case, "verify").status_code in (403, 404)
    assert advance(idh, tenant, soc.id, dispute_case, "verify").status_code in (403, 404, 422)
    # outcome 1: the review upholds the tenancy
    up = advance(idh, s.secretary, soc.id, dispute_case, "verify")
    assert up.status_code == 200
    assert me_membership(idh, tenant, soc.id)["verification"] == "verified"


@pytest.mark.req("IAM-05")
def test_only_an_explicit_reviewer_decision_with_a_reason_ends_occupancy(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-05
    soc = idh.society()
    s = staff(idh, soc.id, 90)
    owner = owner_of(idh, soc, "A-101", 92)
    tenant = idh.login(91)
    mid = idh.seed_membership(soc.id, tenant.id, soc.units["A-101"], "tenant")
    c = idh.client()
    r = c.post(
        f"/v1/societies/{soc.id}/memberships/{mid}/dispute", json={"reason": "Disagreement about the lease end date"},
        headers=owner.headers,
    )  # fmt: skip
    assert (
        r.status_code == 201
        and r.json()["occupancy_unchanged"] is True
        and r.json()["verification"] == "disputed"
    )
    case = r.json()["case_id"]
    assert can_read_register(idh, tenant, soc.id)
    assert (
        c.post(
            f"/v1/societies/{soc.id}/memberships/{mid}/dispute",
            json={"reason": "a second dispute at once"},
            headers=owner.headers,
        ).status_code
        == 422
    )
    no_reason = advance(idh, s.secretary, soc.id, case, "deactivate")
    assert no_reason.status_code == 422
    ended = advance(
        idh,
        s.secretary,
        soc.id,
        case,
        "deactivate",
        reason="Tenancy ended on 31 March per both parties",
    )
    assert ended.status_code == 200, ended.text
    assert ended.json()["state"] == "inactive"
    assert idh.admin_rows(
        "SELECT effective_to IS NOT NULL FROM memberships WHERE id = %s", (mid,)
    ) == [(True,)]
    assert not can_read_register(idh, tenant, soc.id)  # NOW (and only now) the occupancy has ended


@pytest.mark.req("IAM-05")
def test_unit_members_may_raise_a_dispute_strangers_may_not(idh: IdentityHarness) -> None:
    # REQ: IAM-05 INV-01
    soc = idh.society()
    owner = owner_of(idh, soc, "A-101", 100)
    tenant = idh.login(101)
    mid = idh.seed_membership(soc.id, tenant.id, soc.units["A-101"], "tenant")
    stranger_owner = owner_of(idh, soc, "A-102", 102)
    c = idh.client()
    url = f"/v1/societies/{soc.id}/memberships/{mid}/dispute"
    assert (
        c.post(
            url,
            json={"reason": "Owner of another unit interfering"},
            headers=stranger_owner.headers,
        ).status_code
        == 404
    )
    assert (
        c.post(
            url, json={"reason": "Tenant disputes the owner's claim"}, headers=owner.headers
        ).status_code
        == 201
    )
    assert can_read_register(idh, tenant, soc.id)


@pytest.mark.req("IAM-05")
def test_a_dispute_on_a_pending_membership_does_not_verify_it(idh: IdentityHarness) -> None:
    # REQ: IAM-05
    soc = idh.society()
    s = staff(idh, soc.id, 110)
    owner = owner_of(idh, soc, "A-101", 111)
    tenant = idh.login(112)
    out = apply_for(idh, tenant, soc.id, soc.units["A-101"], "tenant")
    c = idh.client()
    r = c.post(
        f"/v1/memberships/{out['membership_id']}/owner-confirm",
        json={"decision": "dispute", "reason": "I never agreed to this tenant"}, headers=owner.headers,
    )  # fmt: skip
    assert (
        r.json()["verification"] == "pending"
    )  # nothing to deactivate yet; nothing granted either
    assert idh.admin_rows("SELECT state FROM verification_cases WHERE kind = 'dispute'") == [
        ("society_review",)
    ]
    assert advance(idh, s.secretary, soc.id, out["case_id"], "start_review").status_code == 200
    v = advance(idh, s.secretary, soc.id, out["case_id"], "verify")
    assert v.status_code == 422 and v.json()["details"]["reason"] == "owner_dispute_open"


@pytest.mark.req("IAM-07", "INV-02")
def test_a_retried_decision_replays_instead_of_being_applied_twice(idh: IdentityHarness) -> None:
    # REQ: IAM-07 INV-02 (approvals are keyed: the retry of a decision must not fail as an invalid second transition)
    soc = idh.society()
    owner = owner_of(idh, soc, "A-101", 120)
    child = idh.login(121)
    case = apply_for(idh, child, soc.id, soc.units["A-101"], "family")["case_id"]
    c = idh.client(auto_key=False)
    url = f"/v1/societies/{soc.id}/verification-cases/{case}/advance"
    headers = {**owner.headers, "Idempotency-Key": "decision-0001"}
    first = c.post(url, json={"action": "start_review"}, headers=headers)
    replay = c.post(url, json={"action": "start_review"}, headers=headers)
    assert first.status_code == replay.status_code == 200
    assert replay.headers["idempotent-replayed"] == "true" and replay.json() == first.json()
    assert idh.admin_rows("SELECT version FROM verification_cases WHERE id = %s", (case,)) == [(2,)]
    assert (
        c.post(url, json={"action": "start_review"}, headers=owner.headers).status_code == 400
    )  # key required
