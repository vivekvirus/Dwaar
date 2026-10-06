"""Payroll adjustments: proposed by one party, effective only when the household approves; money is integer paise (STAFF-02, INV-02).

REQ: STAFF-02, INV-02, INV-07.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("STAFF-02", "INV-02", "INV-07")]


def _setup(pw: PW):  # type: ignore[no-untyped-def]
    h = pw.household("A-101", tenant=True)
    staff = pw.register_staff()
    eng = pw.engage(h.owner, staff, h.unit)
    return h, staff, eng


def _propose(pw: PW, who, eng, **extra):  # type: ignore[no-untyped-def]
    body = {
        "engagement_id": eng["id"],
        "kind": "bonus",
        "amount_paise": 150_000,
        "period": "2026-10",
        "reason": "Festival bonus for the month",
    }
    body.update(extra)
    return pw.call(who, "POST", "/v1/payroll-adjustments", json=body)


# REQ: STAFF-02
def test_an_adjustment_is_proposed_and_takes_effect_only_when_the_household_approves(
    pw: PW,
) -> None:
    h, staff, eng = _setup(pw)
    r = _propose(pw, pw.estate_mgr, eng)
    assert r.status_code == 201, r.text
    adj = r.json()
    assert (
        adj["state"] == "proposed" and adj["effective"] is False and adj["amount_paise"] == 150_000
    )
    assert adj["proposer_role"] == "estate_mgr"
    decided = pw.call(
        h.owner,
        "POST",
        f"/v1/payroll-adjustments/{adj['id']}/decision",
        json={"decision": "approve", "expected_version": adj["version"]},
    )
    assert decided.status_code == 200
    body = decided.json()
    assert (
        body["state"] == "approved"
        and body["effective"] is True
        and body["decided_by"] == str(h.owner.id)
    )
    assert pw.audit("staff.payroll_approve")[0][1] == h.owner.id
    assert (
        pw.outbox("PayrollAdjustmentApproved", adj["id"])[0]["payload"]["amount_paise"] == 150_000
    )


def test_society_roles_cannot_approve_and_the_secretary_has_no_payroll_access_at_all(
    pw: PW,
) -> None:
    h, staff, eng = _setup(pw)
    adj = _propose(pw, pw.estate_mgr, eng).json()
    body = {"decision": "approve", "expected_version": adj["version"]}
    for who in (pw.estate_mgr, pw.secretary, pw.guard_sup, pw.guard):
        assert (
            pw.call(
                who, "POST", f"/v1/payroll-adjustments/{adj['id']}/decision", json=body
            ).status_code
            == 403
        )
    assert pw.call(pw.secretary, "GET", "/v1/payroll-adjustments").status_code == 403
    assert _propose(pw, pw.secretary, eng).status_code == 403
    assert (
        pw.call(
            h.family, "POST", f"/v1/payroll-adjustments/{adj['id']}/decision", json=body
        ).status_code
        == 403
    )
    assert pw.rows("SELECT state FROM payroll_adjustments")[0][0] == "proposed"


def test_the_household_may_reject_and_the_first_decision_wins(pw: PW) -> None:
    h, staff, eng = _setup(pw)
    adj = _propose(
        pw, h.owner, eng, kind="deduction", amount_paise=20_000, reason="Two days of unpaid leave"
    ).json()
    path = f"/v1/payroll-adjustments/{adj['id']}/decision"
    rej = pw.call(
        h.owner,
        "POST",
        path,
        json={"decision": "reject", "expected_version": 1, "note": "Not agreed"},
    )
    assert (
        rej.status_code == 200
        and rej.json()["state"] == "rejected"
        and rej.json()["effective"] is False
    )
    late = pw.call(h.tenant, "POST", path, json={"decision": "approve", "expected_version": 1})
    assert late.status_code == 409 and late.json()["code"] == "already_decided"


def test_concurrent_decisions_have_one_winner(pw: PW) -> None:
    h, staff, eng = _setup(pw)
    adj = _propose(pw, pw.estate_mgr, eng).json()
    barrier = threading.Barrier(4)

    def decide(i: int) -> int:
        barrier.wait()
        who = h.owner if i % 2 else h.tenant
        r = pw.call(
            who,
            "POST",
            f"/v1/payroll-adjustments/{adj['id']}/decision",
            json={"decision": "approve", "expected_version": 1},
        )
        return int(r.status_code)

    with ThreadPoolExecutor(4) as pool:
        codes = list(pool.map(decide, range(4)))
    assert sorted(codes) == [200, 409, 409, 409], codes
    assert (
        pw.rows("SELECT count(*) FROM audit_log WHERE operation = 'staff.payroll_approve'")[0][0]
        == 1
    )


def test_a_stale_version_is_a_409_and_another_household_gets_a_404(pw: PW) -> None:
    h, staff, eng = _setup(pw)
    other = pw.household("A-102")
    adj = _propose(pw, h.owner, eng).json()
    assert (
        pw.call(
            h.owner,
            "POST",
            f"/v1/payroll-adjustments/{adj['id']}/decision",
            json={"decision": "approve", "expected_version": 5},
        ).status_code
        == 409
    )
    assert (
        pw.call(
            other.owner,
            "POST",
            f"/v1/payroll-adjustments/{adj['id']}/decision",
            json={"decision": "approve", "expected_version": 1},
        ).status_code
        == 404
    )
    assert _propose(pw, other.owner, eng).status_code == 404, (
        "proposing for another household's engagement"
    )


# REQ: INV-02
@pytest.mark.parametrize("amount", [1.5, "1500", 0, -5, 100_000_001, True, None])
def test_amounts_are_integer_paise_only(pw: PW, amount: object) -> None:
    h, staff, eng = _setup(pw)
    r = _propose(pw, h.owner, eng, amount_paise=amount)
    assert r.status_code == 400
    assert pw.rows("SELECT count(*) FROM payroll_adjustments")[0][0] == 0


def test_period_kind_and_reason_are_validated(pw: PW) -> None:
    h, staff, eng = _setup(pw)
    for extra in (
        {"period": "2026-13"},
        {"period": "Oct 2026"},
        {"kind": "gift"},
        {"reason": "no"},
    ):
        assert _propose(pw, h.owner, eng, **extra).status_code == 400, extra


def test_reads_are_scoped_to_the_household_and_the_estate_manager_sees_only_its_own_proposals(
    pw: PW,
) -> None:
    h, staff, eng = _setup(pw)
    other = pw.household("A-102")
    s2 = pw.register_staff("Second")
    e2 = pw.engage(other.owner, s2, other.unit)
    mine = _propose(pw, h.owner, eng).json()
    theirs = _propose(pw, other.owner, e2).json()
    by_estate = _propose(pw, pw.estate_mgr, eng).json()
    assert {
        a["id"] for a in pw.call(h.owner, "GET", "/v1/payroll-adjustments").json()["items"]
    } == {mine["id"], by_estate["id"]}
    assert {
        a["id"] for a in pw.call(other.owner, "GET", "/v1/payroll-adjustments").json()["items"]
    } == {theirs["id"]}
    assert {
        a["id"] for a in pw.call(pw.estate_mgr, "GET", "/v1/payroll-adjustments").json()["items"]
    } == {by_estate["id"]}
    assert pw.call_b(pw.other.secretary, "GET", "/v1/payroll-adjustments").status_code == 403
    assert (
        pw.call(h.owner, "GET", "/v1/payroll-adjustments", params={"state": "approved"}).json()[
            "items"
        ]
        == []
    )
