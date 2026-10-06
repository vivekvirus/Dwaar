"""The household decision (PRD 12.3): canonical response, first valid decision wins, stale versions, expiry, replay, who may decide.

REQ: GATE-02, GATE-03, INV-03, INV-07, IAM-08.
"""

from __future__ import annotations

import uuid

import pytest

from tests.integration.visits._support import VW

pytestmark = [pytest.mark.req("GATE-03")]

CANONICAL_KEYS = {
    "request_id",
    "status",
    "version",
    "decision_id",
    "permission_expires_at",
    "entry_observed",
}


@pytest.fixture
def gate(vw: VW) -> VW:
    vw.setup_gate()
    return vw


def test_canonical_response_is_the_prd_12_3_shape(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    action = uuid.uuid4()
    r = gate.decide(h.owner, req, "approve", action=action)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == CANONICAL_KEYS
    assert body["request_id"] == req["id"] and body["status"] == "approved" and body["version"] == 2
    assert body["entry_observed"] is False  # an approval is never shown as physical entry (INV-07)
    assert body["decision_id"] and body["permission_expires_at"]
    visit = gate.rows(
        "SELECT state, authorisation_source, authorised_until, entered_at FROM visits"
    )[0]
    assert (
        visit[0] == "authorised"
        and visit[1] == "household_approval"
        and visit[2] is not None
        and visit[3] is None
    )
    assert gate.rows(
        "SELECT decided_by, decider_role, decision, valid, client_action_id, request_version FROM approval_decisions"
    ) == [(h.owner.id, "owner_occ", "approve", True, action, 2)]
    ev = gate.outbox("ApprovalDecided", req["id"])
    assert len(ev) == 1 and ev[0]["version"] == 2 and ev[0]["payload"]["status"] == "approved"
    assert ev[0]["payload"]["unit_id"] == str(h.unit) and "decided_by_role" in ev[0]["payload"]
    audit = gate.audit("approval.decide")
    assert len(audit) == 1 and audit[0][1] == h.owner.id and audit[0][2] == "owner_occ"
    # the guard sees the outcome but not WHO decided, only which kind of household member
    seen = gate.call(
        gate.guard,
        "GET",
        f"/v1/approval-requests/{req['id']}",
        params={"gate_id": str(gate.gate_id)},
    ).json()
    assert (
        seen["status"] == "approved"
        and seen["decision"]["by_role"] == "owner_occ"
        and str(h.owner.id) not in str(seen)
    )


def test_deny_issues_no_permission_and_cannot_be_resurrected_by_a_stale_approval(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    denied = gate.decide(h.owner, req, "deny")
    assert (
        denied.status_code == 200
        and denied.json()["status"] == "denied"
        and denied.json()["permission_expires_at"] is None
    )
    assert gate.rows("SELECT state, closed_reason FROM visits") == [("cancelled", "denied")]
    # a queued, stale approval from the family member's phone (still holding version 1)
    stale = gate.decide(h.family, req, "approve")  # type: ignore[arg-type]
    assert stale.status_code == 409 and stale.json()["code"] == "already_decided"
    assert stale.json()["details"]["canonical"]["status"] == "denied"
    assert gate.rows("SELECT state FROM visits")[0][0] == "cancelled"  # still no permission
    assert gate.rows("SELECT count(*) FROM approval_decisions WHERE valid")[0][0] == 1
    # even with the right version number now
    again = gate.decide(h.owner, req, "approve", version=denied.json()["version"])
    assert again.status_code == 409 and again.json()["code"] == "already_decided"


def test_the_second_household_member_gets_already_decided_with_the_canonical_result(
    gate: VW,
) -> None:
    h = gate.household("A-101", tenant=True)
    req = gate.raise_request(h.unit)
    first = gate.decide(h.tenant, req)  # type: ignore[arg-type]
    second = gate.decide(h.family, req, "deny")  # type: ignore[arg-type]
    assert first.status_code == 200 and second.status_code == 409
    assert second.json()["code"] == "already_decided"
    canonical = second.json()["details"]["canonical"]
    assert canonical == first.json() | {} and set(canonical) == CANONICAL_KEYS
    assert second.json()["details"]["decided_by_role"] == "tenant"
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "approved"


def test_stale_expected_version_is_409_stale_version(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    stale = gate.decide(h.owner, req, version=7)
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    assert stale.json()["details"]["canonical"]["status"] == "pending"
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "pending"
    assert gate.rows("SELECT count(*) FROM approval_decisions")[0][0] == 0


@pytest.mark.req("GATE-03", "INV-03")
def test_a_decision_after_expiry_is_409_request_expired_and_issues_no_permission(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    gate.expire_request(req["id"])  # the 90 seconds are up; no sweep has run yet
    late = gate.decide(h.owner, req)
    assert late.status_code == 409 and late.json()["code"] == "request_expired"
    assert late.json()["details"]["canonical"]["status"] == "expired"
    assert late.json()["details"]["canonical"]["permission_expires_at"] is None
    row = gate.rows(
        "SELECT state, permission_expires_at, decision_id, closed_reason FROM approval_requests"
    )[0]
    assert row == (
        "expired",
        None,
        None,
        "expired",
    )  # the expiry was PERSISTED although the decision failed
    assert gate.rows("SELECT state, closed_reason FROM visits") == [("expired", "expired")]
    assert gate.rows("SELECT authorised, state FROM visit_stops") == [(False, "expired")]
    assert gate.rows("SELECT count(*) FROM approval_decisions")[0][0] == 0
    esc = gate.outbox("ApprovalEscalated", req["id"])
    assert (
        len(esc) == 1
        and esc[0]["payload"]["reason"] == "expired"
        and "leave_at_gate" in esc[0]["payload"]["guard_options"]
    )
    # another queued approval later: same answer, no second event, still nothing allowed
    again = gate.decide(h.family, req)  # type: ignore[arg-type]
    assert again.status_code == 409 and again.json()["code"] == "request_expired"
    assert len(gate.outbox("ApprovalEscalated", req["id"])) == 1
    # the household and the guard both SEE the expiry
    mine = gate.call(h.owner, "GET", f"/v1/approval-requests/{req['id']}").json()
    assert mine["status"] == "expired" and mine["permission_expires_at"] is None
    theirs = gate.call(
        gate.guard,
        "GET",
        f"/v1/approval-requests/{req['id']}",
        params={"gate_id": str(gate.gate_id)},
    ).json()
    assert (
        theirs["status"] == "expired"
        and "hold" in theirs["guard_options"]
        and theirs["auto_allow_on_timeout"] is False
    )


def test_expiry_is_lazy_on_read_and_the_job_function_is_idempotent(gate: VW) -> None:
    from dwaar_api.core.db import RequestContext
    from dwaar_api.modules.visits import approvals

    h = gate.household("A-101")
    first, second = gate.raise_request(h.unit), gate.raise_request(h.unit, visitor_alias="Two")
    gate.expire_request(first["id"])
    read = gate.call(h.owner, "GET", f"/v1/approval-requests/{first['id']}")
    assert read.json()["status"] == "expired"  # lazily, on read
    assert (
        gate.rows("SELECT state FROM approval_requests WHERE id = %s", (second["id"],))[0][0]
        == "pending"
    )
    gate.expire_request(second["id"])
    ctx = RequestContext(gate.soc.id, None, "system", uuid.uuid4())
    runs = []
    for _ in range(3):  # the job function, run again and again
        with gate.idh.database.app_tx(ctx) as conn:
            runs.append(approvals.expire_due_requests(conn, ctx))
    assert runs == [1, 0, 0]
    assert len(gate.outbox("ApprovalEscalated")) == 2  # exactly one event per expiry


def test_a_request_never_auto_admits_when_nobody_answers(gate: VW) -> None:
    """INV-03: with the clock run out and nobody deciding, nothing becomes authorised and nobody can enter 'by default'."""
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    gate.expire_request(req["id"])
    gate.call(
        gate.guard,
        "GET",
        f"/v1/approval-requests/{req['id']}",
        params={"gate_id": str(gate.gate_id)},
    )
    assert gate.rows("SELECT state, authorised_at, authorised_until FROM visits") == [
        ("expired", None, None)
    ]
    entry = gate.observe(req["visit_id"], "entry")
    assert entry.status_code == 201 and entry.json()["permission_created"] is False
    assert (
        gate.rows("SELECT state FROM visits")[0][0] == "expired"
    )  # the observation did not authorise anyone


def test_replay_with_the_same_key_returns_the_same_canonical_answer(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    action = uuid.uuid4()
    first = gate.decide(h.owner, req, action=action, key="decide-key-0001")
    replay = gate.decide(h.owner, req, action=action, key="decide-key-0001")
    assert first.status_code == replay.status_code == 200
    assert replay.headers["Idempotent-Replayed"] == "true"
    assert (
        replay.json() == first.json()
    )  # including request_id = the APPROVAL REQUEST id (not the replay's correlation id)
    assert replay.json()["request_id"] == req["id"]
    assert gate.rows("SELECT count(*) FROM approval_decisions")[0][0] == 1
    # same key, other payload
    mismatch = gate.decide(h.owner, req, "deny", action=action, key="decide-key-0001")
    assert mismatch.status_code == 409 and mismatch.json()["code"] == "duplicate_payload_mismatch"
    # a retry of the SAME client action under a NEW key (the app lost the response): the original answer, not a 409
    retry = gate.decide(h.owner, req, action=action, key="decide-key-0002")
    assert retry.status_code == 200 and retry.json()["decision_id"] == first.json()["decision_id"]
    assert gate.rows("SELECT count(*) FROM approval_decisions")[0][0] == 1
    # a different client action by someone else is a loser
    other = gate.decide(h.family, req)  # type: ignore[arg-type]
    assert other.status_code == 409
    # no key at all
    bare = gate.client.post(
        f"/v1/approval-requests/{req['id']}/decision",
        json={"decision": "approve", "expected_version": 1, "client_action_id": str(uuid.uuid4())},
        headers={**h.owner.headers, "X-Society-Id": str(gate.soc.id)},
    )
    assert bare.status_code == 400


def test_payload_is_validated(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    url = f"/v1/approval-requests/{req['id']}/decision"
    good = {"decision": "approve", "expected_version": 1, "client_action_id": str(uuid.uuid4())}
    for bad in (
        {**good, "decision": "allow"},
        {**good, "expected_version": 0},
        {**good, "client_action_id": "nope"},
        {**good, "channel": "carrier_pigeon"},
        {**good, "society_id": str(gate.soc.id)},
        {k: v for k, v in good.items() if k != "client_action_id"},
    ):
        r = gate.call(h.owner, "POST", url, json=bad)
        assert r.status_code == 400 and r.json()["code"] == "invalid_schema", bad
    assert (
        gate.call(
            h.owner, "POST", f"/v1/approval-requests/{uuid.uuid4()}/decision", json=good
        ).status_code
        == 404
    )
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "pending"


def test_every_prd_channel_is_in_the_model_but_a_client_can_claim_only_the_app(gate: VW) -> None:
    """PRD 8.2 names five decision channels. ``DecisionIn`` accepts all five (the notifications module builds it without ``model_construct``), but the
    HTTP route refuses the four the SERVER establishes (a keypad press, a link opened from SMS or WhatsApp, a guard relaying): otherwise a client could
    forge the provenance of its own decision. The request stays pending and nothing is written."""
    from dwaar_api.modules.visits.schemas import DecisionIn

    for channel in ("app", "ivr", "whatsapp", "sms", "guard_assisted"):
        body = DecisionIn(
            decision="approve",
            expected_version=1,
            client_action_id=uuid.uuid4(),
            channel=channel,  # type: ignore[arg-type]
        )
        assert body.channel == channel
    assert DecisionIn.model_fields["channel"].default == "app"
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    url = f"/v1/approval-requests/{req['id']}/decision"
    for channel in ("ivr", "whatsapp", "sms", "guard_assisted"):
        r = gate.call(
            h.owner, "POST", url,
            json={"decision": "approve", "expected_version": 1, "client_action_id": str(uuid.uuid4()), "channel": channel},
        )  # fmt: skip
        assert r.status_code == 422 and r.json()["code"] == "policy_violation", (channel, r.text)
        assert r.json()["details"]["reason"] == "channel_set_by_the_server"
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "pending"
    assert gate.rows("SELECT count(*) FROM approval_decisions")[0][0] == 0
    ok = gate.call(
        h.owner, "POST", url,
        json={"decision": "approve", "expected_version": 1, "client_action_id": str(uuid.uuid4()), "channel": "app"},
    )  # fmt: skip
    assert ok.status_code == 200
    assert gate.rows("SELECT channel FROM approval_decisions")[0][0] == "app"


# ------------------------------------------------------------------------------------------ who may decide
@pytest.mark.req("GATE-03", "IAM-08", "INV-04")
def test_only_the_household_that_lives_there_may_decide(gate: VW) -> None:
    a = gate.household("A-101", tenant=True, nr_owner=True)
    b = gate.household("A-102")
    req = gate.raise_request(a.unit)
    # another household's owner, a stranger with no membership at all, and staff: nothing to see (404) or not allowed (403)
    assert gate.decide(b.owner, req).status_code == 404
    assert gate.decide(b.family, req).status_code == 404  # type: ignore[arg-type]
    assert gate.decide(gate.person(), req).status_code == 404
    assert gate.decide(gate.guard, req).status_code == 403
    assert gate.decide(gate.secretary, req).status_code == 403
    assert gate.decide(gate.guard_sup, req).status_code == 403
    # a non-resident co-owner of the SAME unit does not decide for the household (INV-04)
    assert gate.decide(a.nr_owner, req).status_code == 403  # type: ignore[arg-type]
    assert gate.rows("SELECT state FROM approval_requests")[0][0] == "pending"
    # the tenant (lives there) can
    assert gate.decide(a.tenant, req).status_code == 200  # type: ignore[arg-type]


def test_a_family_member_decides_only_when_delegated(gate: VW) -> None:
    unit = gate.unit("A-101")
    gate.resident(unit, "owner")
    undelegated = gate.resident(unit, "family")
    delegated = gate.resident(unit, "family", delegated=True)
    req = gate.raise_request(unit)
    refused = gate.decide(undelegated, req)
    assert refused.status_code == 403 and refused.json()["code"] == "not_authorised"
    assert gate.decide(delegated, req).status_code == 200
    assert gate.rows("SELECT decider_role FROM approval_decisions") == [("family",)]


def test_membership_that_is_not_verified_or_has_ended_cannot_decide(gate: VW) -> None:
    unit = gate.unit("A-101")
    gate.resident(unit, "owner")
    pending = gate.resident(unit, "tenant", verification="pending")
    ended = gate.resident(unit, "tenant")
    gate.sql(
        "UPDATE memberships SET ended_at = now(), effective_from = (now() AT TIME ZONE 'Asia/Kolkata')::date - 5,"
        " effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date - 1"
        " WHERE person_id = %s",
        (ended.id,),
    )
    req = gate.raise_request(unit)
    assert gate.decide(pending, req).status_code == 404
    assert gate.decide(ended, req).status_code == 404


# ------------------------------------------------------------------------------------------ reversal and cancel
def test_a_later_reversal_is_a_new_event_not_an_edit(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    first = gate.decide(h.owner, req).json()
    reverse = gate.call(
        h.family,
        "POST",
        f"/v1/approval-requests/{req['id']}/reversal",  # type: ignore[union-attr]
        json={
            "expected_version": first["version"],
            "client_action_id": str(uuid.uuid4()),
            "reason": "I do not know this visitor",
        },
    )
    assert (
        reverse.status_code == 200
        and reverse.json()["status"] == "cancelled"
        and reverse.json()["permission_expires_at"] is None
    )
    assert reverse.json()["request_id"] == req["id"]
    rows = gate.rows(
        "SELECT decision, valid, reverses_decision_id IS NOT NULL FROM approval_decisions ORDER BY decided_at"
    )
    assert rows == [
        ("approve", True, False),
        ("reverse", False, True),
    ]  # the first decision row is untouched
    assert gate.rows("SELECT state, closed_reason FROM visits") == [("cancelled", "reversed")]
    assert gate.rows("SELECT authorised, state FROM visit_stops") == [(False, "cancelled")]
    assert [e["payload"]["status"] for e in gate.outbox("ApprovalDecided", req["id"])] == [
        "approved",
        "cancelled",
    ]
    # approving again is not possible (no resurrection)
    again = gate.decide(h.owner, req, version=reverse.json()["version"])
    assert again.status_code == 409 and again.json()["code"] == "already_decided"


def test_an_approval_cannot_be_reversed_after_entry_was_observed(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    first = gate.decide(h.owner, req).json()
    assert gate.observe(req["visit_id"], "entry").status_code == 201
    refused = gate.call(
        h.owner,
        "POST",
        f"/v1/approval-requests/{req['id']}/reversal",
        json={
            "expected_version": first["version"],
            "client_action_id": str(uuid.uuid4()),
            "reason": "Too late, he is inside",
        },
    )
    assert (
        refused.status_code == 422
        and refused.json()["details"]["reason"] == "entry_already_observed"
    )
    pending = gate.raise_request(h.unit)
    assert (
        gate.call(
            h.owner,
            "POST",
            f"/v1/approval-requests/{pending['id']}/reversal",
            json={
                "expected_version": 1,
                "client_action_id": str(uuid.uuid4()),
                "reason": "Nothing to reverse yet",
            },
        ).json()["details"]["reason"]
        == "not_approved"
    )


def test_the_guard_cancels_a_pending_request_and_a_late_decision_loses(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    cancelled = gate.call(
        gate.guard,
        "POST",
        f"/v1/approval-requests/{req['id']}/cancel",
        json={"expected_version": 1, "reason": "Visitor walked away"},
    )
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert gate.rows("SELECT state FROM visits")[0][0] == "cancelled"
    late = gate.decide(h.owner, req)
    assert late.status_code == 409 and late.json()["code"] == "already_decided"
    assert late.json()["details"]["canonical"]["status"] == "cancelled"
    assert (
        gate.call(
            h.owner,
            "POST",
            f"/v1/approval-requests/{req['id']}/cancel",
            json={"expected_version": 1},
        ).status_code
        == 403
    )
    # a decided request cannot be cancelled by the guard any more
    other = gate.raise_request(h.unit)
    gate.decide(h.owner, other)
    assert (
        gate.call(
            gate.guard,
            "POST",
            f"/v1/approval-requests/{other['id']}/cancel",
            json={"expected_version": 1},
        ).status_code
        == 409
    )


def test_every_state_change_has_one_event_per_aggregate_version(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    gate.decide(h.owner, req)
    rows = gate.rows(
        "SELECT event_type, aggregate_version FROM outbox WHERE aggregate_id = %s ORDER BY aggregate_version",
        (req["id"],),
    )
    assert rows == [("ApprovalRequested", 1), ("ApprovalDecided", 2)]
    assert gate.rows("SELECT count(*) FROM audit_log WHERE object_id = %s", (req["id"],))[0][0] == 2
