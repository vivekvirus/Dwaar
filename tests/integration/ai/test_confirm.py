"""POST /v1/ai/proposals/{id}/confirm: confirmation bound to the payload hash, re-validated at execution time (AT-26, AI-SYS-04, INV-06)."""

from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.integration.ai._support import AW

pytestmark = [pytest.mark.req("AI-SYS-04"), pytest.mark.at("AT-26")]


@pytest.fixture
def enabled(aw: AW) -> AW:
    aw.set_quota(100)
    return aw


def translate(aw: AW, who, text: str = "The clubhouse is closed on Sunday"):  # type: ignore[no-untyped-def]
    return aw.draft(who, "AI-R07", {"text": text, "target_language": "hi"})["proposal"]


def test_confirm_executes_the_command_once_with_audit_outbox_and_a_receipt(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    p = translate(enabled, owner)
    r = enabled.confirm(owner, p)
    assert r.status_code == 200, r.text
    b = r.json()
    assert (
        b["state"] == "confirmed"
        and b["outcome"] == "accepted"
        and b["edited"] is False
        and b["command"] == "ai.save_draft"
    )
    assert (
        b["result"]["saved"] is True
        and b["result"]["published"] is False
        and b["result"]["sent"] is False
        and b["result"]["draft_id"]
    )
    (run,) = enabled.runs()
    assert run["outcome"] == "accepted"
    assert enabled.rows("SELECT state, confirmed_role, edited FROM action_proposals") == [
        ("confirmed", "owner_occ", False)
    ]
    drafts = enabled.call(owner, "GET", "/v1/ai/drafts").json()["items"]
    assert [d["id"] for d in drafts] == [b["result"]["draft_id"]] and drafts[0]["content"][
        "original_text"
    ].startswith("The clubhouse")
    ops = [
        r[0]
        for r in enabled.rows(
            "SELECT operation FROM audit_log WHERE operation LIKE %s ORDER BY at", ("ai.%",)
        )
    ]
    assert ops == ["ai.proposal.create", "ai.draft.save", "ai.proposal.confirm"]
    events = [
        r[0]
        for r in enabled.rows(
            "SELECT event_type FROM outbox WHERE event_type LIKE %s ORDER BY occurred_at", ("AI%",)
        )
    ]
    assert events == ["AIProposalCreated", "AIDraftSaved", "AIProposalConfirmed"]
    # a second confirmation (new key) is refused; the same key replays the first receipt; nothing runs twice
    again = enabled.confirm(owner, p)
    assert again.status_code == 409 and again.json()["code"] == "already_decided"
    k = enabled.confirm(
        owner, translate(enabled, owner, "second notice text here"), key="confirm-key-0001"
    )
    k2 = enabled.confirm(
        owner,
        {"id": k.json()["proposal_id"], "payload_hash": ""},
        payload_hash=enabled.call(
            owner, "GET", f"/v1/ai/proposals/{k.json()['proposal_id']}"
        ).json()["payload_hash"],
        key="confirm-key-0001",
    )
    assert (
        k2.headers.get("Idempotent-Replayed") == "true"
        and k2.json()["result"] == k.json()["result"]
    )
    assert enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 2


def test_other_people_and_other_societies_cannot_see_or_confirm_a_proposal(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    neighbour = enabled.person("owner2", unit="A-102", kind="owner")
    p = translate(enabled, owner)
    for who in (neighbour, enabled.vw.secretary):
        assert enabled.confirm(who, p).status_code == 404
        assert enabled.call(who, "GET", f"/v1/ai/proposals/{p['id']}").status_code == 404
    assert enabled.call(neighbour, "GET", "/v1/ai/proposals").json()["items"] == []
    assert (
        enabled.call(
            enabled.other_secretary,
            "POST",
            f"/v1/ai/proposals/{p['id']}/confirm",
            json={"payload_hash": p["payload_hash"]},
            society=enabled.other.id,
        ).status_code
        == 404
    )
    assert enabled.rows("SELECT state FROM action_proposals") == [("proposed",)]


def test_a_wrong_or_tampered_payload_hash_never_executes(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    p = translate(enabled, owner)
    bad = enabled.confirm(owner, p, payload_hash="sha256:" + "a" * 64)
    assert (
        bad.status_code == 422
        and bad.json()["code"] == "policy_violation"
        and bad.json()["details"]
        == {"reason": "payload_hash_mismatch", "new_proposal_required": True}
    )
    assert enabled.confirm(owner, p, payload_hash="not-a-hash").status_code == 400
    # the stored row itself is altered (admin role: the app role cannot): the recomputed hash catches it
    with enabled.vw.idh.db.admin_conn() as conn:
        conn.execute(
            "UPDATE action_proposals SET payload = jsonb_set(payload, '{translated_text}', '\"EVIL\"')"
        )
    tampered = enabled.confirm(owner, p)
    assert (
        tampered.status_code == 422
        and tampered.json()["details"]["reason"] == "payload_hash_mismatch"
    )
    assert enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 0 and enabled.rows(
        "SELECT state FROM action_proposals"
    ) == [("proposed",)]


def test_a_proposal_expires(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    p = translate(enabled, owner)
    enabled.rt.clock = lambda: dt.datetime.now(dt.UTC) + dt.timedelta(minutes=45)
    r = enabled.confirm(owner, p)
    assert (
        r.status_code == 409
        and r.json()["code"] == "request_expired"
        and r.json()["details"]["new_proposal_required"] is True
    )
    assert enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 0


def test_edits_are_validated_recorded_as_edited_and_cannot_change_the_command(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    p = translate(enabled, owner)
    for bad in (
        {"command": "gate.open"},
        {"payload_hash": "x"},
        {"target_ids": []},
        {"unit_id": "x"},
        {"original_text": "forged original"},
    ):
        r = enabled.confirm(owner, p, edits=bad)
        assert r.status_code == 400 and r.json()["code"] == "invalid_schema", bad
    assert enabled.confirm(owner, p, edits={"translated_text": ""}).status_code == 400
    ok = enabled.confirm(owner, p, edits={"translated_text": "मेरा सुधारा हुआ अनुवाद"})
    assert (
        ok.status_code == 200 and ok.json()["outcome"] == "edited" and ok.json()["edited"] is True
    )
    (run,) = enabled.runs()
    assert run["outcome"] == "edited"
    (row,) = enabled.rows(
        "SELECT payload->>'translated_text', final_payload->>'translated_text', command, edited FROM action_proposals"
    )
    assert (
        row[0].startswith("[SIMULATED")
        and row[1] == "मेरा सुधारा हुआ अनुवाद"
        and row[2:] == ("ai.save_draft", True)
    )  # the proposal row is unchanged
    assert (
        enabled.call(owner, "GET", "/v1/ai/drafts").json()["items"][0]["content"]["translated_text"]
        == "मेरा सुधारा हुआ अनुवाद"
    )


def test_drafts_are_private_to_their_owner(enabled: AW) -> None:
    a = enabled.person("owner1", unit="A-101", kind="owner")
    b = enabled.person("owner2", unit="A-102", kind="owner")
    enabled.confirm(a, translate(enabled, a))
    assert len(enabled.call(a, "GET", "/v1/ai/drafts").json()["items"]) == 1
    assert enabled.call(b, "GET", "/v1/ai/drafts").json()["items"] == []
    assert enabled.call(enabled.vw.secretary, "GET", "/v1/ai/drafts").json()["items"] == []


# ------------------------------------------------------------------------------------------------ AT-26
def test_at26_role_changed_after_the_proposal_requires_a_new_proposal(enabled: AW) -> None:
    """The person drafted as a TENANT; by confirmation time they are the OWNER-occupier of the unit. The role the proposal was made under is not
    the role held now: revalidation fails and a NEW proposal is required (PRD AT-26)."""
    who = enabled.person("mover", unit="A-101", kind="tenant")
    p = translate(enabled, who)
    enabled.end_membership(who)
    enabled.vw.idh.seed_membership(enabled.soc.id, who.id, enabled.unit("A-101"), "owner")
    r = enabled.confirm(who, p)
    assert r.status_code == 409 and r.json()["code"] == "stale_version"
    assert r.json()["details"] == {"reason": "role_changed", "new_proposal_required": True}
    assert (
        enabled.rows("SELECT state FROM action_proposals") == [("proposed",)]
        and enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 0
    )
    fresh = translate(enabled, who)  # the NEW proposal is made under the current role and confirms
    assert enabled.confirm(who, fresh).status_code == 200


def test_at26_role_lost_entirely_fails_revalidation(enabled: AW) -> None:
    who = enabled.person("leaver", unit="A-101", kind="tenant")
    p = translate(enabled, who)
    enabled.end_membership(who)
    r = enabled.confirm(who, p)
    assert (
        r.status_code == 404 and r.json()["code"] == "not_found"
    )  # no standing left: indistinguishable from an unknown proposal
    assert enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 0


def test_at26_a_role_that_may_no_longer_use_the_feature_is_refused(enabled: AW) -> None:
    sec = enabled.person("sec2", "secretary")
    p = enabled.draft(
        sec,
        "AI-C12",
        {"question": "Should we repaint the lobby?", "options": ["Yes", "No", "No opinion"]},
    )["proposal"]
    enabled.revoke_grant(sec, "secretary")
    enabled.vw.idh.seed_grant(
        enabled.soc.id, sec.id, "treasurer"
    )  # still has ai.use, but the poll check is not a treasurer feature
    enabled.vw.idh.elevate_session(sec)
    r = enabled.confirm(sec, p)
    assert r.status_code == 403 and r.json()["code"] == "not_authorised"


def test_at26_target_version_changed_after_the_proposal_requires_a_new_proposal(
    enabled: AW,
) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    ports = enabled.fake_ports("ticket_create")
    p = enabled.draft(
        tenant, "AI-R02", {"transcript": "Water is leaking in flat A-101 kitchen pipe"}
    )["proposal"]
    assert p["target_versions"] == [1]
    assert enabled.bump_unit("A-101") == 2  # the unit moved on (real organisation API)
    r = enabled.confirm(tenant, p)
    assert (
        r.status_code == 409
        and r.json()["code"] == "stale_version"
        and r.json()["details"] == {"reason": "target_changed", "new_proposal_required": True}
    )
    assert ports["ticket_create"].calls == [] and enabled.rows(
        "SELECT state FROM action_proposals"
    ) == [("proposed",)]
    fresh = enabled.draft(
        tenant, "AI-R02", {"transcript": "Water is leaking in flat A-101 kitchen pipe"}
    )["proposal"]
    assert fresh["target_versions"] == [2]
    assert (
        enabled.confirm(tenant, fresh).status_code == 200 and len(ports["ticket_create"].calls) == 1
    )
    stale = enabled.confirm(
        tenant, fresh, versions=[1], key="other-key-000001"
    )  # already decided wins over a stale version claim
    assert stale.status_code == 409


def test_expected_target_versions_from_the_client_must_match(enabled: AW) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    enabled.fake_ports("ticket_create")
    p = enabled.draft(
        tenant, "AI-R02", {"transcript": "Water is leaking in flat A-101 kitchen pipe"}
    )["proposal"]
    r = enabled.confirm(tenant, p, versions=[9])
    assert r.status_code == 409 and r.json()["details"]["reason"] == "target_changed"
    assert enabled.confirm(tenant, p, versions=[1]).status_code == 200


# ------------------------------------------------------------------------------------------------ AI-R02: resident edits and confirms
def test_complaint_is_submitted_only_after_the_resident_confirms_through_the_ticket_port(
    enabled: AW,
) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    ports = enabled.fake_ports("ticket_create")
    p = enabled.draft(
        tenant, "AI-R02", {"transcript": "Water is leaking in flat A-101 bathroom pipe"}
    )["proposal"]
    assert ports["ticket_create"].calls == []  # a proposal never submits
    r = enabled.confirm(
        tenant,
        p,
        edits={"description": "Water leaks from the bathroom pipe; please come before noon"},
    )
    assert (
        r.status_code == 200
        and r.json()["outcome"] == "edited"
        and r.json()["result"]["via"] == "ticket_create"
    )
    (call,) = ports["ticket_create"].calls
    assert (
        call["payload"]["unit_id"] == str(enabled.unit("A-101"))
        and call["payload"]["description"].startswith("Water leaks from")
        and call["actor"] == str(tenant.id)
    )
    assert call["external_key"] == f"ai-proposal-{p['id']}" and call["society"] == str(
        enabled.soc.id
    )  # stable per proposal: idempotent in the port too


def test_a_complaint_without_a_resolved_place_must_be_completed_with_one_of_the_residents_own_units(
    enabled: AW,
) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    enabled.person("owner2", unit="A-102", kind="owner")
    ports = enabled.fake_ports("ticket_create")
    p = enabled.draft(tenant, "AI-R02", {"transcript": "tap leaking in flat A-102 kitchen"})[
        "proposal"
    ]  # the neighbour's flat: not resolved
    assert p["payload"]["unit_id"] is None and "location" in p["missing_fields"]
    r = enabled.confirm(tenant, p)
    assert r.status_code == 422 and r.json()["details"] == {
        "reason": "missing_required_fields",
        "fields": ["location"],
    }
    nb = enabled.confirm(
        tenant, p, edits={"unit_id": str(enabled.unit("A-102"))}
    )  # naming the neighbour's unit: not theirs
    assert nb.status_code == 404
    unknown = enabled.confirm(tenant, p, edits={"unit_id": "00000000-0000-0000-0000-000000000000"})
    assert unknown.status_code == 404
    ok = enabled.confirm(
        tenant,
        p,
        edits={"unit_id": str(enabled.unit("A-101")), "category": "plumbing", "urgency": "high"},
    )
    assert (
        ok.status_code == 200
        and ok.json()["target_ids"] == [str(enabled.unit("A-101"))]
        and ok.json()["outcome"] == "edited"
    )
    assert ports["ticket_create"].calls[0]["payload"]["unit_label"] == "A-101"
    assert enabled.confirm(
        tenant, p, edits={"category": "not-a-category"}, key="k2-000000001"
    ).status_code in {400, 409}


def test_when_the_module_that_executes_a_command_is_missing_the_proposal_stays_open(
    enabled: AW,
) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    p = enabled.draft(
        tenant, "AI-R02", {"transcript": "Water is leaking in flat A-101 bathroom pipe"}
    )["proposal"]
    r = enabled.confirm(tenant, p)
    assert (
        r.status_code == 503
        and r.json()["code"] == "dependency_unavailable"
        and r.json()["details"]["reason"] == "module_not_available"
    )
    assert (
        enabled.rows("SELECT state FROM action_proposals") == [("proposed",)]
        and enabled.runs()[0]["outcome"] is None
    )  # nothing half-done
    enabled.fake_ports("ticket_create")
    assert enabled.confirm(tenant, p).status_code == 200


def test_a_failing_port_rolls_everything_back(enabled: AW) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    ports = enabled.fake_ports("ticket_create")
    p = enabled.draft(
        tenant, "AI-R02", {"transcript": "Water is leaking in flat A-101 bathroom pipe"}
    )["proposal"]
    ports["ticket_create"].fail = True
    r = enabled.confirm(tenant, p)
    assert r.status_code == 500 and "exploded" not in r.text
    assert enabled.rows("SELECT state FROM action_proposals") == [("proposed",)]
    ports["ticket_create"].fail = False
    assert enabled.confirm(tenant, p).status_code == 200


def test_notice_draft_goes_through_the_notices_port_when_present_and_is_otherwise_a_private_draft(
    enabled: AW,
) -> None:
    sec = enabled.vw.secretary
    p = enabled.draft(sec, "AI-C01", {"brief": "Water tank cleaning on 12/10 from 10 am to 2 pm"})[
        "proposal"
    ]
    r = enabled.confirm(sec, p)
    assert (
        r.status_code == 200
        and r.json()["result"]["via"] == "local_draft_until_notices_module"
        and r.json()["result"]["published"] is False
    )
    ports = enabled.fake_ports("notice_draft")
    p2 = enabled.draft(sec, "AI-C01", {"brief": "Lift service on 14/10 at 9 am"})["proposal"]
    r2 = enabled.confirm(sec, p2)
    assert (
        r2.json()["result"]["via"] == "notice_draft"
        and ports["notice_draft"].calls[0]["payload"]["requires_publish_approval"] is True
    )


def test_confirming_after_the_kill_switch_or_a_feature_switch_is_refused(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    p = translate(enabled, owner)
    r = enabled.call(
        enabled.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"kill_switch": True, "reason": "committee decision"},
    )
    assert r.status_code == 200
    refused = enabled.confirm(owner, p)
    assert refused.status_code == 422 and refused.json()["details"] == {
        "reason": "kill_switch",
        "fallback": "ordinary_form",
    }
    enabled.call(enabled.vw.secretary, "PUT", "/v1/ai/controls", json={"kill_switch": False})
    enabled.call(
        enabled.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"features": {"AI-R07": {"state": "disabled"}}},
    )
    assert enabled.confirm(owner, p).json()["details"]["reason"] == "feature_disabled"
    enabled.call(
        enabled.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"features": {"AI-R07": {"state": "enabled"}}},
    )
    assert (
        enabled.confirm(owner, p).status_code == 200
    )  # switched back on: the same open proposal still confirms


def test_an_exhausted_budget_does_not_block_confirming_the_users_own_draft(enabled: AW) -> None:
    """Confirming makes no model call and costs nothing; blocking it would punish the user for the society's budget (AI-SYS-06)."""
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    enabled.set_quota(1)
    p = translate(enabled, owner)  # uses the one request of today
    assert (
        enabled.ask(owner, "AI-R07", {"text": "another one", "target_language": "hi"}).json()[
            "reason"
        ]
        == "budget_exhausted"
    )
    assert enabled.confirm(owner, p).status_code == 200


def test_two_simultaneous_confirmations_execute_exactly_once(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    p = translate(enabled, owner)
    with ThreadPoolExecutor(2) as pool:
        results = list(
            pool.map(
                lambda k: enabled.confirm(owner, p, key=k), ["race-key-000001", "race-key-000002"]
            )
        )
    assert sorted(r.status_code for r in results) == [200, 409]
    assert enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 1
    assert (
        enabled.rows("SELECT count(*) FROM outbox WHERE event_type = 'AIProposalConfirmed'")[0][0]
        == 1
    )
