"""POST /v1/ai/feedback: run id, outcome, correction -> stored (redacted); feeds evaluation (PRD 12.1, AI-SYS-07, G6)."""

from __future__ import annotations

import pytest

from tests.integration.ai._support import AW

pytestmark = pytest.mark.req("AI-SYS-07", "AI-SYS-08")


@pytest.fixture
def enabled(aw: AW) -> AW:
    aw.set_quota(100)
    return aw


def fb(
    aw: AW, who, run_id: str, outcome: str, correction: str | None = None, key: str | None = None
):  # type: ignore[no-untyped-def]
    body = {"run_id": run_id, "outcome": outcome}
    if correction is not None:
        body["correction"] = correction
    return aw.call(who, "POST", "/v1/ai/feedback", json=body, key=key)


def test_rejecting_a_draft_with_a_correction_stores_it_redacted_and_closes_the_proposal(
    enabled: AW,
) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    b = enabled.draft(owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"})
    r = fb(
        enabled,
        owner,
        b["run_id"],
        "rejected",
        "Wrong tone. Call me on +91 99999 00123 or mail a.b@example.in instead",
    )
    assert r.status_code == 200
    out = r.json()
    assert (
        out["stored"] is True
        and out["proposal_rejected"] is True
        and out["feeds_evaluation"] is True
        and out["correction_redacted"] is True
    )
    (row,) = enabled.rows("SELECT outcome, correction_redacted, redaction_counts FROM ai_feedback")
    assert row[0] == "rejected" and row[2] == {"phone": 1, "email": 1}
    assert (
        "99999" not in row[1]
        and "a.b@example.in" not in row[1]
        and "⟦PHONE:" in row[1]
        and "Wrong tone" in row[1]
    )  # irreversible tokens, no raw identifier
    assert enabled.runs()[0]["outcome"] == "rejected"
    assert enabled.rows("SELECT state FROM action_proposals") == [("rejected",)]
    assert (
        enabled.confirm(owner, b["proposal"]).status_code == 409
    )  # a rejected proposal cannot be confirmed
    assert enabled.rows(
        "SELECT operation FROM audit_log WHERE operation = 'ai.proposal.reject'"
    ) == [("ai.proposal.reject",)]


def test_accepting_an_open_proposal_must_go_through_confirm(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    b = enabled.draft(owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"})
    r = fb(enabled, owner, b["run_id"], "accepted")
    assert r.status_code == 422 and r.json()["details"]["reason"] == "confirm_the_proposal_instead"
    enabled.confirm(owner, b["proposal"])
    after = fb(enabled, owner, b["run_id"], "accepted")
    assert after.status_code == 200 and after.json()["proposal_rejected"] is False
    assert enabled.rows("SELECT state FROM action_proposals") == [("confirmed",)]


def test_feedback_on_an_answer_without_a_proposal_and_one_feedback_per_run(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    ans = enabled.ask(owner, "AI-R06", {"manufacturer": "oppo"}).json()
    assert fb(enabled, owner, ans["run_id"], "accepted").status_code == 200
    assert (
        enabled.runs()[0]["outcome"] is None
    )  # an 'accepted' answer is feedback, not a decision that changes the run
    again = fb(enabled, owner, ans["run_id"], "rejected", key="fb-key-000002")
    assert again.status_code == 409 and again.json()["code"] == "already_decided"
    assert enabled.rows("SELECT count(*) FROM ai_feedback")[0][0] == 1


def test_feedback_is_private_to_the_person_who_made_the_run_and_validated(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    other = enabled.person("owner2", unit="A-102", kind="owner")
    b = enabled.draft(owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"})
    assert fb(enabled, other, b["run_id"], "rejected").status_code == 404
    assert fb(enabled, enabled.vw.secretary, b["run_id"], "rejected").status_code == 404
    assert fb(enabled, enabled.other_secretary, b["run_id"], "rejected").status_code in {403, 404}
    assert (
        fb(enabled, owner, "not-a-uuid-not-a-uuid-not-a-uuid-xxxx"[:36], "rejected").status_code
        == 404
    )
    assert (
        fb(enabled, owner, b["run_id"], "failed").status_code == 400
    )  # 'failed'/'abstained' are not user outcomes
    assert fb(enabled, owner, b["run_id"], "rejected", "x" * 2001).status_code == 400
    assert enabled.rows("SELECT count(*) FROM ai_feedback")[0][0] == 0
