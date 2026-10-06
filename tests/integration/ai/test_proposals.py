"""POST /v1/ai/proposals and the M1 features through the real API (PRD 12.1, AI-SYS-01, AI-SYS-04, AI-SYS-08, G3, G8)."""

from __future__ import annotations

import base64
import json
import uuid

import pytest

from dwaar_ai_gateway.asr import SimulatedAsr
from tests.integration.ai._support import AW, FakeShifts, FakeTickets, body_text

pytestmark = pytest.mark.req("AI-SYS-01", "AI-SYS-04", "AI-SYS-08")


@pytest.fixture
def enabled(aw: AW) -> AW:
    aw.set_quota(100)
    return aw


def test_ai_is_off_by_default_until_the_society_sets_an_allowance(aw: AW) -> None:
    tenant = aw.person("tenant1", unit="A-101", kind="tenant")
    r = aw.ask(tenant, "AI-R07", {"text": "hello", "target_language": "hi"})
    assert r.status_code == 200
    b = r.json()
    assert (
        b["status"] == "unavailable"
        and b["reason"] == "not_enabled"
        and b["fallback"]["kind"] == "ordinary_form"
        and b["proposal"] is None
    )
    assert [x["status"] for x in aw.runs()] == ["unavailable"] and aw.runs()[0][
        "model_called"
    ] is False


def test_translation_proposal_is_a_labelled_draft_with_the_original_and_a_payload_hash(
    enabled: AW,
) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    b = enabled.draft(
        owner,
        "AI-R07",
        {
            "text": "As per the bye-law a penalty of Rs 500 applies after 15/10.",
            "target_language": "hi",
        },
    )
    p = b["proposal"]
    assert (
        b["kind"] == "proposal"
        and b["simulation"] is True
        and p["command"] == "ai.save_draft"
        and p["risk_class"] == "B"
        and p["state"] == "proposed"
    )
    assert (
        p["payload"]["original_text"].startswith("As per the bye-law")
        and p["payload"]["legal_or_safety_flag"] is True
    )
    assert (
        b["labels"]["ai_draft"] is True
        and b["labels"]["original_text_offered"] is True
        and b["labels"]["human_review_required"] is True
    )
    assert (
        b["labels"]["declining_ai_reduces_service"] is False
        and "simulated_output_not_real_ai" in b["labels"]["notes"]
    )
    assert p["payload_hash"].startswith("sha256:") and p["expires_at"] > "2026"
    got = enabled.call(owner, "GET", f"/v1/ai/proposals/{p['id']}")
    assert got.status_code == 200 and got.json()["payload_hash"] == p["payload_hash"]
    assert [x["id"] for x in enabled.call(owner, "GET", "/v1/ai/proposals").json()["items"]] == [
        p["id"]
    ]
    # nothing was executed: no draft, no event of a confirmed proposal
    assert enabled.rows("SELECT count(*) FROM ai_drafts")[0][0] == 0
    assert (
        enabled.rows("SELECT count(*) FROM outbox WHERE event_type = 'AIProposalConfirmed'")[0][0]
        == 0
    )
    assert (
        enabled.rows("SELECT count(*) FROM outbox WHERE event_type = 'AIProposalCreated'")[0][0]
        == 1
    )
    assert (
        enabled.rows("SELECT count(*) FROM audit_log WHERE operation = 'ai.proposal.create'")[0][0]
        == 1
    )


def test_ai_runs_records_the_audit_facts_and_never_a_raw_prompt_or_payload(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    secret_text = (
        "Call me on +91 99999 00123 about the SECRETWORD in the notice, mail a.b@example.in"
    )
    enabled.draft(owner, "AI-R07", {"text": secret_text, "target_language": "mr"})
    (run,) = enabled.runs()
    assert (
        run["feature_id"] == "AI-R07"
        and run["provider"] == "simulator"
        and run["model"] == "simulator-v1"
        and run["simulation"] is True
    )
    assert (
        run["prompt_version"] == "translation/v1"
        and run["schema_version"] == "1"
        and run["model_called"] is True
        and run["cost_paise"] == 0
    )
    assert (
        run["input_hash"].startswith("sha256:")
        and run["redaction_counts"] == {"phone": 1, "email": 1}
        and run["outcome"] is None
        and run["actor_role"] == "owner_occ"
    )
    # the whole row (every column) and the audit and outbox rows contain no prompt text and no identifier
    blob = json.dumps(enabled.rows("SELECT row_to_json(r)::text FROM ai_runs r"), default=str)
    blob += json.dumps(enabled.rows("SELECT diff_masked::text, reason FROM audit_log"), default=str)
    blob += json.dumps(enabled.rows("SELECT payload::text FROM outbox"), default=str)
    for needle in ("SECRETWORD", "99999", "a.b@example.in", "Call me"):
        assert needle not in blob, needle


def test_idempotency_key_replays_the_same_proposal_and_a_different_payload_is_409(
    enabled: AW,
) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    first = enabled.ask(
        owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"}, key="idem-key-0001"
    )
    again = enabled.ask(
        owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"}, key="idem-key-0001"
    )
    assert first.status_code == 200 and again.headers.get("Idempotent-Replayed") == "true"
    assert first.json()["proposal"]["id"] == again.json()["proposal"]["id"]
    assert (
        len(enabled.runs()) == 1
        and enabled.rows("SELECT count(*) FROM action_proposals")[0][0] == 1
    )  # no second model call, no second proposal
    other = enabled.ask(
        owner, "AI-R07", {"text": "different", "target_language": "hi"}, key="idem-key-0001"
    )
    assert other.status_code == 409 and other.json()["code"] == "duplicate_payload_mismatch"
    missing = enabled.call(
        owner,
        "POST",
        "/v1/ai/proposals",
        json={"feature_id": "AI-R07", "inputs": {}},
        headers={"Idempotency-Key": ""},
    )
    assert missing.status_code == 400


def test_pr_12_2_errors_for_bad_requests(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    bad = enabled.ask(owner, "AI-R07", {"text": "", "target_language": "fr"})
    assert (
        bad.status_code == 400
        and bad.json()["code"] == "invalid_schema"
        and bad.json()["request_id"]
        and {f["field"] for f in bad.json()["details"]["fields"]}
    )
    assert enabled.ask(owner, "AI-ZZ9", {}).status_code == 404
    assert (
        enabled.ask(owner, "AI-C01", {"brief": "a notice about water"}).status_code == 403
    )  # feature not open to this role
    extra = enabled.call(
        owner,
        "POST",
        "/v1/ai/proposals",
        json={"feature_id": "AI-R07", "inputs": {}, "society_id": str(uuid.uuid4())},
    )
    assert extra.status_code == 400  # a society id in the body is not even a field
    assert (
        enabled.call(None, "POST", "/v1/ai/proposals", json={"feature_id": "AI-R07"}).status_code
        == 401
    )
    guard = enabled.vw.guard  # a guard has no AI role at all
    assert enabled.ask(guard, "AI-R07", {"text": "x", "target_language": "hi"}).status_code == 403
    outsider = enabled.vw.person("outsider")
    assert (
        enabled.ask(outsider, "AI-R07", {"text": "x", "target_language": "hi"}).status_code == 404
    )  # no standing in this society


def test_excluded_ai_cannot_be_requested_as_a_feature_or_an_input(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    for name in (
        "face_match",
        "emotion_score",
        "credit_scoring",
        "auto_fine",
        "payment_execute",
        "tax_filing",
        "ad_targeting",
        "gate_decision",
    ):
        r = enabled.ask(owner, name, {})
        assert (
            r.status_code == 422
            and r.json()["code"] == "policy_violation"
            and r.json()["details"]["reason"] == "excluded_ai_cannot_be_enabled"
        ), name
    r = enabled.ask(
        owner, "AI-R07", {"text": "hi", "target_language": "hi", "facial_recognition": True}
    )
    assert r.status_code == 422 and r.json()["details"]["capability"] == "facial_recognition"
    assert enabled.rows("SELECT count(*) FROM ai_runs")[0][0] == 0  # refused before anything ran


def test_features_listing_is_per_role_honest_and_states_the_promises(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    r = enabled.call(owner, "GET", "/v1/ai/features")
    assert r.status_code == 200
    b = r.json()
    ids = {i["id"] for i in b["items"]}
    assert (
        ids == {"AI-R07", "AI-R02", "AI-R06"}
        and b["optional"] is True
        and b["declining_ai_reduces_service"] is False
    )
    assert (
        b["training_on_customer_data"] is False
        and b["subprocessors"][0]["name"] == "Anthropic"
        and "[VERIFY]" in b["subprocessors"][0]["status"]
    )
    assert (
        set(b["guardrails"]) == {f"G{i}" for i in range(1, 13)}
        and "facial_recognition" in b["excluded_ai"]
    )
    sec = enabled.call(enabled.vw.secretary, "GET", "/v1/ai/features").json()
    assert {"AI-C01", "AI-C12", "AI-F01", "AI-R07"} <= {i["id"] for i in sec["items"]}
    c05 = (
        next(i for i in sec["items"] if i["id"] == "AI-C05")
        if any(i["id"] == "AI-C05" for i in sec["items"])
        else None
    )
    assert c05 is None or c05["available"] is False


def test_notification_health_needs_no_model_and_no_budget(aw: AW) -> None:
    owner = aw.person(
        "owner1", unit="A-101", kind="owner"
    )  # quota is 0: AI is 'off', the deterministic assistant still answers
    r = aw.ask(
        owner,
        "AI-R06",
        {
            "manufacturer": "Xiaomi",
            "battery_unrestricted": False,
            "notifications_enabled": True,
            "missed_alerts_7d": 4,
        },
        language="mr",
    )
    b = r.json()
    assert (
        b["status"] == "ok"
        and b["kind"] == "answer"
        and b["proposal"] is None
        and b["simulation"] is False
    )
    assert (
        b["answer"]["guaranteed_delivery"] is False
        and b["answer"]["issues"][0]["issue"] == "battery_optimisation"
    )
    assert "बॅटरी" in b["answer"]["issues"][0]["step"] and b["labels"]["ai_draft"] is False
    assert aw.runs()[0]["model"] == "deterministic" and aw.runs()[0]["model_called"] is False


def test_poll_check_and_notice_drafter_for_committee_roles(enabled: AW) -> None:
    sec = enabled.vw.secretary
    poll = enabled.draft(
        sec,
        "AI-C12",
        {
            "question": "Obviously the lift is wasteful, don't you agree we must act immediately?",
            "options": ["Yes", "No"],
        },
    )
    assert {f["kind"] for f in poll["proposal"]["payload"]["bias_flags"]} >= {
        "leading_question",
        "pressure",
        "missing_option",
    }
    assert poll["labels"]["reasons"] and poll["labels"]["human_review_required"]
    notice = enabled.draft(
        sec,
        "AI-C01",
        {"brief": "Pay by 15/10 or else we will publish your name.", "languages": ["en", "hi"]},
    )
    p = notice["proposal"]
    assert (
        p["command"] == "notice.create_draft"
        and p["payload"]["requires_publish_approval"] is True
        and p["payload"]["threatening_flags"]
    )
    assert "not published" in notice["labels"]["what_will_be_saved"]


def test_complaint_by_voice_resolves_to_the_callers_own_unit_id_and_a_wrong_flat_is_never_guessed(
    enabled: AW,
) -> None:
    tenant = enabled.person("tenant1", unit="A-101", kind="tenant")
    audio = base64.b64encode(
        SimulatedAsr.encode("Water is leaking in flat A-101 bathroom pipe")
    ).decode()
    r = enabled.ask(
        tenant,
        "AI-R02",
        {"audio_b64": audio, "duration_seconds": 14, "speech_consent": True, "language": "en"},
    )
    p = r.json()["proposal"]
    assert (
        p["payload"]["unit_id"] == str(enabled.unit("A-101"))
        and p["payload"]["input_mode"] == "voice"
        and p["command"] == "ticket.create"
    )
    assert p["target_ids"] == [str(enabled.unit("A-101"))] and p["target_versions"] == [1]
    wrong = enabled.draft(
        tenant, "AI-R02", {"transcript": "tap leaking in flat A-102"}
    )  # a neighbour's flat
    assert (
        wrong["proposal"]["payload"]["unit_id"] is None
        and "location" in wrong["proposal"]["missing_fields"]
        and wrong["proposal"]["target_ids"] == []
    )
    audio61 = base64.b64encode(SimulatedAsr.encode("x y z w")).decode()
    for bad in (
        {"audio_b64": audio61, "duration_seconds": 61, "speech_consent": True},
        {"audio_b64": audio61, "duration_seconds": 5, "speech_consent": False},
    ):
        rr = enabled.ask(tenant, "AI-R02", bad)
        assert rr.status_code == 400 and rr.json()["code"] == "invalid_schema", bad
    other_unit = enabled.ask(
        tenant, "AI-R02", {"transcript": "leak at home", "unit_id": str(enabled.unit("A-102"))}
    )
    assert (
        other_unit.status_code == 404
    )  # naming a unit you do not hold looks like a unit that does not exist


def test_triage_and_handover_use_the_narrow_ports_and_report_when_the_module_is_missing(
    enabled: AW,
) -> None:
    est = enabled.person("em", "estate_mgr")
    sup = enabled.vw.guard_sup
    tid = str(uuid.uuid4())
    # no ticket or shift module installed: the ordinary screens remain, with the honest reason
    r = enabled.ask(est, "AI-F01", {"ticket_ids": [tid]})
    assert (
        r.json()["status"] == "unavailable"
        and r.json()["reason"] == "data_source_not_available"
        and r.json()["fallback"]["blocks_user"] is False
    )
    tickets, shifts = FakeTickets(), FakeShifts()
    enabled.rt.sources.update({"AI-F01": tickets, "AI-G08": shifts})
    from dwaar_ai_gateway.types import SourceDoc

    tickets.docs = [
        SourceDoc(
            tid,
            enabled.soc.id,
            "ticket",
            "Strong gas smell in the corridor on the third floor",
            version=4,
        )
    ]
    t = enabled.draft(est, "AI-F01", {"ticket_ids": [tid, str(uuid.uuid4())]})
    assert (
        t["proposal"]["payload"]["results"][0]["priority"] == "emergency"
        and t["proposal"]["target_versions"] == [4]
        and t["proposal"]["command"] == "ticket.apply_triage"
    )
    shifts.docs = [
        SourceDoc(
            "ev1",
            enabled.soc.id,
            "shift_event",
            "Gate light fused",
            meta={"kind": "incident", "critical": True, "resolved": False},
        )
    ]
    h = enabled.draft(sup, "AI-G08", {"shift_id": "S1"})
    assert [i["event_id"] for i in h["proposal"]["payload"]["pending_critical_items"]] == [
        "ev1"
    ] and h["proposal"]["command"] == "shift.save_handover"


def test_ai_c05_is_an_interface_only_and_says_so(enabled: AW) -> None:
    r = enabled.ask(enabled.vw.secretary, "AI-C05", {})
    assert (
        r.json()["status"] == "unavailable"
        and r.json()["reason"] == "feature_not_available"
        and "ledger" in r.json()["fallback"]["detail"]
    )


def test_responses_never_contain_secrets_or_the_provider_key(enabled: AW) -> None:
    owner = enabled.person("owner1", unit="A-101", kind="owner")
    b = enabled.draft(owner, "AI-R07", {"text": "hello", "target_language": "hi"})
    assert (
        "api_key" not in body_text(enabled.call(owner, "GET", "/v1/ai/features")).lower()
        and b["labels"]["simulation"] is True
    )
