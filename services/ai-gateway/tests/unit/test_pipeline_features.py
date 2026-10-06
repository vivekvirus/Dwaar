"""The pipeline and the M1 features end to end against the simulator, plus failure behaviour (AI-SYS-06, AT-29, NFR-13, G3, G8, G9, G12)."""

from __future__ import annotations

import base64
import json
import time
import uuid

import pytest

from dwaar_ai_gateway.asr import SimulatedAsr
from dwaar_ai_gateway.config import GatewayConfig
from dwaar_ai_gateway.features import LocationDirectory
from dwaar_ai_gateway.pipeline import Availability, Gateway, GatewayRequest
from dwaar_ai_gateway.providers import SimulatorProvider
from dwaar_ai_gateway.testing import (
    PERSON,
    SOC,
    UNIT_A,
    UNIT_B,
    CompromisedProvider,
    doc,
    make_gateway,
)
from dwaar_ai_gateway.types import Caller, RiskClass, SourceDoc

pytestmark = pytest.mark.req("AI-SYS-06", "AI-SYS-08", "NFR-13")


def go(gw: Gateway, feature: str, caller: Caller, inputs: dict, **kw):  # type: ignore[no-untyped-def]
    return gw.run(
        GatewayRequest(
            feature,
            caller,
            inputs,
            kw.pop("availability", Availability()),
            kw.pop("sources", ()),
            kw.pop("locations", None),
        )
    )


# ---------------------------------------------------------------------------------------------- AI-SYS-08 labelling (every feature)
def test_every_ai_output_is_labelled_with_sources_what_is_saved_and_a_correction_route(
    gateway, resident, secretary, directory
) -> None:  # type: ignore[no-untyped-def]
    r = go(
        gateway, "AI-R07", resident, {"text": "Water supply off on 12/10", "target_language": "hi"}
    )
    assert r.status == "ok" and r.kind == "proposal" and r.proposal is not None
    lab = r.labels
    assert lab is not None and lab.ai_draft is True and lab.simulation is True
    assert "saved" in lab.what_will_be_saved and "Nothing is sent" in lab.what_will_be_saved
    assert "edit" in lab.correction_route.lower() and lab.declining_ai_reduces_service is False
    assert "simulated_output_not_real_ai" in lab.notes
    assert r.simulation is True and r.provider == "simulator" and r.model == "simulator-v1"
    assert (
        r.prompt_version == "translation/v1"
        and r.schema_version == "1"
        and r.input_hash.startswith("sha256:")
    )


def test_deterministic_feature_is_not_an_ai_draft_and_never_promises_delivery(
    gateway, resident
) -> None:  # type: ignore[no-untyped-def]
    r = go(
        gateway,
        "AI-R06",
        resident,
        {
            "manufacturer": "Xiaomi",
            "battery_unrestricted": False,
            "autostart_enabled": False,
            "notifications_enabled": True,
            "missed_alerts_7d": 3,
        },
    )
    assert (
        r.status == "ok" and r.kind == "answer" and r.proposal is None and r.model_called is False
    )
    assert (
        r.labels is not None
        and r.labels.ai_draft is False
        and r.simulation is False
        and r.model == "deterministic"
    )
    a = r.answer or {}
    assert a["guaranteed_delivery"] is False and "cannot guarantee" in a["disclaimer"]
    assert {i["issue"] for i in a["issues"]} == {"battery_optimisation", "autostart_off"}
    assert all(i["reason"] for i in a["issues"])  # G9
    assert a["manufacturer_group"] == "xiaomi" and any(i["vendor_step"] for i in a["issues"])
    assert a["catalogue"]["verified_on_devices"] is False
    assert "guarantee" not in json.dumps(a).lower().replace("cannot guarantee", "").replace(
        "guaranteed_delivery", ""
    )
    assert (
        go(gateway, "AI-R06", resident, {"manufacturer": "Pixel", "missed_alerts_7d": 2}).answer[
            "finding"
        ]
        == "no_setting_problem_found"
    )  # type: ignore[index]
    hi = go(
        gateway,
        "AI-R06",
        Caller(SOC, PERSON, "owner_occ", unit_ids=frozenset({UNIT_A}), language="hi"),
        {"manufacturer": "samsung", "battery_unrestricted": False},
    )
    assert "बैटरी" in hi.answer["issues"][0]["step"]  # type: ignore[index]  # G8: the user's language


# ---------------------------------------------------------------------------------------------- AI-R07 translation (G8)
def test_translation_keeps_the_original_and_flags_legal_or_safety_text_for_human_approval(
    gateway, resident
) -> None:  # type: ignore[no-untyped-def]
    legal = go(
        gateway,
        "AI-R07",
        resident,
        {
            "text": "As per the bye-law a penalty of Rs 500 applies after 15/10. Fire drill is mandatory.",
            "target_language": "hi",
        },
    )
    p = legal.proposal.payload  # type: ignore[union-attr]
    assert p["original_text"].startswith("As per the bye-law") and p["translated_text"].startswith(
        "[SIMULATED hi translation]"
    )
    assert (
        p["legal_or_safety_flag"] is True
        and legal.labels.human_review_required is True
        and legal.labels.original_text_offered is True
    )  # type: ignore[union-attr]
    assert "legal_or_safety_text_needs_human_approval" in legal.labels.notes  # type: ignore[union-attr]
    assert any("penalty" in r or "mandatory" in r for r in p["flag_reasons"])
    plain = go(
        gateway,
        "AI-R07",
        resident,
        {"text": "The clubhouse is closed on Sunday", "target_language": "mr"},
    )
    assert (
        plain.proposal.payload["legal_or_safety_flag"] is False
        and plain.labels.human_review_required is False
    )  # type: ignore[union-attr]
    assert plain.proposal.command == "ai.save_draft" and plain.proposal.risk_class is RiskClass.B  # type: ignore[union-attr]


def test_model_routing_short_text_uses_the_extraction_tier_and_long_text_the_drafting_tier(
    gateway, resident
) -> None:  # type: ignore[no-untyped-def]
    seen: list[str] = []

    class Spy(SimulatorProvider):
        def complete(self, request):  # type: ignore[no-untyped-def]
            seen.append(request.model_id)
            return super().complete(request)

    gw = make_gateway(Spy())
    go(gw, "AI-R07", resident, {"text": "short notice", "target_language": "en"})
    go(gw, "AI-R07", resident, {"text": "long notice " * 80, "target_language": "en"})
    assert seen == ["claude-haiku-4-5-20251001", "claude-sonnet-5-5"]


def test_numbers_missing_from_a_translation_force_human_review() -> None:
    class Dropper(SimulatorProvider):
        def complete(self, request):  # type: ignore[no-untyped-def]
            r = super().complete(request)
            out = json.loads(r.raw_text)
            out["translated_text"] = "[SIMULATED] pay soon"
            return type(r)(
                raw_text=json.dumps(out), model_id="d", simulation=True, provider="simulator"
            )

    res = go(
        make_gateway(Dropper()),
        "AI-R07",
        Caller(SOC, PERSON, "tenant", unit_ids=frozenset({UNIT_A})),
        {"text": "Pay 500 by 15/10", "target_language": "hi"},
    )
    assert res.proposal.payload["legal_or_safety_flag"] is True  # type: ignore[union-attr]
    assert any("numbers" in r for r in res.labels.reasons)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------------------------- AI-C12 poll wording
def test_poll_check_flags_bias_with_reasons_and_proposes_neutral_wording(
    gateway, secretary
) -> None:  # type: ignore[no-untyped-def]
    r = go(
        gateway,
        "AI-C12",
        secretary,
        {
            "question": "Obviously the old lift is wasteful, don't you agree we should replace it immediately?",
            "options": ["Yes", "No"],
        },
    )
    p = r.proposal.payload  # type: ignore[union-attr]
    kinds = {f["kind"] for f in p["bias_flags"]}
    assert {"leading_question", "pressure", "missing_option"} <= kinds
    assert all(f["reason"] for f in p["bias_flags"]) and r.labels.reasons  # type: ignore[union-attr]  # G9
    assert (
        "obviously" not in p["neutral_wording"].lower()
        and "No opinion" in p["options"]
        and p["changed"] is True
    )
    assert p["original_question"].startswith("Obviously") and r.labels.human_review_required  # type: ignore[union-attr]
    clean = go(
        gateway,
        "AI-C12",
        secretary,
        {
            "question": "Should the lobby be repainted this year?",
            "options": ["Yes", "No", "No opinion"],
        },
    )
    assert clean.proposal.payload["bias_flags"] == [] and clean.proposal.payload["changed"] is False  # type: ignore[union-attr]


# ---------------------------------------------------------------------------------------------- AI-C01 notice drafter (G3)
def test_notice_drafter_is_multilingual_flags_threats_and_never_publishes(
    gateway, secretary
) -> None:  # type: ignore[no-untyped-def]
    r = go(
        gateway,
        "AI-C01",
        secretary,
        {
            "brief": "Pay maintenance by 15/10 or else we will publish your name on the notice board.",
            "languages": ["en", "hi", "mr"],
        },
    )
    p = r.proposal.payload  # type: ignore[union-attr]
    assert p["requires_publish_approval"] is True and {
        t["language"] for t in p["translations"]
    } == {"hi", "mr"}
    assert p["threatening_flags"] and all(f["reason"] for f in p["threatening_flags"])
    assert (
        "threatening_language_flagged" in r.labels.notes
        and "publishing_needs_committee_approval" in r.labels.notes
    )  # type: ignore[union-attr]
    assert (
        "not published" in r.labels.what_will_be_saved
        and r.proposal.command == "notice.create_draft"
    )  # type: ignore[union-attr]
    nodate = go(
        gateway, "AI-C01", secretary, {"brief": "Lift maintenance will happen soon"}
    ).proposal  # type: ignore[union-attr]
    assert set(nodate.missing_fields) == {"date", "time"}


# ---------------------------------------------------------------------------------------------- AI-R02 complaint intake
def test_complaint_resolves_the_place_to_an_authorised_unit_id_never_free_text(
    gateway, resident, directory
) -> None:  # type: ignore[no-untyped-def]
    r = go(
        gateway,
        "AI-R02",
        resident,
        {"transcript": "Water is leaking in flat B-402 kitchen pipe"},
        locations=directory,
    )
    p = r.proposal.payload  # type: ignore[union-attr]
    assert (
        p["location_status"] == "unit"
        and p["unit_id"] == str(UNIT_A)
        and p["unit_label"] == "B-402"
        and p["category"] in {"plumbing", "water_supply"}
    )
    assert (
        r.proposal.target_ids == (UNIT_A,)
        and r.proposal.target_versions == (3,)
        and r.proposal.command == "ticket.create"
    )  # type: ignore[union-attr]
    assert "Nothing is submitted yet" in r.labels.what_will_be_saved  # type: ignore[union-attr]  # no auto-submit
    assert r.proposal.missing_fields == []  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "text",
    [
        "tap leaking in flat B-403",  # a neighbour's unit the caller does not hold
        "water leaking in C-301",  # a unit that is not theirs
        "something is leaking in 402",  # no block
        "pipe burst in A-102 and B-403 both",
    ],
)
def test_a_wrong_or_unknown_block_or_flat_is_never_resolved_it_asks(
    gateway, resident, directory, text: str
) -> None:  # type: ignore[no-untyped-def]
    r = go(gateway, "AI-R02", resident, {"transcript": text}, locations=directory)
    p = r.proposal.payload  # type: ignore[union-attr]
    assert p["unit_id"] is None and p["location_status"] in {
        "unresolved",
        "not_in_authorised_units",
        "ambiguous",
    }
    assert "location" in r.proposal.missing_fields and r.proposal.target_ids == ()  # type: ignore[union-attr]
    assert any("choose" in x for x in r.labels.reasons)  # type: ignore[union-attr]


def test_complaint_single_unit_preselect_is_marked_for_confirmation_and_common_areas_resolve(
    gateway, resident
) -> None:  # type: ignore[no-untyped-def]
    one = LocationDirectory(
        units=[
            __import__("dwaar_ai_gateway.features", fromlist=["LocationRef"]).LocationRef(
                UNIT_A, "B", "B-402", 3
            )
        ]
    )
    r = go(
        gateway,
        "AI-R02",
        resident,
        {"transcript": "the geyser does not heat water since morning and the switch sparks"},
        locations=one,
    )
    assert (
        r.proposal.payload["unit_id"] == str(UNIT_A)
        and "single_authorised_unit_preselected_confirm_it" in r.labels.notes
    )  # type: ignore[union-attr]
    c = go(
        gateway,
        "AI-R02",
        resident,
        {"transcript": "Garbage near the lobby is not cleared"},
        locations=one,
    )
    assert c.proposal.payload["common_area"] == "lobby" and c.proposal.payload["unit_id"] is None  # type: ignore[union-attr]


def test_emergency_words_raise_urgency_by_rule_even_if_the_model_missed_them() -> None:
    class Calm(SimulatorProvider):
        def complete(self, request):  # type: ignore[no-untyped-def]
            r = super().complete(request)
            out = json.loads(r.raw_text)
            out["urgency_suggestion"] = "low"
            return type(r)(
                raw_text=json.dumps(out), model_id="c", simulation=True, provider="simulator"
            )

    caller = Caller(SOC, PERSON, "tenant", unit_ids=frozenset({UNIT_A}))
    r = go(
        make_gateway(Calm()),
        "AI-R02",
        caller,
        {"transcript": "There is smoke and a gas smell in B-402 kitchen"},
        locations=LocationDirectory(),
    )
    assert r.proposal.payload["urgency"] == "emergency"  # type: ignore[union-attr]
    assert (
        "emergency_call_the_guard_or_emergency_number_do_not_wait_for_a_ticket" in r.labels.notes
        and any("urgency raised" in x for x in r.labels.reasons)
    )  # type: ignore[union-attr]


def test_voice_needs_speech_consent_the_60_second_cap_and_valid_audio(
    gateway, resident, directory
) -> None:  # type: ignore[no-untyped-def]
    audio = base64.b64encode(SimulatedAsr.encode("water leaking in flat A-101 bathroom")).decode()
    ok = go(
        gateway,
        "AI-R02",
        resident,
        {"audio_b64": audio, "duration_seconds": 12.5, "speech_consent": True, "language": "en"},
        locations=directory,
    )
    assert (
        ok.status == "ok"
        and ok.proposal.payload["input_mode"] == "voice"
        and ok.proposal.payload["unit_label"] == "A-101"
    )  # type: ignore[union-attr]
    assert "audio is not kept" in ok.labels.what_will_be_saved  # type: ignore[union-attr]
    for bad, field in (
        ({"audio_b64": audio, "duration_seconds": 12.5, "speech_consent": False}, "speech_consent"),
        ({"audio_b64": audio, "duration_seconds": 61, "speech_consent": True}, "audio_b64"),
        ({"audio_b64": audio, "duration_seconds": 0, "speech_consent": True}, "duration_seconds"),
        ({"audio_b64": "!!!", "duration_seconds": 5, "speech_consent": True}, "audio_b64"),
        (
            {
                "audio_b64": base64.b64encode(b"not simulated audio").decode(),
                "duration_seconds": 5,
                "speech_consent": True,
            },
            "audio_b64",
        ),
        ({"audio_b64": audio, "duration_seconds": 5}, "speech_consent"),
    ):
        r = go(gateway, "AI-R02", resident, bad, locations=directory)
        assert r.status == "rejected" and r.reason == "invalid_input" and r.model_called is False, (
            bad
        )
        assert field in json.dumps(r.answer), bad


# ---------------------------------------------------------------------------------------------- AI-F01 triage
def test_triage_groups_duplicates_inside_the_authorised_set_and_emergencies_are_forced(
    gateway, secretary
) -> None:  # type: ignore[no-untyped-def]
    ids = [str(uuid.uuid4()) for _ in range(4)]
    ids.sort()
    docs = [
        doc(
            ids[0],
            "Water is leaking from the pipe under the kitchen sink in B wing",
            unit=UNIT_A,
            version=1,
        ),
        doc(
            ids[1],
            "Water is leaking from the pipe under the kitchen sink in B wing please fix",
            unit=UNIT_A,
        ),
        doc(ids[2], "Strong gas smell in the corridor on the third floor", unit=UNIT_B),
        doc(ids[3], "Another society ticket", society=uuid.uuid4()),
    ]
    r = go(gateway, "AI-F01", secretary, {"ticket_ids": ids}, sources=docs)
    res = {x["ticket_id"]: x for x in r.proposal.payload["results"]}  # type: ignore[union-attr]
    assert set(res) == set(ids[:3])  # the foreign ticket never reached the model
    assert res[ids[1]]["duplicate_of"] == ids[0] and res[ids[0]]["duplicate_of"] is None
    assert res[ids[2]]["priority"] == "emergency" and res[ids[2]]["needs_emergency_review"] is True
    assert all(x["reason"] for x in res.values())  # G9
    assert r.proposal.command == "ticket.apply_triage"  # type: ignore[union-attr]
    assert "some_requested_tickets_were_not_available" in r.labels.notes  # type: ignore[union-attr]  # the reason (another society) is not disclosed
    assert set(r.proposal.target_ids) == {uuid.UUID(i) for i in ids[:3]}  # type: ignore[union-attr]


# ---------------------------------------------------------------------------------------------- AI-G08 handover
def test_handover_keeps_every_unresolved_critical_item_and_never_invents_an_exit(gateway) -> None:  # type: ignore[no-untyped-def]
    sup = Caller(SOC, PERSON, "guard_sup", society_wide=True)

    def ev(
        eid: str, text: str, critical: bool, resolved: bool, kind: str = "incident"
    ) -> SourceDoc:
        return SourceDoc(
            eid,
            SOC,
            "shift_event",
            text,
            meta={"kind": kind, "critical": critical, "resolved": resolved},
        )

    ev_list = [
        ev("e1", "Gate light fused, electrician called", True, False),
        ev("e2", "Delivery logged and cleared", False, True, "note"),
        ev("e3", "Unknown person at back wall, supervisor informed", True, False),
        ev("e4", "Fire extinguisher checked", True, True),
    ]
    r = go(gateway, "AI-G08", sup, {"shift_id": "S1"}, sources=ev_list)
    p = r.proposal.payload  # type: ignore[union-attr]
    assert [i["event_id"] for i in p["pending_critical_items"]] == [
        "e1",
        "e3",
    ]  # deterministic, from the sources, not from the model
    assert (
        r.proposal.command == "shift.save_handover"
        and "never records an entry or exit" in r.proposal.estimated_effect
    )  # type: ignore[union-attr]

    class Inventor(SimulatorProvider):
        def complete(self, request):  # type: ignore[no-untyped-def]
            out = json.loads(super().complete(request).raw_text)
            out["narrative"] = "The visitor exited at 2 am and the vehicle left the premises."
            return type(super().complete(request))(
                raw_text=json.dumps(out), model_id="i", simulation=True, provider="simulator"
            )

    bad = go(make_gateway(Inventor()), "AI-G08", sup, {"shift_id": "S1"}, sources=ev_list)
    assert bad.status == "unavailable" and bad.diagnostics[-1]["why"] == "invented_movement_claim"


# ---------------------------------------------------------------------------------------------- AI-C05
def test_bill_run_anomaly_is_an_interface_only_and_says_so(gateway, secretary) -> None:  # type: ignore[no-untyped-def]
    r = go(gateway, "AI-C05", secretary, {})
    assert (
        r.status == "unavailable"
        and r.reason == "feature_not_available"
        and "ledger" in (r.fallback or {})["detail"]
        and r.model_called is False
    )


# ---------------------------------------------------------------------------------------------- role gating and unknowns
def test_role_gating_unknown_feature_and_invalid_inputs(gateway, resident, secretary) -> None:  # type: ignore[no-untyped-def]
    assert (
        go(gateway, "AI-C01", resident, {"brief": "write a notice about water"}).reason
        == "role_not_allowed_for_feature"
    )
    assert (
        go(gateway, "AI-F01", resident, {"ticket_ids": ["x"]}).reason
        == "role_not_allowed_for_feature"
    )
    assert go(gateway, "AI-ZZ9", secretary, {}).reason == "unknown_feature"
    bad = go(gateway, "AI-R07", resident, {"text": "", "target_language": "fr", "extra": 1})
    assert bad.status == "rejected" and bad.reason == "invalid_input" and bad.model_called is False


# ---------------------------------------------------------------------------------------------- failure behaviour (AI-SYS-06, AT-29)
@pytest.mark.parametrize("fail", ["outage", "rate_limited", "refused", "error"])
def test_provider_failure_returns_the_ordinary_path_without_a_spinner(resident, fail: str) -> None:
    r = go(
        make_gateway(SimulatorProvider(fail_with=fail)),
        "AI-R07",
        resident,
        {"text": "hello", "target_language": "hi"},
    )
    assert (
        r.status == "unavailable"
        and r.reason == f"provider_{fail}"
        and r.proposal is None
        and r.answer is None
    )
    assert r.fallback == {
        "kind": "ordinary_form",
        "feature_id": "AI-R07",
        "reason": f"provider_{fail}",
        "retry": "later",
        "message_key": "ai.fallback.ordinary_path",
        "blocks_user": False,
        "upsell": False,
    }
    assert r.outcome is not None and r.outcome.value == "failed" and r.model_called is True


def test_a_slow_provider_is_cut_off_at_the_timeout_not_after_the_model_finishes(resident) -> None:
    gw = make_gateway(SimulatorProvider(delay_seconds=2.0), timeout=0.2)
    t0 = time.perf_counter()
    r = go(gw, "AI-R07", resident, {"text": "hello", "target_language": "hi"})
    assert time.perf_counter() - t0 < 1.0
    assert r.status == "unavailable" and r.reason == "provider_timeout" and r.latency_ms < 1000
    assert GatewayConfig().timeout_seconds == 15.0  # AI-SYS-06 / NFR-13 default


@pytest.mark.parametrize(
    ("availability", "reason"),
    [
        (Availability(False, "kill_switch"), "kill_switch"),
        (Availability(False, "feature_disabled"), "feature_disabled"),
        (Availability(False, "not_enabled"), "not_enabled"),
        (Availability(True, None, False), "budget_exhausted"),
    ],
)
def test_switches_and_budget_disable_optional_assistance_with_no_model_call(
    resident, availability: Availability, reason: str
) -> None:
    spy = SimulatorProvider()
    r = go(
        make_gateway(spy),
        "AI-R07",
        resident,
        {"text": "hello", "target_language": "hi"},
        availability=availability,
    )
    assert (
        r.status == "unavailable"
        and r.reason == reason
        and spy.calls == 0
        and r.model_called is False
    )
    assert (
        r.fallback and r.fallback["blocks_user"] is False and r.fallback["upsell"] is False
    )  # no AI upsell, ever
    assert r.outcome is not None and r.outcome.value == "abstained"


def test_an_exhausted_budget_does_not_stop_the_deterministic_feature(gateway, resident) -> None:  # type: ignore[no-untyped-def]
    r = go(
        gateway,
        "AI-R06",
        resident,
        {"manufacturer": "oppo", "autostart_enabled": False},
        availability=Availability(True, None, False),
    )
    assert r.status == "ok"  # costs nothing, so the budget does not apply


def test_a_prompt_pin_selects_the_rollback_version_and_a_missing_pin_target_falls_back(
    gateway, resident
) -> None:  # type: ignore[no-untyped-def]
    ok = go(
        gateway,
        "AI-R07",
        resident,
        {"text": "hello there", "target_language": "hi"},
        availability=Availability(True, None, True, "v1"),
    )
    assert ok.prompt_version == "translation/v1"
    gone = go(
        gateway,
        "AI-R07",
        resident,
        {"text": "hello there", "target_language": "hi"},
        availability=Availability(True, None, True, "v9"),
    )
    assert gone.status == "unavailable" and gone.reason == "prompt_unavailable"


def test_a_crashing_handler_fails_closed_to_the_ordinary_path(resident) -> None:  # type: ignore[no-untyped-def]
    class Boom(SimulatorProvider):
        def complete(self, request):  # type: ignore[no-untyped-def]
            r = super().complete(request)
            return type(r)(
                raw_text=json.dumps(
                    {
                        "translated_text": "x",
                        "source_language": "en",
                        "target_language": "hi",
                        "legal_or_safety_flag": False,
                        "flag_reasons": [5],
                    }
                ),
                model_id="b",
                simulation=True,
                provider="simulator",
            )

    r = go(make_gateway(Boom()), "AI-R07", resident, {"text": "hello", "target_language": "hi"})
    assert r.status == "unavailable" and r.reason == "output_rejected"


# ---------------------------------------------------------------------------------------------- redaction before the model
def test_the_model_never_sees_personal_identifiers_and_the_caller_gets_them_back(resident) -> None:  # type: ignore[no-untyped-def]
    comp = CompromisedProvider(["benign"])
    r = go(
        make_gateway(comp),
        "AI-R07",
        resident,
        {
            "text": "Call me on +91 99999 00123 or mail a.b@example.in about A-101",
            "target_language": "hi",
        },
    )
    assert (
        "99999" not in comp.seen_text
        and "a.b@example.in" not in comp.seen_text
        and "⟦PHONE:" in comp.seen_text
    )
    assert r.redaction_counts == {"phone": 1, "email": 1}
    assert "+91 99999 00123" in r.proposal.payload["translated_text"]  # type: ignore[union-attr]  # re-identified for the authorised caller only
    assert "⟦" not in json.dumps(r.proposal.payload)  # type: ignore[union-attr]


def test_g3_the_ai_never_messages_anyone_and_features_only_produce_drafts_or_answers(
    gateway,
) -> None:  # type: ignore[no-untyped-def]
    for h in gateway.features():
        s = h.spec
        assert s.g3_basis in {"user_initiated_draft", "user_requested_answer"}, s.id
        if s.command:
            spec = gateway.commands.get(s.command)
            assert (
                spec is not None
                and "send" not in s.command
                and "message" not in s.command
                and "notify" not in s.command
            )
