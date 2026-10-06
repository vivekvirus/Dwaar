"""The M1 feature handlers: translation (AI-R07), poll wording (AI-C12), notice drafter (AI-C01), voice/text complaint (AI-R02),
ticket triage (AI-F01), shift handover (AI-G08), notification health (AI-R06, deterministic) and the AI-C05 interface.

Each handler = server-written task + untrusted segments (prepare) and deterministic post-processing (finish). The COMMAND is fixed by
the feature spec; nothing the model writes can change it (INV-06). Safety-relevant flags are recomputed by rules (``lexicon``) so a
model that misses an emergency or a legal sentence does not lower the flag.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from typing import Any, Final

from .. import lexicon
from ..asr import SimulatedAsr, check_audio_limits
from ..config import MAX_AUDIO_BYTES, MAX_AUDIO_SECONDS
from ..paths import prompts_root
from ..pii import TokenVault, normalise_digits
from ..ports import AsrAdapter, AsrError
from ..types import Caller, RiskClass, SourceDoc, Tier
from .spec import (
    FeatureHandler,
    FeatureOutput,
    FeatureSpec,
    InvalidInput,
    LocationDirectory,
    Prepared,
    reidentify_value,
    validate_inputs,
)

RESIDENTS: Final = frozenset({"owner_occ", "owner_nr", "tenant", "family"})
COMMITTEE: Final = frozenset({"secretary", "committee", "estate_mgr", "treasurer"})
LANGS: Final = ["en", "hi", "mr"]
_DEVANAGARI: Final = re.compile("[ऀ-ॿ]")


def _script_language(text: str) -> str:
    if _DEVANAGARI.search(text):
        return "unknown"  # hi and mr share the script; a rule cannot tell them apart honestly
    return "en" if re.search(r"[A-Za-z]", text) else "unknown"


# ====================================================================================== AI-R07 translation
class Translation:
    spec = FeatureSpec(
        id="AI-R07", name="Notice and ticket translation", risk_class=RiskClass.B, tier=Tier.EXTRACT,
        roles=RESIDENTS | COMMITTEE, command="ai.save_draft", purpose="translation_draft", summary_key="ai.feature.translation",
        input_schema={"type": "object", "additionalProperties": False, "required": ["text", "target_language"], "properties": {
            "text": {"type": "string", "minLength": 1, "maxLength": 6000},
            "target_language": {"enum": LANGS},
            "source_kind": {"enum": ["notice", "ticket", "message"]},
        }},
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        validate_inputs(self.spec.input_schema, request.inputs)
        text = str(request.inputs["text"])
        tier = (
            Tier.EXTRACT if len(text) <= 600 else Tier.DRAFT
        )  # PRD 10.5: short translation -> Haiku, longer drafting -> Sonnet
        return Prepared(
            segments=[("text", str(request.inputs.get("source_kind", "notice")), text)],
            task={"target_language": request.inputs["target_language"], "source_language_hint": _script_language(text)},
            tier=tier, context={"original": text},
        )  # fmt: skip

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        assert data is not None
        original = prepared.context["original"]
        rule_reasons = [
            f"the text mentions '{w}'"
            for w in lexicon.has_any(original, lexicon.LEGAL_SAFETY_WORDS)[:5]
        ]
        model_reasons = [str(x) for x in data.get("flag_reasons", [])]
        flagged = bool(data["legal_or_safety_flag"]) or bool(rule_reasons)
        reasons = list(dict.fromkeys(rule_reasons + model_reasons))
        translated = reidentify_value(data["translated_text"], vault)
        notes = []
        src_nums = set(re.findall(r"\d+", normalise_digits(original)))
        out_nums = set(re.findall(r"\d+", normalise_digits(translated)))
        if src_nums - out_nums:
            flagged = True
            reasons.append(
                "some numbers in the original do not appear in the translation: compare before use"
            )
        if flagged:
            notes.append("legal_or_safety_text_needs_human_approval")
        payload = {
            "kind": "translation", "original_text": original, "translated_text": translated,
            "source_language": data["source_language"], "target_language": data["target_language"],
            "legal_or_safety_flag": flagged, "flag_reasons": reasons,
        }  # fmt: skip
        return FeatureOutput(
            kind="draft", payload=payload, summary="Translation draft", reasons=reasons, notes=notes,
            human_review_required=flagged, original_text_offered=True,
            what_will_be_saved="Your original text and this translation are saved together as your own draft. Nothing is sent to anyone.",
            estimated_effect="Saves a draft for you; it does not publish or send the translation.",
        )  # fmt: skip


# ====================================================================================== AI-C12 poll wording
class PollWording:
    spec = FeatureSpec(
        id="AI-C12", name="Neutral poll wording check", risk_class=RiskClass.B, tier=Tier.DRAFT,
        roles=frozenset({"secretary", "committee"}), command="ai.save_draft", purpose="poll_wording_review", summary_key="ai.feature.poll",
        input_schema={"type": "object", "additionalProperties": False, "required": ["question"], "properties": {
            "question": {"type": "string", "minLength": 3, "maxLength": 1500},
            "options": {"type": "array", "maxItems": 10, "items": {"type": "string", "minLength": 1, "maxLength": 200}},
        }},
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        validate_inputs(self.spec.input_schema, request.inputs)
        options = [str(o) for o in request.inputs.get("options", [])]
        return Prepared(
            segments=[("question", "poll_text", str(request.inputs["question"])), ("options", "poll_text", "\n".join(options))],
            task={"option_count": len(options)}, context={"question": request.inputs["question"], "options": options},
        )  # fmt: skip

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        assert data is not None
        flags = [dict(f) for f in data["bias_flags"]]
        reasons = [f"{f['kind'].replace('_', ' ')}: {f['reason']}" for f in flags]
        payload = reidentify_value({
            "kind": "poll_wording", "original_question": prepared.context["question"], "original_options": prepared.context["options"],
            "neutral_wording": data["neutral_wording"], "options": data["options"], "bias_flags": flags, "changed": data["changed"],
            "summary_reason": data["summary_reason"],
        }, vault)  # fmt: skip
        return FeatureOutput(
            kind="draft", payload=payload, summary="Poll wording suggestion", reasons=reasons or [str(data["summary_reason"])],
            human_review_required=True, original_text_offered=True,
            what_will_be_saved="The suggested wording is saved as your draft next to your original. Nothing is published; a reviewer accepts or edits it.",
            estimated_effect="Saves a draft; no poll is created or sent.",
        )  # fmt: skip


# ====================================================================================== AI-C01 notice drafter
class NoticeDrafter:
    spec = FeatureSpec(
        id="AI-C01", name="Notice and circular drafter", risk_class=RiskClass.B, tier=Tier.DRAFT,
        roles=frozenset({"secretary", "committee", "estate_mgr"}), command="notice.create_draft", purpose="notice_draft", summary_key="ai.feature.notice",
        input_schema={"type": "object", "additionalProperties": False, "required": ["brief"], "properties": {
            "brief": {"type": "string", "minLength": 5, "maxLength": 4000},
            "languages": {"type": "array", "minItems": 1, "maxItems": 3, "uniqueItems": True, "items": {"enum": LANGS}},
        }},
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        validate_inputs(self.spec.input_schema, request.inputs)
        langs = list(
            request.inputs.get("languages")
            or [request.caller.language if request.caller.language in LANGS else "en"]
        )
        return Prepared(
            segments=[("brief", "message", str(request.inputs["brief"]))],
            task={"languages": langs},
            context={"brief": request.inputs["brief"]},
        )

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        assert data is not None
        flags = [dict(f) for f in data["threatening_flags"]]
        known = {f["span"].lower() for f in flags}
        for w in lexicon.has_any(
            prepared.context["brief"] + "\n" + data["body"], lexicon.THREAT_WORDS
        ):
            if w not in known:
                flags.append(
                    {
                        "span": w,
                        "reason": f"'{w}' reads as a threat; a notice should state facts and the process",
                    }
                )
        reasons = [f"{f['span']}: {f['reason']}" for f in flags]
        payload = reidentify_value({
            "kind": "notice_draft", "title": data["title"], "body": data["body"], "language": data["language"],
            "translations": data["translations"], "threatening_flags": flags, "missing_fields": data["missing_fields"],
            "requires_publish_approval": True, "brief": prepared.context["brief"],
        }, vault)  # fmt: skip
        notes = ["publishing_needs_committee_approval"] + (
            ["threatening_language_flagged"] if flags else []
        )
        return FeatureOutput(
            kind="draft", payload=payload, summary="Notice draft", missing_fields=list(data["missing_fields"]), reasons=reasons, notes=notes,
            human_review_required=True, original_text_offered=True,
            what_will_be_saved="A DRAFT notice is created. It is not published or sent; a committee member must approve it first.",
            estimated_effect="Creates a draft notice only.",
        )  # fmt: skip


# ====================================================================================== AI-R02 complaint intake
_BLOCK_LETTERS: Final = {"ए": "A", "बी": "B", "सी": "C", "डी": "D", "ई": "E"}


def _norm_unit(text: str) -> str:
    t = normalise_digits(text).upper()
    for k, v in _BLOCK_LETTERS.items():
        t = t.replace(k, v)
    return re.sub(r"[^A-Z0-9]", "", t)


_AREA_ALIASES: Final = {
    "लॉबी": "lobby", "छत": "terrace", "गच्ची": "terrace", "पार्किंग": "parking", "बगीचा": "garden", "बाग": "garden", "गेट": "gate", "लिफ्ट": "lift",
    "सीढ़ी": "staircase", "सीढ़ियां": "staircase", "जिना": "staircase", "क्लबहाउस": "clubhouse", "बेसमेंट": "basement",
}  # fmt: skip


def resolve_location(text: str | None, kind: str, directory: LocationDirectory) -> dict[str, Any]:
    """Free text -> an AUTHORISED unit id, a known common area, or NOTHING. A wrong block or flat is a critical error, so any doubt
    (no match, several matches, a unit the caller does not hold) resolves to 'unresolved' and the resident must choose."""
    if not text:
        return {"status": "unresolved", "unit_id": None}
    if kind == "common_area" or (kind != "unit" and text.lower() in directory.common_areas):
        low = text.lower()
        for alias, area in _AREA_ALIASES.items():
            if alias in low and area in directory.common_areas:
                return {"status": "common_area", "unit_id": None, "common_area": area}
        for area in directory.common_areas:
            if area == low or area in low:
                return {"status": "common_area", "unit_id": None, "common_area": area}
        return {"status": "unresolved", "unit_id": None}
    wanted = _norm_unit(text)
    exact = [
        u
        for u in directory.units
        if _norm_unit(f"{u.block}{u.label}") == wanted or _norm_unit(u.label) == wanted
    ]
    if len(exact) == 1:
        u = exact[0]
        return {
            "status": "unit",
            "unit_id": u.unit_id,
            "block": u.block,
            "label": u.label,
            "version": u.version,
        }
    return {"status": "ambiguous" if len(exact) > 1 else "not_in_authorised_units", "unit_id": None}


class ComplaintIntake:
    spec = FeatureSpec(
        id="AI-R02", name="Voice or text complaint intake", risk_class=RiskClass.B, tier=Tier.EXTRACT, roles=RESIDENTS,
        command="ticket.create", purpose="complaint_intake", summary_key="ai.feature.complaint",
        input_schema={"type": "object", "additionalProperties": False, "properties": {
            "transcript": {"type": "string", "minLength": 3, "maxLength": 3000},
            "audio_b64": {"type": "string", "maxLength": 3_000_000},
            "duration_seconds": {"type": "number", "exclusiveMinimum": 0},
            "speech_consent": {"type": "boolean"},
            "language": {"enum": LANGS},
            "unit_id": {"type": "string", "format": "uuid"},
        }, "oneOf": [{"required": ["transcript"]}, {"required": ["audio_b64", "duration_seconds", "speech_consent"]}]},
        ttl_seconds=3600,
    )  # fmt: skip

    def __init__(self, asr: AsrAdapter | None = None) -> None:
        self.asr: AsrAdapter = asr or SimulatedAsr()

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        inp = request.inputs
        if "audio_b64" in inp:  # name the missing field instead of a generic one-of error
            missing = [k for k in ("duration_seconds", "speech_consent") if k not in inp]
            if missing:
                raise InvalidInput([(k, "required") for k in missing])
        elif "transcript" not in inp:
            raise InvalidInput([("transcript", "required")])
        validate_inputs(self.spec.input_schema, inp)
        mode = "text"
        if "audio_b64" in inp:
            mode = "voice"
            if (
                inp.get("speech_consent") is not True
            ):  # consent to SPEECH processing is explicit and per request (PRD 11.2)
                raise InvalidInput([("speech_consent", "required_true")])
            try:
                audio = base64.b64decode(str(inp["audio_b64"]), validate=True)
            except (binascii.Error, ValueError):
                raise InvalidInput([("audio_b64", "invalid_base64")]) from None
            try:
                check_audio_limits(audio, float(inp["duration_seconds"]))
                transcript = self.asr.transcribe(
                    audio,
                    str(inp.get("language", request.caller.language)),
                    float(inp["duration_seconds"]),
                )
            except AsrError as exc:
                raise InvalidInput([("audio_b64", str(exc))]) from None
            text = transcript.text
        else:
            text = str(inp["transcript"])
        directory = request.locations or LocationDirectory()
        return Prepared(
            segments=[("transcript", "transcript", text)], task={"input_mode": mode, "language": inp.get("language", request.caller.language)},
            context={"mode": mode, "text": text, "directory": directory, "unit_hint": inp.get("unit_id")},
        )  # fmt: skip

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        assert data is not None
        directory: LocationDirectory = prepared.context["directory"]
        text = prepared.context["text"]
        loc = data["location_ref"]
        res = resolve_location(loc.get("text"), loc["kind"], directory)
        notes: list[str] = []
        reasons: list[str] = []
        hint = prepared.context.get("unit_hint")
        if res["status"] not in {"unit", "common_area"} and hint:
            # the resident explicitly chose a unit in the app: that is an authorised id from their own grants, not a guess
            pick = [u for u in directory.units if str(u.unit_id) == str(hint)]
            if pick:
                u = pick[0]
                res = {
                    "status": "unit",
                    "unit_id": u.unit_id,
                    "block": u.block,
                    "label": u.label,
                    "version": u.version,
                }
                notes.append("unit_chosen_by_resident")
        if (
            res["status"] not in {"unit", "common_area"}
            and len(directory.units) == 1
            and loc.get("text") is None
        ):
            u = directory.units[0]
            res = {
                "status": "unit",
                "unit_id": u.unit_id,
                "block": u.block,
                "label": u.label,
                "version": u.version,
            }
            notes.append("single_authorised_unit_preselected_confirm_it")
        missing = [m for m in data["missing_fields"] if m != "location"]
        if res["status"] not in {"unit", "common_area"}:
            missing.append("location")
            reasons.append(
                "the place you described could not be matched to one of your own homes or a known common area; please choose it"
                if loc.get("text")
                else "no place was mentioned; please choose where the problem is"
            )
        urgency = data["urgency_suggestion"]
        rule_urg, hits = lexicon.urgency(text)
        order = ["low", "normal", "high", "emergency"]
        if order.index(rule_urg) > order.index(urgency):
            urgency = rule_urg
            reasons.append(
                f"urgency raised to {urgency} because the text mentions: {', '.join(hits[:3])}"
            )
        if urgency == "emergency":
            notes.append("emergency_call_the_guard_or_emergency_number_do_not_wait_for_a_ticket")
        payload: dict[str, Any] = {
            "kind": "complaint", "input_mode": prepared.context["mode"], "category": data["category"],
            "description": reidentify_value(data["description"], vault), "urgency": urgency,
            "location_status": res["status"], "unit_id": str(res["unit_id"]) if res.get("unit_id") else None,
            "unit_label": res.get("label"), "block": res.get("block"), "common_area": res.get("common_area"),
            "language": request.caller.language, "missing_fields": missing,
        }  # fmt: skip
        target_ids = (res["unit_id"],) if res.get("unit_id") else ()
        target_versions = (int(res["version"]),) if res.get("unit_id") else ()
        return FeatureOutput(
            kind="draft", payload=payload, summary="Complaint draft", missing_fields=missing, reasons=reasons, notes=notes,
            target_ids=target_ids, target_versions=target_versions, human_review_required=True,
            what_will_be_saved="Nothing is submitted yet. If you confirm, a complaint is created with the text, category and place shown here. The audio is not kept.",
            estimated_effect="Creates one complaint ticket after you confirm; you can edit every field first.",
        )  # fmt: skip


# ====================================================================================== AI-F01 triage
class TicketTriage:
    spec = FeatureSpec(
        id="AI-F01", name="Ticket triage and duplicate grouping", risk_class=RiskClass.B, tier=Tier.EXTRACT,
        roles=frozenset({"secretary", "committee", "estate_mgr"}), command="ticket.apply_triage", purpose="ticket_triage", summary_key="ai.feature.triage",
        input_schema={"type": "object", "additionalProperties": False, "required": ["ticket_ids"], "properties": {
            "ticket_ids": {"type": "array", "minItems": 1, "maxItems": 30, "uniqueItems": True, "items": {"type": "string", "maxLength": 64}}}},
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        validate_inputs(self.spec.input_schema, request.inputs)
        wanted = set(request.inputs["ticket_ids"])
        used = [d for d in allowed if d.source_id in wanted]
        ids = frozenset(d.source_id for d in used)

        def check(data: dict[str, Any]) -> None:
            from ..validation import OutputRejected

            seen = set()
            for r in data["results"]:
                if r["ticket_id"] not in ids or r["ticket_id"] in seen:
                    raise OutputRejected("unknown_or_repeated_ticket_id")
                seen.add(r["ticket_id"])
                if r["duplicate_of"] is not None and (
                    r["duplicate_of"] not in ids or r["duplicate_of"] == r["ticket_id"]
                ):
                    raise OutputRejected("duplicate_of_not_authorised")

        return Prepared(
            segments=[(d.source_id, "ticket", d.text) for d in used], task={"ticket_count": len(used)},
            allowed_ids=ids, checks=[check], sources_used=used, context={"requested": sorted(wanted)},
        )  # fmt: skip

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        assert data is not None
        texts = {d.source_id: d.text for d in prepared.sources_used}
        versions = {d.source_id: d.version for d in prepared.sources_used}
        results = []
        order = ["low", "normal", "high", "emergency"]
        reasons: list[str] = []
        for r in data["results"]:
            r = dict(r)
            rule, hits = lexicon.urgency(texts[r["ticket_id"]])
            if rule == "emergency" and order.index(r["priority"]) < order.index("emergency"):
                r["priority"] = "emergency"
                r["reason"] = (
                    f"{r['reason']}; raised to emergency by safety rule ({', '.join(hits[:3])})"
                )
            r["reason"] = reidentify_value(r["reason"], vault)
            r["needs_emergency_review"] = r["priority"] == "emergency"
            results.append(r)
            reasons.append(f"{r['ticket_id']}: {r['reason']}")
        unavailable = sorted(set(prepared.context["requested"]) - set(texts))
        target_ids, target_versions = [], []
        for tid in texts:
            try:
                target_ids.append(uuid.UUID(tid))
                target_versions.append(versions[tid])
            except ValueError:
                continue
        payload = {
            "kind": "triage",
            "results": results,
            "ticket_versions": {k: versions[k] for k in texts},
        }
        notes = ["some_requested_tickets_were_not_available"] if unavailable else []
        return FeatureOutput(
            kind="draft", payload=payload, summary="Triage suggestions", reasons=reasons, notes=notes,
            evidence=[{"source_id": k, "kind": "ticket", "version": versions[k]} for k in texts],
            target_ids=tuple(target_ids), target_versions=tuple(target_versions), human_review_required=True,
            what_will_be_saved="If you confirm, the category, priority, team and (where shown) parent incident are applied to these tickets.",
            estimated_effect="Updates triage fields on the listed tickets only; emergencies stay flagged for separate human review.",
        )  # fmt: skip


# ====================================================================================== AI-G08 handover
_CLAIM: Final = re.compile(
    r"\b(exit(ed)?|left|departed|entered|arrived|checked (in|out))\b", re.IGNORECASE
)


class ShiftHandover:
    spec = FeatureSpec(
        id="AI-G08", name="Shift handover summary", risk_class=RiskClass.B, tier=Tier.DRAFT,
        roles=frozenset({"guard_sup", "estate_mgr", "secretary"}), command="shift.save_handover", purpose="shift_handover", summary_key="ai.feature.handover",
        input_schema={"type": "object", "additionalProperties": False, "required": ["shift_id"], "properties": {"shift_id": {"type": "string", "maxLength": 64}}},
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        validate_inputs(self.spec.input_schema, request.inputs)
        events = [d for d in allowed if d.kind == "shift_event"]
        ids = frozenset(d.source_id for d in events)
        kinds = {str(d.meta.get("kind", "event")) for d in events}
        meta = [
            {
                "event_id": d.source_id,
                "kind": d.meta.get("kind", "event"),
                "critical": bool(d.meta.get("critical")),
                "resolved": bool(d.meta.get("resolved")),
            }
            for d in events
        ]

        def check(data: dict[str, Any]) -> None:
            from ..validation import OutputRejected

            for n in data["item_notes"]:
                if n["event_id"] not in ids:
                    raise OutputRejected("note_for_unknown_event")
            if _CLAIM.search(data["narrative"]) and not (
                kinds & {"entry", "exit", "visit", "visitor"}
            ):
                raise OutputRejected("invented_movement_claim")

        return Prepared(
            segments=[(d.source_id, "message", d.text) for d in events], task={"events": meta}, allowed_ids=ids, checks=[check], sources_used=events,
            context={"meta": {m["event_id"]: m for m in meta}},
        )  # fmt: skip

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        assert data is not None
        pending = []
        for d in prepared.sources_used:
            m = prepared.context["meta"][d.source_id]
            if m["critical"] and not m["resolved"]:
                pending.append(
                    {"event_id": d.source_id, "kind": m["kind"], "summary": d.text[:300]}
                )  # deterministic, from the source, never the model
        reasons = [
            f"{p['event_id']}: critical and not marked resolved, so it stays in the handover"
            for p in pending
        ]
        payload = reidentify_value({
            "kind": "handover", "shift_id": request.inputs["shift_id"], "narrative": data["narrative"],
            "item_notes": data["item_notes"], "pending_critical_items": pending,
        }, vault)  # fmt: skip
        return FeatureOutput(
            kind="draft", payload=payload, summary="Shift handover draft", reasons=reasons,
            evidence=[{"source_id": d.source_id, "kind": "shift_event", "version": d.version} for d in prepared.sources_used],
            human_review_required=True,
            what_will_be_saved="If you confirm, this handover is saved for the incoming supervisor. Unresolved critical items are always included.",
            estimated_effect="Saves one handover note; it never records an entry or exit.",
        )  # fmt: skip


# ====================================================================================== AI-R06 notification health (no model)
_CATALOGUE_CACHE: dict[str, Any] = {}


def _catalogue() -> dict[str, Any]:
    if not _CATALOGUE_CACHE:
        path = prompts_root() / "notification_health" / "guidance.json"
        _CATALOGUE_CACHE.update(json.loads(path.read_text(encoding="utf-8")))
    return _CATALOGUE_CACHE


_AUTOSTART_VENDORS: Final = frozenset({"xiaomi", "oppo", "vivo", "huawei"})


def diagnose_notifications(inputs: dict[str, Any], language: str) -> dict[str, Any]:
    cat = _catalogue()
    lang = language if language in LANGS else "en"
    maker = str(inputs.get("manufacturer", "")).strip().lower()
    vendor_key = "google"
    for key, entry in cat["manufacturers"].items():
        if maker in entry["names"] or any(n in maker for n in entry["names"] if len(n) > 3):
            vendor_key = key
            break
    extra = cat["manufacturers"][vendor_key]["extra"]
    checks = [
        (
            "notifications_disabled",
            inputs.get("notifications_enabled") is False,
            "the phone reports notifications are off for Dwaar",
        ),
        (
            "channel_blocked",
            inputs.get("visitor_channel_enabled") is False,
            "the 'Visitor at the gate' channel is blocked or silent",
        ),
        (
            "battery_optimisation",
            inputs.get("battery_unrestricted") is False,
            "battery use for Dwaar is restricted",
        ),
        (
            "background_restricted",
            inputs.get("background_restricted") is True,
            "background activity or data is restricted for Dwaar",
        ),
        (
            "autostart_off",
            inputs.get("autostart_enabled") is False and vendor_key in _AUTOSTART_VENDORS,
            "autostart is off on this phone brand",
        ),
        (
            "do_not_disturb",
            inputs.get("dnd_active") is True and inputs.get("dnd_allows_dwaar") is not True,
            "Do Not Disturb is on and does not allow Dwaar",
        ),
        (
            "app_not_recent",
            inputs.get("app_swiped_away") is True,
            "Dwaar was swiped away from recent apps",
        ),
    ]
    issues = []
    for key, hit, why in checks:
        if hit:
            step = cat["issues"][key][lang]
            vendor_step = extra.get(key)
            issues.append({"issue": key, "reason": why, "step": step, "vendor_step": vendor_step})
    missed = int(inputs.get("missed_alerts_7d") or 0)
    if not issues and missed > 0:
        found = "no_setting_problem_found"
    elif issues:
        found = "settings_to_check"
    else:
        found = "no_problem_reported"
    return {
        "kind": "notification_health", "manufacturer_group": vendor_key, "finding": found, "issues": issues,
        "missed_alerts_7d": missed, "disclaimer": cat["disclaimer"][lang], "guaranteed_delivery": False,
        "catalogue": {"version": cat["catalogue_version"], "verified_on_devices": False, "note": cat["review"]},
    }  # fmt: skip


class NotificationHealth:
    spec = FeatureSpec(
        id="AI-R06", name="Notification health assistant", risk_class=RiskClass.A, tier=Tier.NONE, roles=RESIDENTS | COMMITTEE, command=None,
        purpose="notification_health", uses_model=False, summary_key="ai.feature.notification_health", g3_basis="user_requested_answer",
        input_schema={"type": "object", "additionalProperties": False, "required": ["manufacturer"], "properties": {
            "manufacturer": {"type": "string", "maxLength": 40}, "model": {"type": "string", "maxLength": 60}, "os_version": {"type": "string", "maxLength": 20},
            "notifications_enabled": {"type": "boolean"}, "visitor_channel_enabled": {"type": "boolean"}, "battery_unrestricted": {"type": "boolean"},
            "background_restricted": {"type": "boolean"}, "autostart_enabled": {"type": "boolean"}, "dnd_active": {"type": "boolean"},
            "dnd_allows_dwaar": {"type": "boolean"}, "app_swiped_away": {"type": "boolean"}, "missed_alerts_7d": {"type": "integer", "minimum": 0, "maximum": 1000},
        }},
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        validate_inputs(self.spec.input_schema, request.inputs)
        return Prepared(segments=[], task={})

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        answer = diagnose_notifications(dict(request.inputs), request.caller.language)
        reasons = [f"{i['issue']}: {i['reason']}" for i in answer["issues"]]
        return FeatureOutput(
            kind="answer", payload=answer, summary="Notification health", reasons=reasons, human_review_required=False,
            what_will_be_saved="Nothing is saved. These are steps you can try on your phone.",
            notes=["steps_not_verified_on_every_device", "delivery_is_never_guaranteed"],
        )  # fmt: skip


# ====================================================================================== AI-C05 (interface only)
class BillRunAnomaly:
    """INTERFACE ONLY. The ledger slice does not exist: preset violations must block deterministically there and a model may only explain
    flagged units (PRD 11.1). Registered as unavailable so the catalogue is honest."""

    spec = FeatureSpec(
        id="AI-C05", name="Bill-run anomaly check", risk_class=RiskClass.A, tier=Tier.NONE, roles=frozenset({"secretary", "treasurer", "committee"}),
        command=None, purpose="bill_run_anomaly", uses_model=False, available=False,
        unavailable_reason="waits for the ledger slice: see ports.BillRunSource", summary_key="ai.feature.bill_anomaly",
    )  # fmt: skip

    def prepare(self, request: Any, allowed: list[SourceDoc], max_chars: int) -> Prepared:
        raise NotImplementedError("AI-C05 waits for the ledger slice")

    def finish(
        self, request: Any, prepared: Prepared, data: dict[str, Any] | None, vault: TokenVault
    ) -> FeatureOutput:
        raise NotImplementedError("AI-C05 waits for the ledger slice")


def build_handlers(asr: AsrAdapter | None = None) -> dict[str, FeatureHandler]:
    handlers: list[Any] = [
        Translation(),
        PollWording(),
        NoticeDrafter(),
        ComplaintIntake(asr),
        TicketTriage(),
        ShiftHandover(),
        NotificationHealth(),
        BillRunAnomaly(),
    ]
    return {h.spec.id: h for h in handlers}


__all__ = [
    "MAX_AUDIO_BYTES",
    "MAX_AUDIO_SECONDS",
    "Caller",
    "build_handlers",
    "diagnose_notifications",
    "resolve_location",
]
