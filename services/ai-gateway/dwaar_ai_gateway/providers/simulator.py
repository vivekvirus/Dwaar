"""Deterministic SIMULATOR provider (rule and template based). ``simulation=True`` always.

REQ: AI-SYS-01 (provider adapter), BUILD_BRIEF section 3 (labelled simulator; never claim measured AI quality), INV-06.

This is NOT a language model. It applies small keyword rules and fixed templates to the structured TASK and to the data segments,
treats segment text strictly as DATA (it never follows an instruction found in a segment: there is no code path that does), and
returns JSON that satisfies each feature's output schema. Translations are NOT real: the output is a clearly marked placeholder
(``[SIMULATED <lang> translation]``) followed by the original text, so nobody mistakes it for a translation. Everything it
returns is labelled ``simulation=True`` by the pipeline and shown as such to users.

Failure injection for tests: ``SimulatorProvider(delay_seconds=..., fail_with=...)``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any

from .. import lexicon
from ..pii import normalise_digits
from ..types import ProviderRequest, ProviderResponse
from .base import ProviderError

_UNIT_A = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]|[एबीसीडीई]{1,2})\s*[- ]?\s*(\d{3,4})(?!\d)")
_UNIT_B = re.compile(
    r"(?<!\d)(\d{3,4})\s*(?:in|,|of|-)?\s*(?:block\s+|wing\s+|tower\s+)?([A-Za-z]|[एबीसीडीई]{1,2})\s*(?:block|wing|tower|विंग|ब्लॉक)",
    re.IGNORECASE,
)
_COMMON = ("lobby", "terrace", "parking", "garden", "gate", "clubhouse", "playground", "lift", "staircase", "basement", "podium",
           "लॉबी", "छत", "पार्किंग", "बगीचा", "सीढ़ी", "गेट", "लिफ्ट", "गच्ची", "जिना")  # fmt: skip
_DATE = re.compile(
    r"\b(\d{1,2}[/-]\d{1,2}([/-]\d{2,4})?|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|today|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
    re.I,
)
_TIME = re.compile(
    r"\b(\d{1,2}[:.]\d{2}\s*(am|pm)?|\d{1,2}\s*(am|pm)|noon|morning|evening)\b", re.I
)


def _lang_marker(lang: str) -> str:
    return f"[SIMULATED {lang} translation]"


class SimulatorProvider:
    name = "simulator"
    simulation = True

    def __init__(self, *, delay_seconds: float = 0.0, fail_with: str | None = None) -> None:
        self.delay_seconds = delay_seconds
        self.fail_with = fail_with
        self.calls = 0
        self._handlers: dict[str, Callable[[ProviderRequest], dict[str, Any]]] = {
            "AI-R07": self._translation,
            "AI-C12": self._poll,
            "AI-C01": self._notice,
            "AI-R02": self._complaint,
            "AI-F01": self._triage,
            "AI-G08": self._handover,
        }

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        self.calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if self.fail_with:
            raise ProviderError(self.fail_with)
        handler = self._handlers.get(request.feature_id)
        if handler is None:
            raise ProviderError("error", "no simulator behaviour for this feature")
        out = handler(request)
        text = json.dumps(out, ensure_ascii=False)
        return ProviderResponse(
            raw_text=text, model_id="simulator-v1", input_tokens=sum(len(s.text) for s in request.untrusted) // 4,
            output_tokens=len(text) // 4, simulation=True, provider=self.name,
        )  # fmt: skip

    # ---------------------------------------------------------------- AI-R07
    def _translation(self, r: ProviderRequest) -> dict[str, Any]:
        text = r.untrusted[0].text if r.untrusted else ""
        target = str(r.task.get("target_language", "en"))
        source = str(r.task.get("source_language_hint", "unknown"))
        reasons = [
            f"the text mentions '{w}'"
            for w in lexicon.has_any(text, lexicon.LEGAL_SAFETY_WORDS)[:5]
        ]
        return {
            "translated_text": f"{_lang_marker(target)} {text}",
            "source_language": source if source in {"en", "hi", "mr"} else "unknown",
            "target_language": target,
            "legal_or_safety_flag": bool(reasons),
            "flag_reasons": reasons,
        }

    # ---------------------------------------------------------------- AI-C12
    def _poll(self, r: ProviderRequest) -> dict[str, Any]:
        seg = {s.segment_id: s.text for s in r.untrusted}
        text = seg.get("question", "")
        options = [o.strip() for o in seg.get("options", "").splitlines() if o.strip()]
        flags: list[dict[str, str]] = []
        for w in lexicon.has_any(text, lexicon.BIAS_LEADING):
            flags.append(
                {
                    "span": w,
                    "kind": "leading_question",
                    "reason": f"'{w}' pushes the reader towards one answer",
                }
            )
        for w in lexicon.has_any(text, lexicon.BIAS_PRESSURE):
            flags.append(
                {
                    "span": w,
                    "kind": "pressure",
                    "reason": f"'{w}' adds time pressure that can distort answers",
                }
            )
        if re.search(r"\b(and also|and whether|as well as)\b", text, re.I) or text.count("?") > 1:
            flags.append(
                {
                    "span": text[:60],
                    "kind": "double_barrelled",
                    "reason": "the question appears to ask two things at once",
                }
            )
        if options and not lexicon.has_any(" ".join(options), lexicon.NEUTRAL_OPTIONS):
            flags.append(
                {
                    "span": "options",
                    "kind": "missing_option",
                    "reason": "no 'no opinion' or 'other' option is offered",
                }
            )
        neutral = text
        for f in flags:
            if f["kind"] in {"leading_question", "pressure"}:
                neutral = re.sub(re.escape(f["span"]), "", neutral, flags=re.I)
        neutral = re.sub(r"\s{2,}", " ", neutral).strip(" ,.-")
        new_options = list(options)
        if any(f["kind"] == "missing_option" for f in flags):
            new_options.append("No opinion")
        return {
            "bias_flags": flags[:12], "neutral_wording": neutral or text, "options": new_options,
            "changed": bool(flags), "summary_reason": f"{len(flags)} possible bias issue(s) found by simulator rules" if flags else "no issue found by simulator rules",
        }  # fmt: skip

    # ---------------------------------------------------------------- AI-C01
    def _notice(self, r: ProviderRequest) -> dict[str, Any]:
        brief = r.untrusted[0].text if r.untrusted else ""
        langs = [str(x) for x in r.task.get("languages", ["en"])] or ["en"]
        first = brief.strip().splitlines()[0][:80] if brief.strip() else "Notice"
        missing = []
        if not _DATE.search(brief):
            missing.append("date")
        if not _TIME.search(brief):
            missing.append("time")
        threats = [
            {
                "span": w,
                "reason": f"'{w}' reads as a threat; notices should state facts and the process",
            }
            for w in lexicon.has_any(brief, lexicon.THREAT_WORDS)
        ]
        body = f"Dear residents,\n\n{brief.strip()}\n\nThank you for your cooperation.\nManaging Committee"
        return {
            "title": first, "body": body, "language": langs[0] if langs[0] in {"en", "hi", "mr"} else "en",
            "threatening_flags": threats, "missing_fields": missing,
            "translations": [{"language": lg, "title": f"{_lang_marker(lg)} {first}", "body": f"{_lang_marker(lg)} {body}"} for lg in langs[1:3] if lg in {"en", "hi", "mr"}],
        }  # fmt: skip

    # ---------------------------------------------------------------- AI-R02
    def _complaint(self, r: ProviderRequest) -> dict[str, Any]:
        text = normalise_digits(r.untrusted[0].text if r.untrusted else "").strip()
        loc_kind, loc_text = "unknown", None
        m = _UNIT_B.search(text)
        if m:
            loc_kind, loc_text = "unit", f"{m.group(2)}-{m.group(1)}"
        else:
            m = _UNIT_A.search(text)
            if m:
                loc_kind, loc_text = "unit", f"{m.group(1)}-{m.group(2)}"
        if loc_text is None:
            common = lexicon.has_any(text, _COMMON)
            if common:
                loc_kind, loc_text = "common_area", common[0]
        category = lexicon.classify_category(text)
        urg, _ = lexicon.urgency(text)
        missing = []
        if loc_text is None:
            missing.append("location")
        if len(text.split()) < 4:
            missing.append("description")
        return {
            "location_ref": {"kind": loc_kind, "text": loc_text}, "category": category, "description": text[:1500],
            "urgency_suggestion": urg, "missing_fields": missing,
        }  # fmt: skip

    # ---------------------------------------------------------------- AI-F01
    def _triage(self, r: ProviderRequest) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        seen: list[tuple[str, str, set[str]]] = []
        for seg in sorted(r.untrusted, key=lambda s: s.segment_id):
            toks = set(re.findall(r"\w+", seg.text.lower()))
            cat = lexicon.classify_category(seg.text)
            urg, why = lexicon.urgency(seg.text)
            dup, reason = (
                None,
                f"category '{cat}' from keywords; urgency '{urg}'"
                + (f" because of: {', '.join(why[:3])}" if why else ""),
            )
            for sid, scat, stoks in seen:
                union = toks | stoks
                if scat == cat and union and len(toks & stoks) / len(union) >= 0.6:
                    dup, reason = sid, f"very similar wording to ticket {sid} and the same category"
                    break
            seen.append((seg.segment_id, cat, toks))
            results.append(
                {
                    "ticket_id": seg.segment_id,
                    "category": cat,
                    "priority": urg,
                    "team": lexicon.TEAM_FOR.get(cat, "office"),
                    "duplicate_of": dup,
                    "reason": reason,
                }
            )
        return {"results": results}

    # ---------------------------------------------------------------- AI-G08
    def _handover(self, r: ProviderRequest) -> dict[str, Any]:
        events = {str(e["event_id"]): e for e in r.task.get("events", [])}
        unresolved = [i for i, e in events.items() if e.get("critical") and not e.get("resolved")]
        notes = [
            {
                "event_id": i,
                "note": f"{e.get('kind', 'event')}: {'unresolved' if i in unresolved else 'noted'}",
            }
            for i, e in events.items()
        ]
        return {
            "narrative": f"Simulated summary of {len(events)} event(s); {len(unresolved)} critical item(s) still unresolved.",
            "item_notes": notes[:60],
        }
