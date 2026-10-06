"""Runners for the small synthetic scaffolds (classification, voice location, translation) and the placeholder sets.

HONESTY: results here prove the HARNESS and the deterministic code (the location resolver, the safety overrides). They are not model quality:
the simulator and these cases share an author. Every report says so.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import GatewayConfig
from ..features.handlers import PollWording, resolve_location
from ..features.spec import LocationDirectory, LocationRef
from ..guardrails import default_commands
from ..paths import evals_root
from ..pipeline import Gateway, GatewayRequest
from ..types import Caller
from . import banner
from .access_injection import OWN as SOC
from .access_injection import PERSON


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (evals_root() / name / "cases.json").read_text(encoding="utf-8")
    )
    return data


def macro_f1(pairs: list[tuple[str, str]]) -> float:
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    f1s = []
    for lab in labels:
        tp = sum(1 for a, b in pairs if a == lab and b == lab)
        fp = sum(1 for a, b in pairs if a != lab and b == lab)
        fn = sum(1 for a, b in pairs if a == lab and b != lab)
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(2 * p * r / (p + r) if p + r else 0.0)
    return sum(f1s) / len(f1s) if f1s else 0.0


@dataclass
class SetReport:
    name: str
    lines: list[str]
    gate_met: bool | None  # None = not measurable

    def render(self) -> str:
        return "\n".join([f"{self.name.upper()}", banner(), *self.lines])


def _gateway() -> Gateway:
    return Gateway(GatewayConfig(environment="test"))


def classification() -> SetReport:
    data = _load("classification")
    gw = _gateway()
    caller = Caller(SOC, PERSON, "secretary", society_wide=True)
    from .access_injection import _doc  # reuse doc builder

    by_lang: dict[str, list[tuple[str, str]]] = defaultdict(list)
    emergency_fn = 0
    emergencies = 0
    for c in data["cases"]:
        # the triage handler takes tickets from a source; build one ticket per case
        doc = _doc(
            c["id"],
            {
                "ref": c["id"],
                "society": "own",
                "unit": None,
                "roles": None,
                "status": "published",
                "kind": "ticket",
                "text": c["text"],
                "meta": {},
            },
        )
        res = gw.run(
            GatewayRequest("AI-F01", caller, {"ticket_ids": [doc.source_id]}, sources=[doc])
        )
        got = (
            res.proposal.payload["results"][0]
            if res.proposal
            else {"category": "none", "priority": "none"}
        )
        by_lang[c["lang"]].append((c["category"], got["category"]))
        if c["emergency"]:
            emergencies += 1
            emergency_fn += int(got["priority"] != "emergency")
    lines = [
        f"status: {data['status']}",
        f"annotator agreement: {data['annotator_agreement']['status']}",
    ]
    for lang, pairs in sorted(by_lang.items()):
        f1 = macro_f1(pairs)
        lines.append(
            f"  {lang}: macro-F1 {f1:.3f} over {len(pairs)} cases  (release gate >= 0.90: {'met' if f1 >= 0.90 else 'NOT MET'} by the SIMULATOR's keyword rules; "
            "informational only: the rules and the cases share an author, so this says nothing about a real model)"
        )
    lines.append(
        f"emergency false negatives after the deterministic safety override: {emergency_fn}/{emergencies} (this IS a code property and is gated)"
    )
    return SetReport("classification (AI-F01)", lines, emergency_fn == 0)


def voice() -> SetReport:
    data = _load("voice")
    directory = LocationDirectory(
        units=[
            LocationRef(uuid.uuid5(SOC, f"{b}-{n}"), b, f"{b}-{n}", 1) for b, n in data["directory"]
        ]
    )
    own = set(data["authorised_units_of_caller"])
    authorised = LocationDirectory(units=[u for u in directory.units if u.label in own])
    gw = _gateway()
    caller = Caller(
        SOC, PERSON, "owner_occ", unit_ids=frozenset(u.unit_id for u in authorised.units)
    )
    critical = 0
    raw_ok = 0
    n = 0
    by_lang: Counter[str] = Counter()
    lines = [f"status: {data['status']}"]
    for c in data["cases"]:
        n += 1
        res = gw.run(
            GatewayRequest("AI-R02", caller, {"transcript": c["transcript"]}, locations=authorised)
        )
        p = res.proposal.payload if res.proposal else {}
        exp = c["expected"]
        got_unit = p.get("unit_label")
        if exp == "UNRESOLVED":
            ok = (
                p.get("location_status")
                in {"unresolved", "not_in_authorised_units", "ambiguous", None}
                and got_unit is None
                and p.get("common_area") is None
            )
            wrong = got_unit is not None
        elif exp.startswith("common:"):
            ok = p.get("common_area") == exp.split(":")[1]
            wrong = got_unit is not None
        else:
            ok = got_unit == exp
            wrong = got_unit is not None and got_unit != exp
        raw_ok += int(ok)
        critical += int(wrong)
        by_lang[c["lang"]] += int(not ok)
    lines += [
        f"cases: {n}   location correct: {raw_ok}/{n}   CRITICAL errors (wrong block/flat resolved): {critical}",
        "gate: >=95% correct critical fields after confirmation; wrong block or flat is critical. NO recordings, ASR never run.",
    ]
    return SetReport(
        "voice complaint location (AI-R02)", lines, critical == 0 and raw_ok / n >= 0.95
    )


def translation() -> SetReport:
    data = _load("translation")
    gw = _gateway()
    caller = Caller(SOC, PERSON, "secretary", society_wide=True)
    flagged_ok = 0
    nums_ok = 0
    for c in data["cases"]:
        res = gw.run(
            GatewayRequest(
                "AI-R07",
                caller,
                {"text": c["text"], "target_language": "en" if c["lang"] != "en" else "hi"},
            )
        )
        p = res.proposal.payload if res.proposal else {}
        flagged_ok += int(p.get("legal_or_safety_flag") == c["legal_or_safety"])
        nums_ok += int(bool(p) and p["original_text"] == c["text"])
    n = len(data["cases"])
    lines = [f"status: {data['status']}", f"legal/safety flag agrees with author label: {flagged_ok}/{n}; original text always returned: {nums_ok}/{n}",
             "meaning preservation (gate >= 95% by bilingual reviewers): NOT MEASURED"]  # fmt: skip
    return SetReport("translation (AI-R07)", lines, None)


def placeholders() -> list[SetReport]:
    out = []
    for name in ("groundedness", "ocr", "matching"):
        d = _load(name)
        out.append(
            SetReport(
                name,
                [
                    f"status: {d['status']}",
                    f"PRD minimum: {d['prd_minimum']}",
                    f"gate: {d['gate']}",
                ],
                None,
            )
        )
    return out


def _unused(_: Path, __: object) -> None:  # keep imports honest for type checkers
    PollWording()
    resolve_location(None, "unknown", LocationDirectory())
    default_commands()
