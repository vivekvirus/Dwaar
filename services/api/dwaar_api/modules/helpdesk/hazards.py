"""Deterministic hazard rules (OPS-09, AI-F01 emergency routing, guardrail G12).

REQ: OPS-09 (unsafe lift, electrical, gas or fire observations IMMEDIATELY show the site emergency procedure and the
accountable contacts; work beyond staff competence routes to a qualified contractor; NO repair instructions for hazardous
live equipment), G12 (safety-critical domains limited to approved manuals and SOPs; no diagnosis), INV-06.

Rules are plain data and plain code (no model). Matching is on whole words / phrases in the lower-cased title and description;
the Hindi and Marathi phrases are MACHINE-DRAFTED and need native review before a pilot (``review_status.json``). A match makes
the ticket an emergency; it never produces repair advice. ``RULESET_VERSION`` is stored with the match so an audit can say
which rules fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

RULESET_VERSION: Final = "pilot-2026-10"
HAZARD_KINDS: Final = ("lift", "electrical", "gas", "fire")
#: categories that ARE a hazard domain. gas and fire_safety always show the procedure; lift and electrical need an unsafe
#: observation (a flickering corridor bulb is not an emergency).
CATEGORY_HAZARD: Final = {
    "lift": "lift",
    "electrical": "electrical",
    "gas": "gas",
    "fire_safety": "fire",
}
ALWAYS_PROCEDURE: Final = frozenset({"gas", "fire_safety"})

_KEYWORDS: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    (
        "fire",
        "kw-fire",
        (
            "on fire",
            "caught fire",
            "fire broke",
            "flames",
            "smoke",
            "smoking",
            "burning smell",
            "burnt smell",
            "आग",
            "धुआं",
            "धुआँ",
            "जलने की बदबू",
            "धूर",
            "जळण्याचा वास",
            "aag lagi",
        ),
    ),
    (
        "gas",
        "kw-gas",
        (
            "gas leak",
            "gas leaking",
            "smell of gas",
            "smells of gas",
            "gas smell",
            "lpg leak",
            "png leak",
            "cylinder leak",
            "गैस लीक",
            "गैस की बदबू",
            "गैस गळती",
            "गॅस गळती",
        ),
    ),
    (
        "electrical",
        "kw-electrical",
        (
            "sparking",
            "sparks",
            "short circuit",
            "short-circuit",
            "electric shock",
            "electrocuted",
            "live wire",
            "exposed wire",
            "exposed wires",
            "current in the wall",
            "earth leakage",
            "बिजली का झटका",
            "करंट लगा",
            "शॉर्ट सर्किट",
            "विजेचा धक्का",
            "शॉर्टसर्किट",
        ),
    ),
    (
        "lift",
        "kw-lift",
        (
            "stuck in lift",
            "stuck in the lift",
            "trapped in lift",
            "trapped in the lift",
            "lift stuck between",
            "lift door open while moving",
            "lift free fall",
            "lift fell",
            "lift jerk",
            "people trapped",
            "लिफ्ट में फंसे",
            "लिफ्ट में फंस गया",
            "लिफ्ट में फँसे",
            "लिफ्टमध्ये अडकले",
            "लिफ्टमध्ये अडकलो",
        ),
    ),
)
_COMPILED: Final = tuple(
    (
        kind,
        rule,
        tuple(
            re.compile(
                r"(?<![\w\u0900-\u097F])" + re.escape(p) + r"(?![\w\u0900-\u097F])", re.IGNORECASE
            )
            for p in phrases
        ),
    )
    for kind, rule, phrases in _KEYWORDS
)


@dataclass(frozen=True)
class HazardMatch:
    kind: str  # lift | electrical | gas | fire
    rule: str  # which rule fired (stored on the ticket)
    emergency: bool  # forces priority 'emergency'
    minimum_priority: str = "emergency"


def detect(category: str, text: str, *, unsafe_declared: bool) -> HazardMatch | None:
    """The hazard this report amounts to, or None. Keyword matches win over the category; they never depend on a model."""
    haystack = text.lower()
    category_kind = CATEGORY_HAZARD.get(category)
    for found, rule, patterns in _COMPILED:
        if any(p.search(haystack) for p in patterns):
            # the reporter's own domain wins: a lift that is sparking is a LIFT emergency (the lift procedure and contractor)
            return HazardMatch(category_kind or found, f"{rule}@{RULESET_VERSION}", True)
    kind = category_kind
    if kind is None:
        return None
    if unsafe_declared:
        return HazardMatch(kind, f"declared_unsafe:{category}@{RULESET_VERSION}", True)
    if category in ALWAYS_PROCEDURE:
        return HazardMatch(kind, f"category:{category}@{RULESET_VERSION}", False, "urgent")
    return None
