"""Small multilingual keyword lexicons (en / hi / mr) used by the SIMULATOR and by deterministic safety overrides.

REQ: G9 (reasons), G12, AI-R02/AI-F01 (emergency never missed because a model missed it), AI-R07 (legal/safety text is flagged for
human approval by rules, not by the model's say-so).

HONESTY: these lists are tiny, hand-written and unreviewed by native speakers. They exist to make the simulator and the
safety overrides deterministic. They are NOT a measure of, or a substitute for, model quality. hi/mr entries are machine-drafted.
"""

from __future__ import annotations

import re
from typing import Final

CATEGORY_WORDS: Final[dict[str, tuple[str, ...]]] = {
    "plumbing": (
        "leak",
        "leaking",
        "pipe",
        "tap",
        "drain",
        "sewage",
        "toilet",
        "overflow",
        "लीक",
        "पाइप",
        "नल",
        "नाली",
        "गळती",
        "पाईप",
        "नळ",
    ),
    "electrical": (
        "electric",
        "wiring",
        "spark",
        "short circuit",
        "switch",
        "power cut",
        "fuse",
        "बिजली",
        "तार",
        "स्पार्क",
        "वीज",
        "ठिणगी",
    ),
    "lift": ("lift", "elevator", "लिफ्ट"),
    "parking": ("parking", "car", "vehicle", "bike", "पार्किंग", "गाड़ी", "गाडी"),
    "security": ("security", "stranger", "theft", "gate", "intruder", "सुरक्षा", "चोरी", "गेट"),
    "housekeeping": (
        "garbage",
        "dustbin",
        "cleaning",
        "sweep",
        "dirty",
        "कचरा",
        "सफाई",
        "झाड़ू",
        "स्वच्छता",
    ),
    "noise": ("noise", "loud", "music", "party", "शोर", "आवाज", "गोंगाट"),
    "water_supply": (
        "water supply",
        "no water",
        "tanker",
        "pressure",
        "पानी नहीं",
        "पानी की सप्लाई",
        "पाणी पुरवठा",
        "पाणी नाही",
    ),
    "civil": ("crack", "wall", "paint", "ceiling", "seepage", "दरार", "दीवार", "भिंत", "तडा"),
}
EMERGENCY_WORDS: Final = (
    "fire", "smoke", "gas leak", "gas smell", "short circuit", "sparking", "sparks", "electric shock", "flood", "flooding",
    "stuck in lift", "stuck in the lift", "stuck between floors", "lift is stuck", "lift stuck", "stuck inside", "person stuck", "people stuck", "gas leakage", "burning smell", "short-circuit", "trapped", "collapse", "आग", "धुआं", "गैस", "करंट", "बाढ़", "फंस", "आग लागली", "धूर", "अडकले", "गॅस", "वीज धक्का", "शॉर्ट सर्किट", "पूर आला", "आगीचा",
)  # fmt: skip
HIGH_WORDS: Final = (
    "urgent",
    "no water",
    "no power",
    "leaking badly",
    "burst",
    "overflowing",
    "तुरंत",
    "जल्दी",
    "तातडीने",
)
TEAM_FOR: Final = {
    "plumbing": "plumbing", "electrical": "electrical", "lift": "lift_vendor", "parking": "security", "security": "security",
    "housekeeping": "housekeeping", "noise": "security", "water_supply": "plumbing", "civil": "maintenance", "other": "office",
}  # fmt: skip

#: legal or safety significant text in a notice/ticket: flagged human-review-required (AI-R07)
LEGAL_SAFETY_WORDS: Final = (
    "penalty", "fine", "legal action", "legal notice", "bye-law", "bylaw", "by-law", "statutory", "as per law", "act, ", "deadline",
    "must", "mandatory", "evacuat", "fire", "gas", "electrical", "lift will", "unsafe", "danger", "hazard", "emergency", "demolition",
    "दंड", "जुर्माना", "कानूनी", "उपनियम", "अनिवार्य", "खतरा", "आग", "गैस", "आपातकाल", "दंडात्मक", "कायदेशीर", "उपविधी", "बंधनकारक", "धोका",
)  # fmt: skip
THREAT_WORDS: Final = (
    "or else", "will be fined", "we will publish your name", "name and shame", "legal action will", "will be evicted", "disconnect your",
    "cut your water", "cut off your", "you will regret", "we will take action against you", "shame", "कार्रवाई होगी", "नाम सार्वजनिक", "कनेक्शन काट", "पानी बंद कर", "नाव जाहीर", "कारवाई होईल", "पाणी बंद करू",
)  # fmt: skip
BIAS_LEADING: Final = (
    "don't you agree", "do you agree that", "obviously", "everyone knows", "surely", "clearly the best", "wasteful", "ridiculous",
    "finally", "as usual", "only a fool", "irresponsible", "क्या आप सहमत नहीं", "ज़ाहिर है", "सब जानते हैं", "तुम्ही सहमत नाही का", "सर्वांना माहीत आहे",
)  # fmt: skip
BIAS_PRESSURE: Final = (
    "urgent",
    "last chance",
    "immediately",
    "act now",
    "before it is too late",
    "अभी",
    "आखिरी मौका",
    "तातडीने",
    "शेवटची संधी",
)
NEUTRAL_OPTIONS: Final = ("no opinion", "abstain", "other", "कोई राय नहीं", "अन्य", "मत नाही", "इतर")

_WS = re.compile(r"\s+")


def has_any(text: str, words: tuple[str, ...]) -> list[str]:
    low = _WS.sub(" ", text.lower())
    return [w for w in words if w in low]


def classify_category(text: str) -> str:
    low = text.lower()
    best, score = "other", 0
    for cat, words in CATEGORY_WORDS.items():
        s = sum(1 for w in words if w in low)
        if s > score:
            best, score = cat, s
    return best


def urgency(text: str) -> tuple[str, list[str]]:
    emerg = has_any(text, EMERGENCY_WORDS)
    if emerg:
        return "emergency", emerg
    high = has_any(text, HIGH_WORDS)
    if high:
        return "high", high
    return "normal", []
