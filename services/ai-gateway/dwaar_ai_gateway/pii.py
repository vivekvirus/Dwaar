"""PII redaction middleware: tokenise Indian personal identifiers BEFORE any model call; re-identify only on authorised return.

REQ: AI-SYS-05 (phones, Aadhaar, PAN, bank numbers tokenised before model calls; re-identified only on return to authorised
users; PII golden set recall >= 99% is a RELEASE GATE, not an achieved result), PRIV-14, G6 (minimise and redact before any
model call), SEC-07.

What is detected (ordered by priority; overlaps are resolved by priority, then length):
email, GSTIN, PAN, IFSC, vehicle plate, bank account number (context-gated), mobile phone, Aadhaar. Digits are normalised first (Devanagari and
full-width digits map 1:1 to ASCII so offsets are preserved), then matched with deliberately NARROW shapes (to keep false positives
low): state-code-checked plates, 4-4-4 or contiguous Aadhaar that does not start 0/1 and is not preceded by UTR/ref/invoice words,
mobile numbers 6-9 + nine digits with optional +91/91/0 prefix and single separators, bank account numbers (9-18 digits) ONLY when an
account keyword (A/c, account, खाता ...) or an IFSC is nearby.

Known limits (reported, not hidden): a bare account number with no keyword and no IFSC is NOT detected; free-text names and
addresses are not detected by this module (names are minimised by never sending them: see policy.minimise); a plausible
12-digit number with no UTR/ref context is treated as an Aadhaar (false positive, by design: leaking is worse).

Tokens are scoped to ONE request: ``⟦PHONE:<nonce>:<n>⟧``. The mapping lives only in memory in the TokenVault, is never logged, and
a token from another request (or a forged one) is never re-identified.
"""

from __future__ import annotations

import re
import secrets
from collections import Counter
from dataclasses import dataclass, field
from typing import Final

_DIGIT_MAP: Final = {ord(c): str(i) for i, c in enumerate("०१२३४५६७८९")}
_DIGIT_MAP.update({ord(c): str(i) for i, c in enumerate("０１２３４５６７８９")})
_DIGIT_MAP.update(
    {ord(c): str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")}
)  # Arabic-Indic, seen in pasted text

PII_TYPES: Final = ("email", "gstin", "pan", "ifsc", "plate", "account", "phone", "aadhaar")
_PRIORITY: Final = {t: i for i, t in enumerate(PII_TYPES)}

_STATE_CODES: Final = [
    "AN",
    "AP",
    "AR",
    "AS",
    "BR",
    "CH",
    "CG",
    "DD",
    "DL",
    "DN",
    "GA",
    "GJ",
    "HP",
    "HR",
    "JH",
    "JK",
    "KA",
    "KL",
    "LA",
    "LD",
    "MH",
    "ML",
    "MN",
    "MP",
    "MZ",
    "NL",
    "OD",
    "OR",
    "PB",
    "PY",
    "RJ",
    "SK",
    "TN",
    "TR",
    "TS",
    "UK",
    "UP",
    "WB",
]
_PLATE_STATE: Final = "(?:" + "|".join(_STATE_CODES) + ")"

_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    (
        "email",
        re.compile(
            r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
        ),
    ),
    (
        "gstin",
        re.compile(
            r"(?<![A-Za-z0-9])[0-3]\d[A-Za-z]{5}\d{4}[A-Za-z][1-9A-Za-z][Zz][0-9A-Za-z](?![A-Za-z0-9])"
        ),
    ),
    (
        "pan",
        re.compile(
            r"(?<![A-Za-z0-9])(?:[A-Za-z]{5}\d{4}[A-Za-z]"
            r"|[A-Za-z]{5}[ -]\d{4}[ -][A-Za-z])(?![A-Za-z0-9])"
        ),
    ),
    ("ifsc", re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{4}0[A-Za-z0-9]{6}(?![A-Za-z0-9])")),
    (
        "plate",
        re.compile(
            rf"(?<![A-Za-z0-9])(?:(?i:{_PLATE_STATE})[ -]?\d{{1,2}}[ -]?[A-Za-z]{{1,3}}[ -]?\d{{4}}"
            r"|\d{2}[ -]?BH[ -]?\d{4}[ -]?[A-Za-z]{2})(?![A-Za-z0-9])"
        ),
    ),
    ("aadhaar", re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])")),
    (
        "phone",
        re.compile(
            r"(?<![\d])(?:(?:\+\s?91|\(\+91\)|0091|91)[\s-]*)?0?[6-9](?:[\s.-]?\d){9}(?!\d)"
        ),
    ),
]
_ACCOUNT: Final = re.compile(
    r"(?<![\d-])\d{9,18}(?![\d-])|(?<![\d-])\d{4}[ -]\d{4}[ -]\d{1,10}(?![\d-])"
)
_ACCOUNT_CONTEXT: Final = re.compile(
    r"(a/c|a\.c\.?|acct|account|acc\.? ?no|savings|current a|खाता|खाते|खात्याचा|खात्यात|बैंक|बँक|bank)",
    re.IGNORECASE,
)
_NOT_ID_CONTEXT: Final = re.compile(
    r"(utr|ref(?:erence)?|txn|transaction|invoice|inv|order|bill|ticket|tkt|rrn|receipt)\W{0,4}$",
    re.IGNORECASE,
)
_ACCOUNT_WINDOW: Final = 48
# object identifiers (UUIDs) are never personal data, and hyphenated digit runs inside them look like phone numbers
_UUID: Final = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_TOKEN: Final = re.compile(r"⟦([A-Z]+):([0-9a-f]{6}):(\d+)⟧")


def normalise_digits(text: str) -> str:
    """Devanagari / full-width / Arabic-Indic digits to ASCII, one character for one character (offsets are preserved)."""
    return text.translate(_DIGIT_MAP)


@dataclass(frozen=True)
class Detection:
    type: str
    start: int
    end: int


@dataclass
class TokenVault:
    """Per-request token table. In memory only; never logged, never persisted."""

    nonce: str = field(default_factory=lambda: secrets.token_hex(3))
    _by_value: dict[tuple[str, str], str] = field(default_factory=dict)
    _by_token: dict[str, str] = field(default_factory=dict)
    _counts: Counter[str] = field(default_factory=Counter)

    def token_for(self, kind: str, value: str) -> str:
        key = (kind, _canonical(kind, value))
        token = self._by_value.get(key)
        if token is None:
            n = len(self._by_value) + 1
            token = f"⟦{kind.upper()}:{self.nonce}:{n}⟧"
            self._by_value[key] = token
            self._by_token[token] = value
        return token

    def values(self) -> frozenset[str]:
        """Canonical forms of every value this request sent (what a model output may legitimately contain)."""
        return frozenset(k[1] for k in self._by_value)

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def count(self, kind: str) -> None:
        self._counts[kind] += 1

    def reidentify(self, text: str, *, authorised: bool) -> str:
        """Replace this request's tokens by the original values, only when ``authorised``. Foreign or forged tokens stay."""
        if not authorised:
            return text
        return _TOKEN.sub(lambda m: self._by_token.get(m.group(0), m.group(0)), text)

    def has_token(self, token: str) -> bool:
        return token in self._by_token


def _canonical(kind: str, value: str) -> str:
    v = normalise_digits(value)
    if kind in {"phone", "aadhaar", "account"}:
        digits = re.sub(r"\D", "", v)
        return digits[-10:] if kind == "phone" else digits
    return re.sub(r"[\s-]", "", v).upper()


@dataclass
class RedactionResult:
    text: str
    detections: list[Detection]

    @property
    def counts(self) -> dict[str, int]:
        return dict(Counter(d.type for d in self.detections))


def detect(text: str) -> list[Detection]:
    """All identifier spans in ``text`` (offsets refer to the ORIGINAL text), overlaps resolved by priority then length."""
    norm = normalise_digits(text)
    found: list[Detection] = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(norm):
            if kind == "aadhaar" and _NOT_ID_CONTEXT.search(
                norm[max(0, m.start() - 16) : m.start()]
            ):
                continue
            found.append(Detection(kind, m.start(), m.end()))
    has_ifsc = [d for d in found if d.type == "ifsc"]
    for m in _ACCOUNT.finditer(norm):
        before = norm[max(0, m.start() - _ACCOUNT_WINDOW) : m.start()]
        near_ifsc = any(
            abs(d.start - m.end()) <= 60 or abs(m.start() - d.end) <= 60 for d in has_ifsc
        )
        if _NOT_ID_CONTEXT.search(norm[max(0, m.start() - 16) : m.start()]):
            continue
        if _ACCOUNT_CONTEXT.search(before) or near_ifsc:
            found.append(Detection("account", m.start(), m.end()))
    ids = [(m.start(), m.end()) for m in _UUID.finditer(norm)]
    found = [d for d in found if not any(a <= d.start and d.end <= b for a, b in ids)]
    return _resolve(found)


def _resolve(found: list[Detection]) -> list[Detection]:
    ordered = sorted(found, key=lambda d: (_PRIORITY[d.type], -(d.end - d.start), d.start))
    kept: list[Detection] = []
    for d in ordered:
        if not any(d.start < k.end and k.start < d.end for k in kept):
            kept.append(d)
    return sorted(kept, key=lambda d: d.start)


def redact(text: str, vault: TokenVault) -> RedactionResult:
    """Replace every detected identifier by a request-scoped token."""
    detections = detect(text)
    out: list[str] = []
    pos = 0
    for d in detections:
        out.append(text[pos : d.start])
        out.append(vault.token_for(d.type, text[d.start : d.end]))
        vault.count(d.type)
        pos = d.end
    out.append(text[pos:])
    return RedactionResult("".join(out), detections)


def leaked_values(text: str, allowed: frozenset[str]) -> list[str]:
    """Identifier TYPES present in ``text`` whose canonical value this request never sent: a model must not invent or
    export personal data it was not given (output validation, AI-SYS-03)."""
    leaks: list[str] = []
    for d in detect(text):
        if _canonical(d.type, text[d.start : d.end]) not in allowed:
            leaks.append(d.type)
    return leaks
