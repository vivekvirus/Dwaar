"""Untrusted-content handling: sanitising, delimiting, safe parsing and DIAGNOSTIC injection detection.

REQ: AI-SYS-03 (uploaded documents, invoices, transcripts, tickets and messages are untrusted data; safe parsing, output
validation, sandboxed conversion and size limits), SEC-10 (prompt injection), AT-25.

Important design note: ``detect_injection`` is a DIAGNOSTIC (it makes the safe log line and lets operators see attacks). No
security decision depends on it: the defence is structural (scoped retrieval, no credentials/URLs/SQL in the boundary, closed tool
and command allow-lists, schema + output validation, confirmation bound to a payload hash). A document that evades every
pattern here still cannot make the gateway disclose or execute anything.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

from .types import UntrustedSegment

_STRIP: Final = re.compile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f​‎‏‪-‮⁠-⁤⁦-⁩﻿]")
_DELIM: Final = re.compile(r"<\s*/?\s*untrusted_data", re.IGNORECASE)
_MAX_JSON_DEPTH: Final = 8
MAX_RESPONSE_BYTES: Final = 64_000

_INJECTION_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("override_instructions", re.compile(r"(ignore|disregard|forget|override)\W+(all\W+|any\W+)?(the\W+)?(previous|prior|above|earlier|system)\W+(instruction|prompt|rule|message)s?", re.I)),
    ("override_instructions_hi_mr", re.compile(r"(पिछले|पहले के|मागील|आधीच्या)\W+(सभी\W+)?(निर्देश|सूचना|आदेश)\W*(को\W+)?(अनदेखा|नज़रअंदाज़|दुर्लक्ष)")),
    ("reveal_prompt", re.compile(r"(reveal|print|show|repeat|leak|output)\W+(your\W+|the\W+)?(system\W+)?(prompt|instructions|secret|api\W*key|credential)", re.I)),
    ("role_switch", re.compile(r"(you are now|act as|pretend to be|new role|developer mode|jailbreak)", re.I)),
    ("exfiltrate_data", re.compile(r"(export|dump|list|send|email|forward|exfiltrate|share)\W+(all\W+|every\W+)?(the\W+)?(other\W+)?(neighbou?r|resident|tenant|owner|member|society|societies|unit|flat|phone|aadhaar|pan|account|ticket|data)", re.I)),
    ("exfiltrate_hi_mr", re.compile(r"(सभी|सब|सर्व)\W+(निवासियों|निवासी|पड़ोसियों|शेजाऱ्यांचा|रहिवाशांचा)\W+.*(भेजें|निर्यात|डेटा|नंबर|पाठवा)")),
    ("url_fetch", re.compile(r"(https?://|ftp://|www\.)", re.I)),
    ("markdown_image", re.compile(r"!\[[^\]]*\]\([^)]*\)")),
    ("sql", re.compile(r"\b(select\s+.+\s+from|drop\s+table|union\s+select|insert\s+into|delete\s+from|update\s+\w+\s+set)\b", re.I | re.S)),
    ("tool_request", re.compile(r"(call|invoke|run|execute)\W+(the\W+)?(tool|function|command|api|shell)", re.I)),
    ("encoded_payload", re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")),
    ("delimiter_spoof", re.compile(r"</?\s*(untrusted_data|system|assistant)\s*>", re.I)),
)  # fmt: skip


def sanitise(text: str, max_chars: int) -> tuple[str, list[str]]:
    """Strip control and bidi/zero-width characters (ZWJ/ZWNJ stay: Devanagari needs them), neutralise delimiter spoofing and cap
    the size. Returns the clean text and diagnostic flags (codes only)."""
    flags: list[str] = []
    clean = _STRIP.sub("", text)
    if clean != text:
        flags.append("control_or_hidden_characters_removed")
    if _DELIM.search(clean):
        clean = _DELIM.sub("‹untrusted_data", clean)
        flags.append("delimiter_spoof_neutralised")
    if len(clean) > max_chars:
        clean = clean[:max_chars]
        flags.append("truncated_to_size_limit")
    return clean, flags


def detect_injection(text: str) -> list[str]:
    """Diagnostic codes for injection-looking content (never the content itself)."""
    return [code for code, pattern in _INJECTION_PATTERNS if pattern.search(text)]


def segment(
    segment_id: str, kind: str, text: str, max_chars: int
) -> tuple[UntrustedSegment, list[str]]:
    clean, flags = sanitise(text, max_chars)
    flags += [f"injection_pattern:{c}" for c in detect_injection(clean)]
    return UntrustedSegment(segment_id, kind, clean), flags


def render_untrusted(
    segments: list[UntrustedSegment] | tuple[UntrustedSegment, ...], nonce: str
) -> str:
    """The single, delimited rendering of data blocks used by every real provider adapter."""
    parts = []
    for s in segments:
        parts.append(
            f'<untrusted_data id="{s.segment_id}" kind="{s.kind}" request="{nonce}">\n{s.text}\n</untrusted_data>'
        )
    return "\n".join(parts)


class UnsafeJson(Exception):
    pass


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise UnsafeJson("duplicate_key")
        out[k] = v
    return out


def _depth(value: Any, level: int = 0) -> int:
    if level > _MAX_JSON_DEPTH:
        return level
    if isinstance(value, dict):
        return max([_depth(v, level + 1) for v in value.values()] or [level + 1])
    if isinstance(value, list):
        return max([_depth(v, level + 1) for v in value] or [level + 1])
    return level


def safe_parse_json(raw: str) -> dict[str, Any]:
    """Model output -> dict, or UnsafeJson. Size-limited, no NaN/Infinity, no duplicate keys, bounded depth, objects only."""
    if len(raw.encode("utf-8", "replace")) > MAX_RESPONSE_BYTES:
        raise UnsafeJson("response_too_large")
    text = raw.strip()
    if text.startswith("```"):  # tolerate ONE fence; anything else around the object is a failure
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)

    def bad_constant(name: str) -> Any:
        raise UnsafeJson("non_finite_number")

    try:
        value = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=bad_constant)
    except UnsafeJson:
        raise
    except (ValueError, RecursionError):
        raise UnsafeJson("not_json") from None
    if not isinstance(value, dict):
        raise UnsafeJson("not_an_object")
    if _depth(value) > _MAX_JSON_DEPTH:
        raise UnsafeJson("too_deep")
    return value


#: content types a sandboxed conversion step accepts today. PDFs/Office files need a sandboxed converter that does not exist yet
#: (blocked: not built), so they are REFUSED rather than parsed in-process.
ALLOWED_UPLOAD_TYPES: Final = frozenset({"text/plain"})


def extract_text_safely(data: bytes, content_type: str, max_bytes: int = 200_000) -> str:
    if content_type.split(";")[0].strip().lower() not in ALLOWED_UPLOAD_TYPES:
        raise UnsafeJson("unsupported_upload_type")
    if len(data) > max_bytes:
        raise UnsafeJson("upload_too_large")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise UnsafeJson("not_utf8") from None
