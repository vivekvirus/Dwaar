"""Output validation: nothing a model returns is trusted (PRD 10.1 'validated proposal'; AI-SYS-03; AT-25).

Checks, in order, all deterministic:
1. safe JSON parse (size, depth, no duplicate keys, no NaN)           -> ``not_json`` ...
2. JSON-schema validation (additionalProperties false)                -> ``schema_invalid``
3. tool allow-list: ANY tool call outside the feature's list rejects  -> ``tool_not_allowed``
4. active-content and URL rules (no HTML/markdown images, no link the input did not contain, no data: / javascript:)
5. PII: no raw identifier the request did not send, no foreign or forged token          -> ``pii_not_in_input`` / ``foreign_token``
6. echo of excluded (unauthorised) documents, by shingle fingerprint  -> ``excluded_content_echo``
7. system-prompt canary                                               -> ``system_prompt_leak``
8. feature-specific checks (ids cited by the model must be authorised ids)

A rejection fails CLOSED: the user gets the ordinary form/search path and a safe diagnostic (codes only) is logged.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from jsonschema import Draft202012Validator

from . import pii
from .injection import UnsafeJson, safe_parse_json
from .policy import shingles
from .types import ProviderResponse, ToolCall

_URL: Final = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"')\]]+|\bwww\.[^\s<>\"')\]]+")
_ACTIVE: Final = re.compile(
    r"(?i)(!\[[^\]]*\]\([^)]*\)|<\s*(img|script|iframe|object|embed|link|style|svg)\b|javascript:|data:[a-z/+-]+;base64|\bon\w+\s*=)"
)


class OutputRejected(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail  # never contains model text


@dataclass
class ValidationContext:
    schema: Mapping[str, Any]
    allowed_tools: tuple[str, ...]
    vault_values: frozenset[str]
    vault_tokens: Callable[[str], bool]
    input_texts: Sequence[str]
    excluded_fingerprints: frozenset[str]
    canary: str
    hosts_allowed: tuple[str, ...] = ()
    feature_checks: list[Callable[[dict[str, Any]], None]] = field(default_factory=list)


def _leaves(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield str(k)
            yield from _leaves(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _leaves(v)


def validate_output(response: ProviderResponse, ctx: ValidationContext) -> dict[str, Any]:
    try:
        data = safe_parse_json(response.raw_text)
    except UnsafeJson as exc:
        raise OutputRejected("unsafe_output", str(exc)) from None

    errors = sorted(
        Draft202012Validator(dict(ctx.schema)).iter_errors(data), key=lambda e: list(e.path)
    )
    if errors:
        raise OutputRejected(
            "schema_invalid", ",".join(sorted({e.validator or "?" for e in errors}))[:120]
        )

    bad_tools = [c.name for c in response.tool_calls if c.name not in ctx.allowed_tools]
    if bad_tools:
        raise OutputRejected("tool_not_allowed", f"{len(bad_tools)} call(s)")

    input_blob = "\n".join(ctx.input_texts)
    out_fp: set[str] = set()
    for text in _leaves(data):
        if ctx.canary and ctx.canary in text:
            raise OutputRejected("system_prompt_leak")
        if _ACTIVE.search(text):
            raise OutputRejected("active_content")
        for url in _URL.findall(text):
            if url in input_blob or any(h and h in url for h in ctx.hosts_allowed):
                continue
            raise OutputRejected("url_not_in_input")
        for m in pii._TOKEN.finditer(text):
            if not ctx.vault_tokens(m.group(0)):
                raise OutputRejected("foreign_token")
        leaks = pii.leaked_values(pii._TOKEN.sub(" ", text), ctx.vault_values)
        if leaks:
            raise OutputRejected("pii_not_in_input", ",".join(sorted(set(leaks))))
        out_fp |= shingles(text)
    if ctx.excluded_fingerprints and out_fp & ctx.excluded_fingerprints:
        raise OutputRejected("excluded_content_echo")
    for check in ctx.feature_checks:
        check(data)
    return data


def tool_names(calls: Sequence[ToolCall]) -> list[str]:
    return [c.name for c in calls]
