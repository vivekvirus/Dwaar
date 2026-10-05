"""Structured JSON logging with a scrubber (OBS-01).

REQ: OBS-01 (structured logs with correlation ID, society token, route, latency, status,
safe error code; never OTPs, phone numbers, pass secrets, images or bank credentials),
INV-05/PII rules.

Two layers, both fail-closed:
* `ScrubFilter` rewrites the record (message, args, extras, exception text) before any
  handler sees it. Sensitive field NAMES are redacted wholesale; free TEXT is pattern-scrubbed
  (OTPs, bearer/JWT tokens, secret=value pairs, Aadhaar-like 12-digit numbers, Indian
  mobile numbers, 9-18 digit bank-account-like runs).
* `JsonFormatter` scrubs its final payload again, so a handler without the filter is safe.
Over-redaction (for example a bare 13-digit epoch in free text) is accepted by design.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import sys
import traceback
import uuid
from collections.abc import Iterator, Mapping
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import IO, Any, Final

REDACTED: Final = "[REDACTED]"

correlation_id_var: ContextVar[str | None] = ContextVar("dwaar_correlation_id", default=None)
society_token_var: ContextVar[str | None] = ContextVar("dwaar_society_token", default=None)

_SENSITIVE_TOKENS: Final = frozenset(
    {
        "authorization", "authorisation", "secret", "secrets", "token", "tokens",
        "password", "passwd", "pwd", "otp", "cookie", "cookies", "credential",
        "credentials", "passcode", "aadhaar", "aadhar", "phone", "mobile", "msisdn",
        "apikey", "privatekey", "jwt", "bearer", "cvv",
    }
)  # fmt: skip
_SENSITIVE_COMPOUNDS: Final = ("apikey", "privatekey", "accountnumber", "bankaccount", "passsecret")
_SENSITIVE_EXACT: Final = frozenset({"pin", "account_no", "acct_no", "iban", "ifsc_account"})
_ALLOWED_KEYS: Final = frozenset({"society_token", "correlation_id", "request_id", "token_type"})
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^a-z0-9]+")


def is_sensitive_key(key: str) -> bool:
    """True if a mapping key / log extra name denotes a secret or personal identifier."""
    lowered = key.lower()
    if lowered in _ALLOWED_KEYS:
        return False
    if lowered in _SENSITIVE_EXACT:
        return True
    tokens = {t for t in _SPLIT.split(_CAMEL.sub("_", key).lower()) if t}
    if tokens & _SENSITIVE_TOKENS:
        return True
    squashed = "".join(_SPLIT.split(lowered))
    return any(c in squashed for c in _SENSITIVE_COMPOUNDS)


_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_KEYVALUE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|authorisation|"
    r"otp|passcode|pass[_-]?secret)\b(?P<sep>[\"']?\s*[:=]\s*[\"']?)(?!\[REDACTED\])(?P<val>[^\s,;&\"'}\]]+)"
)
_OTP_AFTER = re.compile(
    r"(?i)\b(otp|one[- ]time (?:password|code)|verification code)\b[^0-9\n]{0,20}\d{4,8}\b"
)
_OTP_BEFORE = re.compile(
    r"(?i)\b\d{4,8}\b(?=\s+is\s+(?:your|the)\s+(?:otp|one[- ]time|verification|login))"
)
_AADHAAR = re.compile(r"(?<![\w-])\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![\w-]|\.\d)")
_PHONE = re.compile(r"(?<![\w-])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?![\w-]|\.\d)")
_LONG_DIGITS = re.compile(r"(?<![\w-])\d{9,18}(?![\w-]|\.\d)")


def scrub_text(text: str) -> str:
    """Remove secrets and personal identifiers from free text."""
    text = _JWT.sub(REDACTED, text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _KEYVALUE.sub(lambda m: f"{m.group(1)}{m.group('sep')}{REDACTED}", text)
    text = _OTP_AFTER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _OTP_BEFORE.sub(REDACTED, text)
    text = _AADHAAR.sub(REDACTED, text)
    text = _PHONE.sub(REDACTED, text)
    return _LONG_DIGITS.sub(REDACTED, text)


def scrub_value(value: Any, key: str | None = None) -> Any:
    """Recursively scrub a JSON-like value; `key` is the field name it was found under."""
    if key is not None and is_sensitive_key(key) and value is not None:
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return f"[BYTES len={len(value)}]"
    if isinstance(value, Mapping):
        return {str(k): scrub_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [scrub_value(v) for v in value]
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return scrub_text(str(value))


_STANDARD_ATTRS: Final = frozenset(
    logging.LogRecord("x", 0, "x", 0, "", (), None).__dict__.keys()
) | {"message", "asctime", "taskName"}


class ContextFilter(logging.Filter):
    """Adds correlation_id and society_token from context variables when absent."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = correlation_id_var.get()
        if not hasattr(record, "society_token"):
            record.society_token = society_token_var.get()
        return True


class ScrubFilter(logging.Filter):
    """Scrubs message, args, extras and exception text in place. Never drops records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = scrub_text(message)
        record.args = ()
        for name in list(record.__dict__):
            if name in _STANDARD_ATTRS or name in ("correlation_id", "society_token"):
                continue
            record.__dict__[name] = scrub_value(record.__dict__[name], name)
        if record.exc_info and record.exc_info[0] is not None:
            record.exc_type = record.exc_info[0].__name__
            record.exc_text = scrub_text(
                "".join(traceback.format_exception(*record.exc_info)).rstrip()
            )
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = scrub_text(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub_text(record.stack_info)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, service, msg, correlation_id, society_token + extras."""

    def __init__(self, service: str = "dwaar") -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        body: dict[str, Any] = {"msg": message}
        for name, value in record.__dict__.items():
            if name in _STANDARD_ATTRS or name in ("correlation_id", "society_token"):
                continue
            body[name] = value
        if record.exc_text:
            body["exc"] = record.exc_text
        elif record.exc_info and record.exc_info[0] is not None:
            body["exc_type"] = record.exc_info[0].__name__
            body["exc"] = "".join(traceback.format_exception(*record.exc_info)).rstrip()
        if record.stack_info:
            body["stack"] = record.stack_info
        body = scrub_value(body)  # defence in depth if the handler lacks ScrubFilter
        out: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "service": self.service,
            "correlation_id": getattr(record, "correlation_id", None) or correlation_id_var.get(),
            "society_token": getattr(record, "society_token", None) or society_token_var.get(),
        }
        out.update(body)
        return json.dumps(out, ensure_ascii=False, default=str)


def society_log_token(society_id: uuid.UUID | str) -> str:
    """Stable, non-reversible short token for a society, safe for logs and metrics labels."""
    digest = hashlib.sha256(str(society_id).encode("utf-8")).hexdigest()
    return f"soc_{digest[:12]}"


@contextlib.contextmanager
def bind_log_context(
    correlation_id: str | uuid.UUID | None = None,
    society_id: uuid.UUID | str | None = None,
    society_token: str | None = None,
) -> Iterator[None]:
    """Bind correlation id and society token for the current context (request / job)."""
    tokens = []
    if correlation_id is not None:
        tokens.append((correlation_id_var, correlation_id_var.set(str(correlation_id))))
    token = society_token or (society_log_token(society_id) if society_id is not None else None)
    if token is not None:
        tokens.append((society_token_var, society_token_var.set(token)))
    try:
        yield
    finally:
        for var, reset_token in reversed(tokens):
            var.reset(reset_token)


def build_handler(
    service: str = "dwaar", stream: IO[str] | None = None, json_output: bool = True
) -> logging.Handler:
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.addFilter(ContextFilter())
    handler.addFilter(ScrubFilter())
    if json_output:
        handler.setFormatter(JsonFormatter(service))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler._dwaar = True  # type: ignore[attr-defined]  # marker for idempotent configure
    return handler


def configure_logging(
    service: str = "dwaar",
    level: int | str = "INFO",
    stream: IO[str] | None = None,
    json_output: bool = True,
) -> logging.Handler:
    """Install the scrubbing JSON handler on the root logger (idempotent)."""
    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_dwaar", False):
            root.removeHandler(existing)
    handler = build_handler(service, stream, json_output)
    root.addHandler(handler)
    root.setLevel(level)
    return handler
