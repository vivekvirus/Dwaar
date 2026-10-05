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
import unicodedata
import uuid
from collections.abc import Iterator, Mapping
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import IO, Any, Final

from dwaar_common.keynames import ALLOWED_KEYS, is_quantity_key
from dwaar_common.keynames import is_sensitive_key as is_sensitive_key  # re-exported

REDACTED: Final = "[REDACTED]"

correlation_id_var: ContextVar[str | None] = ContextVar("dwaar_correlation_id", default=None)
society_token_var: ContextVar[str | None] = ContextVar("dwaar_society_token", default=None)

_ALLOWED_KEYS: Final = ALLOWED_KEYS
_SPLIT = re.compile(r"[^a-z0-9]+")


_SEP_CLASS = r"[ \t.\-()\u2010-\u2015\u2212]"
# One of these (plus a little spacing) between digit groups also continues a run: "1234,5678,9012",
# "99999/00123", "99999_00123", non-breaking spaces. Zero-width characters are removed before matching.
_JOINER = r"[ \t]?[,/_\u00a0\u202f][ \t]{0,2}"
_ZERO_WIDTH = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic|digest)\s+[A-Za-z0-9._~+/=-]+")
# Whole-line header values: scheme word AND credential (Token/ApiKey/Bearer/Basic ...) or cookie jar.
_HEADER_LINE = re.compile(
    r"(?i)(?<![\w-])(?P<key>proxy-authori[sz]ation|authori[sz]ation|set-cookie|cookie)"
    r"(?P<sep>[\"']?[ \t]*(?:[:=]|%3[AD])[ \t]*[\"']?)(?![ \t]*\[REDACTED\])[^\r\n]+"
)
# key<sep>value pairs anywhere in free text (query strings, headers, JSON-ish dumps, repr of dicts).
# The key is anchored at the start of a word run and capped, so the scan stays linear.
_KV = re.compile(
    r"(?<![\w.\[\]-])(?P<key>[\w.\[\]-]{1,64})"
    r"(?P<sep>[\"']?[ \t]*(?:[:=]|%3[AD])[ \t]*[\"']?)"
)
_VALUE_END = re.compile(r"[\s,;&\"'}\]]")
_OTP_PHRASE = re.compile(
    r"(?i)(?<![a-z])(otp|one[- ]?time[- ](?:password|code|pin)|verification[ _-]?code|passcode|"
    r"security code|auth(?:entication)? code|login code|"
    r"ओटीपी|ओ\.?\s?टी\.?\s?पी\.?|वन टाइम पासवर्ड|एक बार का पासवर्ड|सत्यापन कोड|पडताळणी कोड|"
    r"एकदा वापरायचा पासवर्ड|पासकोड)(?P<gap>[^0-9\n]{0,25})"
    r"(?P<code>\d(?:[ \t]?\d){3,7})(?!\d)"
)
_OTP_BEFORE = re.compile(
    r"(?i)\b\d(?:[ \t]?\d){3,7}(?!\d)(?=\s+(?:is\s+(?:your|the)\s+(?:otp|one[- ]time|verification|login)|"
    r"to\s+(?:verify|log\s?in|sign\s?in|confirm|continue|proceed|complete|authori[sz]e|reset|activate|"
    r"access|register|login)))"
)
# ``code=482913``, ``?c=482913``, ``code: 482913``, ``your code is 482913``: a bare code parameter.
_OTP_CODE_KV = re.compile(
    r"(?i)(?<![\w])(?P<key>code|c)(?P<sep>[ \t]*(?:[:=]|%3[AD])[ \t]*|[ \t]+is[ \t]+)"
    r"(?P<value>\d{4,8})(?!\d)"
)
# scheme://user:password@host -- the password of a DSN or URL (error messages embed whole URLs).
_URL_USERINFO = re.compile(
    r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.-]*://)(?P<user>[^\s/:@]*):(?P<password>[^\s/]*)@"
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}"
    r"(?![A-Za-z0-9-])"
)
_VPA = re.compile(r"(?<![\w.%+-])[\w.-]{2,64}@[A-Za-z][A-Za-z0-9]{1,30}(?![\w.@-])")
_GSTIN = re.compile(
    r"(?<![A-Za-z0-9])\d{2}[A-Za-z]{5}\d{4}[A-Za-z][1-9A-Za-z][Zz][0-9A-Za-z](?![A-Za-z0-9])"
)
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{5}[0-9]{4}[A-Za-z](?![A-Za-z0-9])")
_IFSC = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{4}0[A-Za-z0-9]{6}(?![A-Za-z0-9])")
# Digit runs (phone, Aadhaar, bank, card numbers in any grouping) -- with a few shapes that are
# deliberately left alone so correlation ids and timestamps stay readable.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_DIGIT_RUNS = re.compile(
    r"(?P<safe>"
    r"(?<![0-9A-Za-z-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"(?![0-9A-Za-z])"
    r"|(?<![\d.])" + _OCTET + r"(?:\." + _OCTET + r"){3}(?![\d.])"
    r"|(?<![\d-])\d{4}-\d{2}-\d{2}(?![\d-])"
    r")"
    r"|(?P<run>(?<!\d)\d(?:(?:" + _SEP_CLASS + r"{0,6}|" + _JOINER + r")\d)*)"
)
# Long opaque strings. A labelled digest (``sha256:<64 hex>``: payload and request hashes) stays readable;
# any other 32+ hex run (a key, a pepper, a token) and any 40+ character base64-like run that mixes letters
# and digits is redacted. Hashes look like keys, so an unlabelled one is redacted too: over-redaction is fine.
_LONG_OPAQUE = re.compile(
    r"(?P<safe>(?<![0-9A-Za-z])(?:sha256|sha-256|sha512|sha1|md5):[0-9a-f]{32,128}(?![0-9A-Za-z]))"
    r"|(?P<hex>(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z]))"
    r"|(?P<b64>(?<![0-9A-Za-z_+-])(?=[A-Za-z0-9_+-]*[A-Za-z])(?=[A-Za-z0-9_+-]*\d)"
    r"[A-Za-z0-9_+-]{40,}={0,2}(?![A-Za-z0-9_+-]))"
)
_MIN_SECRET_DIGITS: Final = 9


def _fold_digits(text: str) -> str:
    """Drop zero-width characters, NFKC-fold and map every Unicode decimal digit to ASCII."""
    if text.isascii():
        return text
    text = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    if text.isascii():
        return text
    return "".join(
        str(unicodedata.digit(ch)) if ch.isdecimal() and not ch.isascii() else ch for ch in text
    )


def _is_secret_text_key(key: str) -> bool:
    """The same classifier as for mapping keys (``dwaar_common.keynames``): one answer in both places."""
    return is_sensitive_key(key)


def _scrub_key_values(text: str) -> str:
    out: list[str] = []
    pos = 0
    scan = 0
    while True:
        m = _KV.search(text, scan)
        if m is None:
            break
        if not _is_secret_text_key(m.group("key")):
            scan = m.end()  # the value may itself contain more pairs (url=...?token=x)
            continue
        value_start = m.end()
        if text.startswith(REDACTED[:-1], value_start):
            scan = value_start
            continue
        quote = m.group("sep")[-1:] if m.group("sep")[-1:] in "\"'" else ""
        if quote:
            close = text.find(quote, value_start)
            value_end = len(text) if close == -1 else close
        else:
            end = _VALUE_END.search(text, value_start)
            value_end = len(text) if end is None else end.start()
        if value_end == value_start:
            scan = value_start
            continue
        out.append(text[pos:value_start])
        out.append(REDACTED)
        pos = scan = value_end
    out.append(text[pos:])
    return "".join(out)


def _redact_long_opaque(match: re.Match[str]) -> str:
    return match.group(0) if match.group("safe") is not None else REDACTED


def _redact_digit_run(match: re.Match[str]) -> str:
    if match.group("safe") is not None:
        return match.group(0)
    run = match.group("run")
    digits = sum(ch.isdigit() for ch in run)
    return REDACTED if digits >= _MIN_SECRET_DIGITS else run


def scrub_text(text: str) -> str:
    """Remove secrets and personal identifiers from free text (fail closed; over-redaction is fine)."""
    text = _fold_digits(text)
    text = _URL_USERINFO.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@", text)
    text = _JWT.sub(REDACTED, text)
    text = _HEADER_LINE.sub(lambda m: f"{m.group('key')}{m.group('sep')}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _scrub_key_values(text)
    text = _OTP_PHRASE.sub(lambda m: f"{m.group(1)}{m.group('gap')}{REDACTED}", text)
    text = _OTP_BEFORE.sub(REDACTED, text)
    text = _OTP_CODE_KV.sub(lambda m: f"{m.group('key')}{m.group('sep')}{REDACTED}", text)
    text = _LONG_OPAQUE.sub(_redact_long_opaque, text)
    text = _EMAIL.sub(REDACTED, text)
    text = _VPA.sub(REDACTED, text)
    text = _GSTIN.sub(REDACTED, text)
    text = _PAN.sub(REDACTED, text)
    text = _IFSC.sub(REDACTED, text)
    return _DIGIT_RUNS.sub(_redact_digit_run, text)


def scrub_value(value: Any, key: str | None = None) -> Any:
    """Recursively scrub a JSON-like value; `key` is the field name it was found under.

    Numbers are scrubbed too: a phone or account number stored as an int under an innocuous key
    ('contact', 'ref') becomes ``[REDACTED]`` unless the key names a quantity (paise, count, ms ...).
    """
    if key is not None and is_sensitive_key(key) and value is not None:
        return REDACTED
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        if is_quantity_key(key):  # money and measured quantities are data, not identifiers
            return value
        rendered = str(value)
        return value if scrub_text(rendered) == rendered else REDACTED
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return f"[BYTES len={len(value)}]"
    if isinstance(value, Mapping):
        return {str(k): scrub_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [scrub_value(v, key) for v in value]
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


class DropRecordsFilter(logging.Filter):
    """Drops every record that passes through it."""

    def filter(self, record: logging.LogRecord) -> bool:
        return False


_SERVER_LOGGERS: Final = ("uvicorn", "uvicorn.error", "uvicorn.access")


def harden_server_loggers() -> None:
    """Route uvicorn's own loggers through the scrubbing root handler and silence its request lines (OBS-01).

    uvicorn installs plain handlers on ``uvicorn``/``uvicorn.access`` with ``propagate=False`` before the
    application is imported, so without this the raw request line (path AND query string) is written to stderr
    in clear. We detach those handlers and let ``uvicorn``/``uvicorn.error`` propagate to the root scrubbing JSON
    handler. ``uvicorn.access`` is DROPPED outright, whatever flags uvicorn was started with: its request line
    carries the raw path (invitation tokens, ids) and the client ip:port, and the one access log of this
    service is ``dwaar_api.access`` (method, route TEMPLATE, status, latency, error code; never the raw path).
    """
    for name in _SERVER_LOGGERS:
        server_logger = logging.getLogger(name)
        server_logger.handlers.clear()
        server_logger.propagate = True
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, DropRecordsFilter) for f in access.filters):
        access.addFilter(DropRecordsFilter())


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
    harden_server_loggers()
    return handler
