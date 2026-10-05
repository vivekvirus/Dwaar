import io
import json
import logging
import uuid
from typing import Any

import pytest

from dwaar_common.logging import (
    REDACTED,
    JsonFormatter,
    ScrubFilter,
    bind_log_context,
    build_handler,
    configure_logging,
    is_sensitive_key,
    scrub_text,
    scrub_value,
    society_log_token,
)


class Emitter:
    """Captures one JSON log line at a time from a private logger with the Dwaar handler."""

    def __init__(self) -> None:
        self.stream = io.StringIO()
        self.logger = logging.getLogger(f"test.{uuid.uuid4().hex}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.logger.addHandler(build_handler("svc", self.stream))

    def __call__(self, message: str, *args: object, **extra: object) -> dict[str, Any]:
        self.stream.seek(0)
        self.stream.truncate()
        self.logger.info(message, *args, extra=extra)
        line: dict[str, Any] = json.loads(self.stream.getvalue())
        return line


@pytest.fixture
def emit() -> Emitter:
    return Emitter()


# ------------------------------------------------------------------ text scrubbing


@pytest.mark.parametrize(
    "text",
    [
        "call +91 99999 00123 now",
        "call +919999900123 now",
        "call 9999900123 now",
        "call 09999900123 now",
        "call 99999-00123 now",
        "aadhaar 1234 5678 9012 recorded",
        "aadhaar 123456789012 recorded",
        "aadhaar 1234-5678-9012 recorded",
        "acct 123456789012345 credited",
        "acct 000123456789 credited",
        "OTP is 482913",
        "otp: 482913",
        "your OTP 4829",
        "482913 is your OTP",
        "password=hunter2",
        'secret: "s3cr3t-value"',
        "token=abc123def",
        "api_key=sk_live_123",
        "Authorization: Bearer abcdefghij1234567890",
        "Bearer abcdefghij1234567890",
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl end",
    ],
)
def test_scrub_text_removes_sensitive_values(text: str) -> None:
    out = scrub_text(text)
    assert REDACTED in out
    for needle in ("99999", "9999900123", "5678", "123456789", "482913", "4829", "hunter2",
                   "s3cr3t", "abc123def", "sk_live", "abcdefghij", "eyJ", "000123456789"):  # fmt: skip
        assert needle not in out, (needle, out)


@pytest.mark.parametrize(
    "text",
    [
        "visit 0192f3a1-6b2d-7c00-8e4f-1a2b3c4d5e6f approved",
        "society 0192f300-0000-7000-8000-000000000001",
        "lane lane-1 latency_ms=12 status=200",
        "2026-10-05T13:41:07.250Z request done",
        "amount 12345 paise",
        "seq 18452 acked",
        "society_token=soc_abc123def456",
        "route /v1/visits/{id}",
    ],
)
def test_scrub_text_keeps_ordinary_values(text: str) -> None:
    assert scrub_text(text) == text


def test_scrub_text_idempotent() -> None:
    once = scrub_text("phone +91 99999 00123 otp 123456 password=x")
    assert scrub_text(once) == once


# ------------------------------------------------------------------ keys / values


@pytest.mark.parametrize(
    "key",
    ["authorization", "Authorization", "access_token", "refreshToken", "client_secret", "password",
     "otp", "phone", "phone_number", "mobile", "aadhaar_number", "api_key", "apiKey", "cookie",
     "set-cookie", "X-Api-Key", "pass_secret", "account_number", "pin", "private_key"],
)  # fmt: skip
def test_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key", ["society_token", "correlation_id", "request_id", "route", "latency_ms", "status",
            "error_code", "pin_code", "email_domain", "tokenizer_version"],
)  # fmt: skip
def test_non_sensitive_keys(key: str) -> None:
    # tokenizer_version / pin_code must not be collateral damage... but token-ish names are
    # judged per whole word, so only exact word matches are flagged.
    assert not is_sensitive_key(key)


def test_scrub_value_recurses_and_handles_bytes() -> None:
    value = {
        "ok": "fine",
        "Authorization": "Bearer abcdefghij1234567890",
        "nested": [{"phone": "+919999900123"}, {"note": "call 9999900123"}],
        "image": b"\x89PNG....",
        "n": 5,
        "society_token": "soc_1",
    }
    out = scrub_value(value)
    assert out["ok"] == "fine"
    assert out["Authorization"] == REDACTED
    assert out["nested"][0]["phone"] == REDACTED
    assert "9999900123" not in out["nested"][1]["note"]
    assert out["image"].startswith("[BYTES")
    assert out["n"] == 5
    assert out["society_token"] == "soc_1"
    assert scrub_value(None, "password") is None


# ------------------------------------------------------------------ handler / formatter


def test_json_line_has_required_fields(emit: Emitter) -> None:
    with bind_log_context(correlation_id="0192f3a1-6b2d-7c00-8e4f-1a2b3c4d5e6f", society_id="s-1"):
        line = emit("request done", route="/v1/visits", status=200, latency_ms=12, error_code=None)
    assert line["msg"] == "request done"
    assert line["level"] == "INFO"
    assert line["service"] == "svc"
    assert line["correlation_id"] == "0192f3a1-6b2d-7c00-8e4f-1a2b3c4d5e6f"
    assert line["society_token"] == society_log_token("s-1")
    assert line["route"] == "/v1/visits"
    assert line["status"] == 200
    assert line["latency_ms"] == 12
    assert str(line["ts"]).endswith("Z")


def test_context_is_restored_after_block(emit: Emitter) -> None:
    with bind_log_context(correlation_id="c-1", society_token="soc_x"):
        pass
    line = emit("after")
    assert line["correlation_id"] is None
    assert line["society_token"] is None


def test_message_args_and_extras_are_scrubbed(emit: Emitter) -> None:
    line = emit(
        "otp sent to %s code %s", "+919999900123", "otp 123456",
        phone="+919999900123", detail={"aadhaar": "123456789012"}, note="acct 123456789012345",
    )  # fmt: skip
    dumped = json.dumps(line)
    for needle in ("9999900123", "123456789012", "otp 123456"):
        assert needle not in dumped, needle
    assert line["phone"] == REDACTED


def test_exception_text_is_scrubbed(emit: Emitter) -> None:
    try:
        raise ValueError("bad phone 9999900123 and password=hunter2")
    except ValueError:
        emit.logger.exception("failed")
    line = json.loads(emit.stream.getvalue())
    assert line["exc_type"] == "ValueError"
    assert "9999900123" not in line["exc"]
    assert "hunter2" not in line["exc"]
    assert "ValueError" in line["exc"]


def test_formatter_scrubs_even_without_filter() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "phone 9999900123", (), None)
    record.otp = "123456"
    record.safe = "ok"
    out = json.loads(JsonFormatter("svc").format(record))
    assert "9999900123" not in out["msg"]
    assert out["otp"] == REDACTED
    assert out["safe"] == "ok"


def test_filter_never_drops_records_and_survives_bad_format_args() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "value %d", ("not-int",), None)
    assert ScrubFilter().filter(record) is True
    assert record.getMessage()


def test_configure_logging_is_idempotent() -> None:
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        stream = io.StringIO()
        configure_logging("svc", stream=stream)
        configure_logging("svc", stream=stream)
        ours = [h for h in root.handlers if getattr(h, "_dwaar", False)]
        assert len(ours) == 1
        logging.getLogger("t").warning("call 9999900123")
        assert "9999900123" not in stream.getvalue()
        assert json.loads(stream.getvalue())["service"] == "svc"
    finally:
        for handler in list(root.handlers):
            if handler not in before:
                root.removeHandler(handler)


def test_society_log_token_is_stable_and_not_reversible() -> None:
    sid = uuid.UUID("0192f300-0000-7000-8000-000000000001")
    token = society_log_token(sid)
    assert token == society_log_token(str(sid))
    assert token.startswith("soc_")
    assert str(sid)[:8] not in token
