"""PRD 12.2 error bodies, no raw database errors or personal data in responses, scrubbed structured logs (OBS-01)."""

from __future__ import annotations

import io
import json
import logging
import re
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api.core.errors import map_db_error, register_society_scoped_unique
from dwaar_common.errors import ERROR_CLASSES, STATUS_BY_CODE
from dwaar_common.logging import build_handler
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import COMMITTEE_A, SOCIETY_A, CoreHarness, core_harness

pytestmark = pytest.mark.req("OBS-01", "INV-01", "ARCH-03")

BODY_KEYS = {"request_id", "code", "message", "message_key", "details"}
#: words that only a leaked database/driver/stack error would contain
LEAK_MARKERS = (
    "psycopg", "sqlalchemy", "traceback", "select ", "insert ", "violates", "relation ", "constraint",
    "syntax error", "does not exist", "probe_things", "rate_limit_buckets", "sqlstate", "row-level security",
    "dwaar_app", "permission denied", "File \"", "DETAIL:", "LINE 1",
)  # fmt: skip


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


@pytest.fixture
def log_stream() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = build_handler("dwaar-api-test", stream)
    root = logging.getLogger()
    root.addHandler(handler)
    previous = root.level
    root.setLevel(logging.DEBUG)
    try:
        yield stream
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def assert_clean(text: str) -> None:
    lowered = text.lower()
    for marker in LEAK_MARKERS:
        assert marker.lower() not in lowered, f"leaked {marker!r}: {text[:300]}"


# ------------------------------------------------------------------------------------ the table
@pytest.mark.parametrize("cls", ERROR_CLASSES, ids=lambda c: c.code)
def test_every_prd_error_code_has_the_documented_status_and_body(
    core: CoreHarness, cls: type
) -> None:
    with core.client() as client:
        res = client.get(f"/v1/probe/errors/code/{cls.code}")  # type: ignore[attr-defined]
    body = res.json()
    assert res.status_code == STATUS_BY_CODE[cls.code]  # type: ignore[attr-defined]
    assert set(body) == BODY_KEYS
    assert body["code"] == cls.code  # type: ignore[attr-defined]
    assert body["request_id"] == res.headers["x-request-id"]
    assert uuid.UUID(body["request_id"])
    assert body["message"]
    assert isinstance(body["details"], dict)
    if cls.code in ("rate_limited", "dependency_unavailable"):  # type: ignore[attr-defined]
        assert int(res.headers["retry-after"]) >= 1
        assert body["details"]["retry_after_seconds"] >= 1


def test_prd_status_table_is_complete() -> None:
    assert STATUS_BY_CODE == {
        "invalid_schema": 400,
        "unauthenticated": 401,
        "not_authorised": 403,
        "not_found": 404,
        "stale_version": 409,
        "duplicate_payload_mismatch": 409,
        "already_decided": 409,
        "request_expired": 409,
        "policy_violation": 422,
        "missing_tax_config": 422,
        "legal_pack_not_approved": 422,
        "rate_limited": 429,
        "dependency_unavailable": 503,
    }


# ------------------------------------------------------------------------------------ no raw DB errors
@pytest.mark.parametrize(
    ("path", "status", "code"),
    [
        (
            "/v1/probe/errors/db-syntax",
            500,
            "internal_error",
        ),  # undefined table: a server fault, generic body
        (
            "/v1/probe/errors/db-unique",
            409,
            "stale_version",
        ),  # unique key not society-scoped: generic conflict
        ("/v1/probe/errors/db-rls", 404, "not_found"),  # RLS refusal: reveals nothing
        ("/v1/probe/errors/runtime", 500, "internal_error"),
        ("/v1/probe/errors/db-param-leak", 500, "internal_error"),
    ],
)
def test_database_and_unexpected_errors_are_safe(
    core: CoreHarness, path: str, status: int, code: str
) -> None:
    with core.client() as client:
        res = client.get(path)
    assert res.status_code == status
    body = res.json()
    assert set(body) == BODY_KEYS
    assert body["code"] == code
    assert body["request_id"] == res.headers["x-request-id"]
    assert_clean(res.text)
    assert "hunter2" not in res.text
    assert "persons" not in res.text


def test_unique_violation_on_unregistered_key_reveals_nothing_about_existence(
    core: CoreHarness,
) -> None:
    with core.client() as client:
        body = client.get("/v1/probe/errors/db-unique").json()
    assert body["code"] == "stale_version"
    assert body["details"] == {}
    assert "already_exists" not in json.dumps(body)


def test_unique_violation_on_a_society_scoped_key_may_say_already_exists() -> None:
    class Diag:
        constraint_name = "uq_probe_scoped_number"

    class FakeUnique(Exception):
        sqlstate = "23505"
        diag = Diag()

    assert map_db_error(FakeUnique("dup")).code == "stale_version"  # type: ignore[union-attr]
    register_society_scoped_unique("uq_probe_scoped_number")
    mapped = map_db_error(FakeUnique("dup"))
    assert mapped is not None
    assert (mapped.code, mapped.details) == ("policy_violation", {"reason": "already_exists"})


def test_server_errors_still_log_the_cause_for_operators_but_without_bound_parameters(
    core: CoreHarness, log_stream: io.StringIO
) -> None:
    with core.client() as client:
        client.get("/v1/probe/errors/db-param-leak")
        client.get("/v1/probe/errors/runtime")
    logged = log_stream.getvalue()
    assert "unhandled exception" in logged  # operators can diagnose
    assert "table_that_does_not_exist_xyz" in logged
    assert (
        "Zorro-Secret-Resident-Name" not in logged
    )  # hide_parameters: bound values never reach logs
    assert "hunter2" not in logged  # message text scrubbed (password=...)
    assert "[REDACTED]" in logged


def test_validation_errors_report_field_and_type_but_never_echo_input(core: CoreHarness) -> None:
    secret_phone = "9999900123"
    with core.client() as client:
        res = client.post(
            f"/v1/probe/{SOCIETY_A}/things",
            json={"name": secret_phone * 10, "phone": "x" * 50, "unknown": secret_phone},
            headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "valid-key-" + uuid.uuid4().hex},
        )
    assert res.status_code == 400
    body = res.json()
    assert body["code"] == "invalid_schema"
    fields = {f["field"]: f["issue"] for f in body["details"]["fields"]}
    assert fields["name"] == "string_too_long"
    assert secret_phone not in res.text
    assert "xxxxx" not in res.text
    assert_clean(res.text)


def test_not_found_for_missing_members_and_for_unknown_routes_look_alike(core: CoreHarness) -> None:
    with core.client() as client:
        unknown_route = client.get("/v1/definitely/not/here")
        foreign = client.get(f"/v1/probe/{uuid.uuid4()}/whoami", headers=core.auth(COMMITTEE_A))
    a = {k: v for k, v in unknown_route.json().items() if k != "request_id"}
    b = {k: v for k, v in foreign.json().items() if k != "request_id"}
    assert unknown_route.status_code == foreign.status_code == 404
    assert a == b


@pytest.mark.parametrize(
    ("sqlstate", "expected"),
    [
        ("40001", "dependency_unavailable"),
        ("40P01", "dependency_unavailable"),
        ("55P03", "dependency_unavailable"),
        ("57014", "dependency_unavailable"),
        ("08006", "dependency_unavailable"),
        ("53300", "dependency_unavailable"),
        ("42501", "not_found"),
        ("23505", "stale_version"),
        ("23503", "not_found"),
        ("23514", "policy_violation"),
        ("23502", "policy_violation"),
        ("22P02", "invalid_schema"),
        ("22003", "invalid_schema"),
        ("42P01", None),
        ("XX000", None),
        ("DW001", None),
    ],
)
def test_sqlstate_mapping(sqlstate: str, expected: str | None) -> None:
    class FakeDriverError(Exception):
        pass

    error = FakeDriverError("secret SQL text")
    error.sqlstate = sqlstate  # type: ignore[attr-defined]
    mapped = map_db_error(error)
    assert (mapped.code if mapped else None) == expected
    if mapped is not None:
        assert "secret" not in json.dumps(mapped.to_body("rid"))


# ------------------------------------------------------------------------------------ log scrubbing
SECRETS = {
    "phone": "+91 99999 00123",
    "phone_plain": "9999900124",
    "otp": "482913",
    "aadhaar": "2345 6789 0123",
    "bank": "123456789012",
    "jwt": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlc2lnbmF0dXJl",
    "bearer": "Bearer abcdefghijklmnop123456",
}


def _emit_everything(logger: logging.Logger) -> None:
    logger.info("login phone %s otp is %s", SECRETS["phone"], SECRETS["otp"])
    logger.info("aadhaar %s bank %s", SECRETS["aadhaar"], SECRETS["bank"])
    logger.info(f"header Authorization: {SECRETS['bearer']} token={SECRETS['jwt']}")
    logger.info(
        "structured",
        extra={
            "phone": SECRETS["phone_plain"],
            "otp": SECRETS["otp"],
            "authorization": SECRETS["bearer"],
            "nested": {"password": "hunter2", "aadhaar": SECRETS["aadhaar"], "ok": "fine"},
            "request_id": "keep-me",
        },
    )
    try:
        raise ValueError(f"otp={SECRETS['otp']} for {SECRETS['phone']} password=hunter2")
    except ValueError:
        logger.exception("failure while handling %s", SECRETS["phone_plain"])


def test_log_scrubbing_removes_secrets_from_messages_extras_and_tracebacks(
    log_stream: io.StringIO,
) -> None:
    _emit_everything(logging.getLogger("dwaar_api.test"))
    output = log_stream.getvalue()
    for label in ("phone", "phone_plain", "otp", "aadhaar", "bank", "jwt"):
        assert SECRETS[label] not in output, label
    assert "abcdefghijklmnop123456" not in output
    assert "hunter2" not in output
    assert "99999 00123" not in output
    lines = [json.loads(line) for line in output.splitlines() if "dwaar_api.test" in line]
    assert len(lines) == 5
    structured = next(entry for entry in lines if entry["msg"] == "structured")
    assert structured["request_id"] == "keep-me"  # correlation fields survive
    assert structured["nested"]["ok"] == "fine"
    assert structured["nested"]["password"] == "[REDACTED]"
    assert lines[-1]["exc_type"] == "ValueError"  # the traceback is kept for operators...
    assert "ValueError" in lines[-1]["exc"]
    assert "[REDACTED]" in lines[-1]["exc"]  # ...but scrubbed


def test_request_logging_never_contains_the_query_string_or_body(
    core: CoreHarness, log_stream: io.StringIO
) -> None:
    with core.client() as client:
        client.post(
            f"/v1/probe/{SOCIETY_A}/things?phone=9999900777&otp=654321",
            json={"name": "Visitor", "phone": "+91 99999 00888"},
            headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "log-key-" + uuid.uuid4().hex},
        )
    server_lines = "\n".join(
        line for line in log_stream.getvalue().splitlines() if "dwaar_api" in line
    )
    for secret in ("9999900777", "654321", "99999 00888", "9999900888"):
        assert secret not in server_lines
    access = json.loads(
        next(line for line in server_lines.splitlines() if '"dwaar_api.access"' in line)
    )
    assert access["route"] == "/v1/probe/{society_id}/things"
    assert re.fullmatch(r"soc_[0-9a-f]{12}", access["society_token"])


def test_error_code_is_logged_for_failed_requests(
    core: CoreHarness, log_stream: io.StringIO
) -> None:
    with core.client() as client:
        client.get(f"/v1/probe/{SOCIETY_A}/whoami")  # 401
        client.get("/v1/probe/errors/code/rate_limited")  # 429
    entries: list[dict[str, Any]] = [
        json.loads(line)
        for line in log_stream.getvalue().splitlines()
        if '"dwaar_api.access"' in line
    ]
    assert [(e["status"], e["error_code"]) for e in entries] == [
        (401, "unauthenticated"),
        (429, "rate_limited"),
    ]
