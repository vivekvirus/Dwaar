"""W1 adversarial verification: error handlers, membership oracles and the logging scrubber (OBS-01, IAM, INV-01).

Not collected by ``make test``; run explicitly:
    uv run --no-sync pytest tests/security/verify_w1_errors_logging.py -p no:cacheprovider

A FAILING test asserts the secure behaviour and therefore marks a confirmed defect.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import io
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from collections.abc import Iterator
from typing import Annotated, Any

import psycopg
import pytest
from fastapi import APIRouter, Depends

from dwaar_api.core.audit import masked_diff
from dwaar_api.core.authz import AuthContext, Permission, require
from dwaar_api.core.errors import map_db_error
from dwaar_common.logging import build_handler, scrub_text, scrub_value
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    OUTSIDER,
    RESIDENT_A,
    SOCIETY_A,
    CoreHarness,
    core_harness,
)

pytestmark = pytest.mark.req("OBS-01", "INV-01", "IAM-13")


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


# ------------------------------------------------------------------------------------------------
# (6) error handlers
# ------------------------------------------------------------------------------------------------
def _install_probe_routes(core: CoreHarness) -> None:
    core.app.state.permissions.register(Permission("verify.boom", frozenset({"committee"})))
    router = APIRouter()

    @router.get("/v1/verify/{society_id}/sql-error")
    def sql_error(
        society_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("verify.boom"))]
    ) -> Any:
        from sqlalchemy import text

        with auth.tx() as conn:
            conn.execute(
                text(
                    "SELECT * FROM table_that_does_not_exist_secret_name WHERE phone = '9999900123'"
                )
            )

    @router.get("/v1/verify/{society_id}/boom")
    def boom(
        society_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("verify.boom"))]
    ) -> Any:
        raise RuntimeError(
            "password=hunter2 SELECT * FROM persons WHERE phone='9999900123' /srv/app/secret.py"
        )

    @router.post("/v1/verify/{society_id}/dup")
    def dup(
        society_id: uuid.UUID,
        auth: Annotated[AuthContext, Depends(require("verify.boom"))],
        phone_token: str = "",
    ) -> Any:
        from sqlalchemy import text

        with auth.tx() as conn:
            conn.execute(
                text("INSERT INTO verify_persons (phone_token) VALUES (:t)"), {"t": phone_token}
            )
        return {"created": True}

    core.app.include_router(router)
    with core.db.owner_conn() as conn:
        conn.execute(
            "CREATE TABLE verify_persons (id serial PRIMARY KEY, phone_token text NOT NULL UNIQUE)"
        )
        conn.execute("GRANT SELECT, INSERT ON verify_persons TO dwaar_app")
        conn.execute("GRANT USAGE ON SEQUENCE verify_persons_id_seq TO dwaar_app")


def test_database_and_unhandled_errors_never_reach_the_client(core: CoreHarness) -> None:
    _install_probe_routes(core)
    client = core.client()
    for path in ("sql-error", "boom"):
        resp = client.get(f"/v1/verify/{SOCIETY_A}/{path}", headers=core.auth(COMMITTEE_A))
        body = resp.text
        assert resp.status_code in (500, 503)
        for needle in (
            "table_that_does_not_exist",
            "hunter2",
            "persons",
            "9999900123",
            "Traceback",
            "secret.py",
            "psycopg",
            "SELECT",
        ):
            assert needle not in body, (path, needle)
        assert set(resp.json()) == {"request_id", "code", "message", "message_key", "details"}


def test_unique_violation_does_not_become_an_existence_oracle_for_people(core: CoreHarness) -> None:
    """Core maps SQLSTATE 23505 to 422 policy_violation {reason: already_exists}. For a globally unique
    identifier such as persons.phone_token this tells any caller whether a person (possibly a member of
    ANOTHER society) already exists, contradicting 'errors never reveal whether a person is a member'."""
    _install_probe_routes(core)
    client = core.client()
    url = f"/v1/verify/{SOCIETY_A}/dup"
    first = client.post(url, params={"phone_token": "tok-abc"}, headers=core.auth(COMMITTEE_A))
    second = client.post(url, params={"phone_token": "tok-abc"}, headers=core.auth(COMMITTEE_A))
    assert first.status_code == 200
    assert "already_exists" not in second.text, second.text
    assert second.status_code in (200, 404, 409), second.status_code


def test_non_member_and_nonexistent_society_are_indistinguishable(core: CoreHarness) -> None:
    client = core.client()
    other = uuid.UUID("0192f300-0000-7000-8000-0000000000ee")  # does not exist anywhere
    real = client.get(f"/v1/probe/{SOCIETY_A}/things", headers=core.auth(OUTSIDER))
    ghost = client.get(f"/v1/probe/{other}/things", headers=core.auth(OUTSIDER))
    assert real.status_code == ghost.status_code == 404

    def norm(r: Any) -> dict[str, Any]:
        d = r.json()
        d.pop("request_id")
        return dict(d)

    assert norm(real) == norm(ghost)
    assert {
        k: v for k, v in real.headers.items() if k.lower() not in ("x-request-id", "content-length")
    } == {
        k: v
        for k, v in ghost.headers.items()
        if k.lower() not in ("x-request-id", "content-length")
    }


def test_member_without_permission_vs_outsider_only_reveals_the_callers_own_standing(
    core: CoreHarness,
) -> None:
    client = core.client()
    resident = client.get(f"/v1/probe/{SOCIETY_A}/things", headers=core.auth(RESIDENT_A))
    outsider = client.get(f"/v1/probe/{SOCIETY_A}/things", headers=core.auth(OUTSIDER))
    assert (resident.status_code, outsider.status_code) == (
        403,
        404,
    )  # accepted: caller's own membership only


def test_response_timing_does_not_separate_member_from_non_member_by_an_order_of_magnitude(
    core: CoreHarness,
) -> None:
    client = core.client()

    def median(person: uuid.UUID, society: uuid.UUID) -> float:
        samples = []
        for _ in range(60):
            t = time.perf_counter()
            client.get(f"/v1/probe/{society}/things", headers=core.auth(person))
            samples.append(time.perf_counter() - t)
        samples.sort()
        return samples[len(samples) // 2]

    member_denied = median(RESIDENT_A, SOCIETY_A)  # 403
    outsider = median(OUTSIDER, SOCIETY_A)  # 404
    assert 0.2 < member_denied / outsider < 5.0, (member_denied, outsider)


def test_validation_errors_never_echo_submitted_values(core: CoreHarness) -> None:
    resp = core.client().post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "echo-test-0001"},
        json={"name": "", "phone": "+91 99999 00123 and more text 123456789012"},
    )
    assert resp.status_code == 400
    assert "99999" not in resp.text and "123456789012" not in resp.text


def test_map_db_error_classes_never_forward_message_text() -> None:
    for exc in (
        psycopg.errors.UniqueViolation("Key (email)=(a@b.example) already exists."),
        psycopg.errors.ForeignKeyViolation("Key (unit_id)=(123) is not present in table units"),
        psycopg.errors.CheckViolation(
            'new row for relation "x" violates check constraint "x_phone_check"'
        ),
        psycopg.errors.InsufficientPrivilege('permission denied for table "persons"'),
    ):
        mapped = map_db_error(exc)
        assert mapped is not None
        rendered = repr(mapped.to_body("rid")) + mapped.message
        for needle in ("a@b.example", "unit_id", "x_phone_check", "persons"):
            assert needle not in rendered


# ------------------------------------------------------------------------------------------------
# (7) logging scrubber misses
# ------------------------------------------------------------------------------------------------
def _leaks(text: str, secret: str) -> bool:
    return secret in scrub_text(text)


PHONE_VARIANTS = [
    "+91 99999 00123",
    "+91-99999-00123",
    "99999-00123",
    "9999900123",
    "+919999900123",
    "09999900123",
    "0091 9999900123",
    "(+91) 99999 00123",
    "99999 00123",
    "tel:+919999900123",
    "wa.me/919999900123",
    "phone_9999900123",
    "customer-9999900123",
    "+91 999 990 0123",
    "999-990-0123",
    "+91.99999.00123",
    "99999.00123",
    "99999 00123",
    "९९९९९००१२३",
    "９９９９９００１２３",
    "٩٩٩٩٩٠٠١٢٣",
]


@pytest.mark.parametrize("variant", PHONE_VARIANTS)
def test_phone_number_variants_are_scrubbed_from_free_text(variant: str) -> None:
    out = scrub_text(f"call back on {variant} please")
    digits_left = "".join(ch for ch in out if ch.isdigit())
    assert "[REDACTED]" in out and len(digits_left) < 6, out


AADHAAR_VARIANTS = [
    "1234 5678 9012",
    "1234-5678-9012",
    "123456789012",
    "1234  5678  9012",
    "1234.5678.9012",
    "1234 5678 9012",
    "1234 56789012",
    "१२३४ ५६७८ ९०१२",
]


@pytest.mark.parametrize("variant", AADHAAR_VARIANTS)
def test_aadhaar_variants_are_scrubbed(variant: str) -> None:
    out = scrub_text(f"aadhaar {variant} on file")
    digits_left = "".join(ch for ch in out if ch.isdigit())
    assert len(digits_left) < 5, out


OTP_VARIANTS = [
    ("otp=123456", "123456"),
    ("OTP: 123456", "123456"),
    ("otp%3D123456", "123456"),
    ("otp_code=123456", "123456"),
    ("verification_code=123456", "123456"),
    ("otp = 123456", "123456"),
    ("your one-time password is 482913", "482913"),
    ("482913 is your OTP", "482913"),
    ("OTP is 12 34 56", "12 34 56"),
    ("/auth/otp/123456/verify", "123456"),
    ("otp[]=123456", "123456"),
    ("OTP-123456", "123456"),
    ("x-otp: 123456", "123456"),
    ("otp_value=123456", "123456"),
]


@pytest.mark.parametrize(("variant", "code"), OTP_VARIANTS)
def test_otp_variants_are_scrubbed(variant: str, code: str) -> None:
    out = scrub_text(f"GET /v1/auth/verify?{variant} HTTP/1.1 200")
    assert code not in out, out


SECRET_HEADER_VARIANTS = [
    ("Authorization: Bearer abcdefgh12345678", "abcdefgh12345678"),
    ("Authorization: Token abcdef1234567890", "abcdef1234567890"),
    ("Authorization: ApiKey abcdef1234567890", "abcdef1234567890"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("Authorization: Bearer abc123", "abc123"),
    ("Cookie: session=abcdef123456", "abcdef123456"),
    ("Set-Cookie: sid=abcdef123456; HttpOnly", "abcdef123456"),
    ("X-Auth-Token: abcdef123456", "abcdef123456"),
    ("access_token=abcdef1234567890", "abcdef1234567890"),
    ("refresh_token=abcdef1234567890", "abcdef1234567890"),
    ("client_secret=abcdef1234567890", "abcdef1234567890"),
    ("new_password=hunter2hunter2", "hunter2hunter2"),
    ("password=hunter2", "hunter2"),
    ("x-api-key: abcdef123456", "abcdef123456"),
    ("session_token=abcdef123456", "abcdef123456"),
    ("secret_key=abcdef123456", "abcdef123456"),
]


@pytest.mark.parametrize(("line", "secret"), SECRET_HEADER_VARIANTS)
def test_credentials_in_text_are_scrubbed(line: str, secret: str) -> None:
    assert not _leaks(f"request headers: {line}", secret), scrub_text(line)


BANK_VARIANTS = [
    "50100123456789",
    "a/c 1234567890123",
    "acct 1234 5678 9012 3456",
    "1234-5678-9012-3456",
    "account_number: 123456789",
    "A/C No. 0123-4567-8901-2",
    "0123 4567 8901 2345 67",
]


@pytest.mark.parametrize("variant", BANK_VARIANTS)
def test_bank_account_variants_are_scrubbed(variant: str) -> None:
    out = scrub_text(f"settle to {variant} today")
    digits_left = "".join(ch for ch in out if ch.isdigit())
    assert len(digits_left) < 5, out


def test_numbers_under_innocuous_keys_are_scrubbed_as_values() -> None:
    """scrub_value returns ints untouched: a phone/account stored as a number under a key that is not on the
    sensitive-name list ('contact', 'acct', 'ref') is logged and audited verbatim."""
    out = scrub_value({"contact": 9999900123, "ref": 50100123456789, "nested": {"n": [9999900123]}})
    assert "9999900123" not in str(out) and "50100123456789" not in str(out), out


def test_logging_pipeline_end_to_end_scrubs_extras_and_exceptions() -> None:
    stream = io.StringIO()
    handler = build_handler("verify", stream)
    logger = logging.getLogger("verify_w1.pipeline")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.info(
        "login for +91 99999 00123",
        extra={"Authorization": "Bearer abcdefgh12345678", "otp": "123456"},
    )
    try:
        raise ValueError("bad otp=123456 for 9999900123")
    except ValueError:
        logger.exception("failed")
    out = stream.getvalue()
    for needle in ("99999 00123", "abcdefgh12345678", "123456", "9999900123"):
        assert needle not in out, (needle, out)


def test_masked_diff_scrubs_nested_lists_and_numeric_values() -> None:
    diff = masked_diff(
        None,
        {
            "members": [[{"phone": "9999900123"}], [{"note": "call +91 99999 00123"}]],
            "contact": 9999900123,
        },
    )
    rendered = str(diff)
    assert "9999900123" not in rendered and "99999 00123" not in rendered, rendered


def test_record_audit_explicit_diff_is_masked_too(core: CoreHarness) -> None:
    """``record_audit(diff=...)`` stores the caller's dict as is: the masking guarantee exists only on the
    before/after path, so one call site using ``diff=`` writes raw PII into the append-only audit log."""
    from dwaar_api.core.audit import record_audit
    from dwaar_api.core.db import RequestContext

    ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.uuid4())
    with core.database.app_tx(ctx) as conn:
        audit_id = record_audit(
            conn,
            ctx,
            operation="probe.x",
            object_type="probe_thing",
            diff={
                "op": "update",
                "changed": {"note": {"after": "call +91 99999 00123, aadhaar 1234 5678 9012"}},
            },
        )
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        row = conn.execute(
            "SELECT diff_masked::text FROM audit_log WHERE id = %s", (audit_id,)
        ).fetchone()
    assert row is not None
    assert "99999 00123" not in row[0] and "5678 9012" not in row[0], row[0]


def test_outbox_event_payload_is_masked_or_rejected_when_it_carries_personal_data(
    core: CoreHarness,
) -> None:
    from dwaar_api.core.audit import MutationResult, mutation
    from dwaar_api.core.db import RequestContext

    ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.uuid4())

    def apply(c: Any) -> MutationResult:
        return MutationResult(
            uuid.uuid4(), 1, event_payload={"phone": "+91 99999 00123", "note": "otp=123456"}
        )

    try:
        with core.database.app_tx(ctx) as conn:
            mutation(
                conn,
                ctx,
                operation="probe.x",
                object_type="probe_thing",
                event_type="ThingCreated",
                apply=apply,
            )
    except Exception:  # noqa: BLE001
        return  # rejected: acceptable
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        payload = conn.execute("SELECT payload::text FROM outbox").fetchone()
    assert payload is not None
    assert "99999 00123" not in payload[0] and "123456" not in payload[0], payload[0]


# ------------------------------------------------------------------------------------------------
# uvicorn's own access log bypasses the scrubbing handler
# ------------------------------------------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_uvicorn_and_get_log(tmp_path: Any, extra_args: list[str]) -> str:
    """Boot ``uvicorn dwaar_api.main:app`` the way ``make api`` does, hit it with secrets in the URL, and
    return everything it wrote to stdout/stderr."""
    port = _free_port()
    env = {
        **os.environ,
        "DWAAR_ENV": "local",
        "NO_PROXY": "127.0.0.1",
        "no_proxy": "127.0.0.1",
        "PYTHONUNBUFFERED": "1",
    }
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(var, None)
    log = tmp_path / "uvicorn.err"
    with log.open("w") as err:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "dwaar_api.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                *extra_args,
            ],
            stdout=err,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=os.getcwd(),
        )
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1).read()  # noqa: S310
                    break
                except Exception:  # noqa: BLE001
                    time.sleep(0.3)
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/healthz?otp=482913&phone=9999900123&access_token=SECRETTOKEN123",
                timeout=3,
            ).read()
            time.sleep(0.5)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    return log.read_text()


@pytest.mark.parametrize("extra_args", [[], ["--no-access-log"]], ids=["default", "make-api"])
def test_server_access_log_does_not_contain_query_string_secrets(
    tmp_path: Any, extra_args: list[str]
) -> None:
    """uvicorn.access used to write the raw request line (query string included) to stderr with its own
    handler and propagate=False, bypassing dwaar_common.logging. ``make api`` now passes --no-access-log, and
    the app additionally re-routes uvicorn's loggers through the scrubbing handler and strips query strings,
    so even a deployment that forgets the flag logs no secret."""
    output = _run_uvicorn_and_get_log(tmp_path, extra_args)
    assert "/healthz" in output, output[
        -500:
    ]  # a request line (or the JSON access record) is logged
    for needle in ("482913", "9999900123", "SECRETTOKEN123", "otp=", "access_token"):
        assert needle not in output, f"{needle} written to the server log: {output[-400:]}"
    assert '"service":"dwaar-api"' in output.replace(" ", "")  # JSON via the scrubbing handler


def test_make_api_recipe_disables_the_raw_uvicorn_access_log() -> None:
    from pathlib import Path

    makefile = (Path(__file__).resolve().parents[2] / "Makefile").read_text(encoding="utf-8")
    recipe = next(ln for ln in makefile.splitlines() if "uvicorn dwaar_api.main:app" in ln)
    assert "--no-access-log" in recipe
