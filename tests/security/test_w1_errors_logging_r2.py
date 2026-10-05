"""W1 fix round 2: regression tests for error handlers, the logging scrubber and exposed documentation (OBS-01, INV-01, IAM-13).

These started life as failing repros in ``verify_w1_errors_logging.py`` (open findings of verification round 1) and were moved
here when their root causes were fixed; each asserts the SECURE behaviour. Tests that already passed in the
repro file (attacks that were tried and did not work) are kept as regression evidence.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import socket
import uuid
from collections.abc import Iterator
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends

from dwaar_api.core.authn import InMemorySessionStore
from dwaar_api.core.authz import AuthContext, Permission, require
from dwaar_common.logging import scrub_text
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    CoreHarness,
    core_harness,
    make_settings,
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


def test_openapi_and_docs_are_not_served_in_production(db: DbHandle) -> None:
    from fastapi.testclient import TestClient

    from dwaar_api.core.db import Database
    from dwaar_api.main import create_app

    settings = make_settings(
        db,
        env="production",
        oidc_issuer_url="https://issuer.example",
        oidc_jwks_url="https://issuer.example/jwks",
        cors_origins="https://admin.example",
    )
    database = Database.from_settings(settings)
    try:
        app = create_app(
            settings,
            database=database,
            modules_package=None,
            session_store=InMemorySessionStore(),
        )
        client = TestClient(app, raise_server_exceptions=False)
        served = {p: client.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")}
    finally:
        database.dispose()
    assert served == {"/docs": 404, "/redoc": 404, "/openapi.json": 404}, served


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


BANK_VARIANTS = [
    "50100123456789",
    "a/c 1234567890123",
    "acct 1234 5678 9012 3456",
    "1234-5678-9012-3456",
    "account_number: 123456789",
    "A/C No. 0123-4567-8901-2",
    "0123 4567 8901 2345 67",
]


# ------------------------------------------------------------------------------------------------
# uvicorn's own access log bypasses the scrubbing handler
# ------------------------------------------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
