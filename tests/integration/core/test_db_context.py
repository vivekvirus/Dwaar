"""Per-transaction request context, pool hygiene and the restricted-role startup guard (ARCH-03)."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from dwaar_api.core.config import ConfigError
from dwaar_api.core.db import Database, RequestContext, make_engine, to_sqlalchemy_url, transaction
from dwaar_api.main import create_app
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    PROBE_PACKAGE,
    SOCIETY_A,
    SOCIETY_B,
    create_probe_table,
    make_settings,
)

pytestmark = pytest.mark.req("ARCH-03", "INV-01")

REQUEST_ID = uuid.UUID("0192f300-0000-7000-8000-0000000000bb")


def current(conn, name: str):  # type: ignore[no-untyped-def]
    return conn.execute(text("SELECT current_setting(:n, true)"), {"n": name}).scalar_one()


def test_context_dataclass_validates_and_renders_settings() -> None:
    ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", REQUEST_ID)
    assert ctx.settings() == {
        "app.society_id": str(SOCIETY_A),
        "app.person_id": str(COMMITTEE_A),
        "app.actor_role": "committee",
        "app.request_id": str(REQUEST_ID),
    }
    assert RequestContext().settings() == {}
    assert ctx.actor_ref == f"person:{COMMITTEE_A}"
    assert RequestContext().actor_ref == "system"
    assert ctx.with_society(SOCIETY_B).society_id == SOCIETY_B
    with pytest.raises(TypeError):
        RequestContext(society_id=str(SOCIETY_A))  # type: ignore[arg-type]
    for bad_role in ("Admin", "committee; DROP TABLE x", "", "a" * 65, "1abc"):
        with pytest.raises(ValueError, match="actor_role"):
            RequestContext(actor_role=bad_role)


def test_transaction_sets_all_four_values_transaction_locally(db: DbHandle) -> None:
    database = Database(db.app_dsn, pool_size=1, max_overflow=0)
    try:
        ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", REQUEST_ID)
        with database.app_tx(ctx) as conn:
            assert current(conn, "app.society_id") == str(SOCIETY_A)
            assert current(conn, "app.person_id") == str(COMMITTEE_A)
            assert current(conn, "app.actor_role") == "committee"
            assert current(conn, "app.request_id") == str(REQUEST_ID)
        # the SAME pooled connection (pool_size=1) is reused: nothing may survive the transaction
        with database.app_tx() as conn:
            for name in ("app.society_id", "app.person_id", "app.actor_role", "app.request_id"):
                assert current(conn, name) in ("", None), name
    finally:
        database.dispose()


def test_context_does_not_leak_between_consecutive_requests_or_after_errors(db: DbHandle) -> None:
    create_probe_table(db)
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        conn.execute(
            "INSERT INTO probe_things (society_id, name) VALUES (%s, 'visible-to-a')", (SOCIETY_A,)
        )
    database = Database(db.app_dsn, pool_size=1, max_overflow=0)
    try:
        with database.app_tx(RequestContext(SOCIETY_A)) as conn:
            assert conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one() == 1
        with pytest.raises(RuntimeError), database.app_tx(RequestContext(SOCIETY_A)):
            raise RuntimeError("request failed")
        with database.app_tx() as conn:  # next request on the recycled connection has no society
            assert conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one() == 0
        with database.app_tx(RequestContext(SOCIETY_B)) as conn:
            assert conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one() == 0
    finally:
        database.dispose()


def _insert_then_fail(database: Database, ctx: RequestContext) -> None:
    with database.app_tx(ctx) as conn:
        conn.execute(
            text("INSERT INTO probe_things (society_id, name) VALUES (:s, 'lost')"),
            {"s": SOCIETY_A},
        )
        raise RuntimeError("boom")


def test_transaction_commits_on_success_and_rolls_back_on_error(db: DbHandle) -> None:
    create_probe_table(db)
    database = Database(db.app_dsn)
    ctx = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", REQUEST_ID)
    try:
        with database.app_tx(ctx) as conn:
            conn.execute(
                text("INSERT INTO probe_things (society_id, name) VALUES (:s, 'kept')"),
                {"s": SOCIETY_A},
            )
        with pytest.raises(RuntimeError):
            _insert_then_fail(database, ctx)
    finally:
        database.dispose()
    with db.admin_conn() as conn:
        assert [r[0] for r in conn.execute("SELECT name FROM probe_things")] == ["kept"]


def test_worker_engine_uses_the_worker_role(db: DbHandle) -> None:
    database = Database(db.app_dsn, db.worker_dsn)
    try:
        with database.app_tx() as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() == "dwaar_app"
        with database.worker_tx(RequestContext(SOCIETY_A)) as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() == "dwaar_worker"
            assert current(conn, "app.society_id") == str(SOCIETY_A)
        database.ping()
        database.assert_restricted_role()
    finally:
        database.dispose()
    no_worker = Database(db.app_dsn)
    try:
        with pytest.raises(ConfigError):
            _ = no_worker.worker_engine
    finally:
        no_worker.dispose()


def test_engine_applies_statement_timeout_and_application_name(db: DbHandle) -> None:
    engine = make_engine(db.app_dsn, application_name="dwaar-test", statement_timeout_ms=1234)
    try:
        with transaction(engine) as conn:
            assert conn.execute(text("SHOW statement_timeout")).scalar_one() == "1234ms"
            assert current(conn, "application_name") == "dwaar-test"
    finally:
        engine.dispose()


def test_url_helper_accepts_both_schemes_and_rejects_other_databases() -> None:
    assert to_sqlalchemy_url("postgresql://u:p%40ss@h:5432/d").startswith(
        "postgresql+psycopg://u:p%40ss@h:5432/d"
    )
    assert to_sqlalchemy_url("postgres://u:p@h/d").startswith("postgresql+psycopg://")
    with pytest.raises(ConfigError):
        to_sqlalchemy_url("mysql://u:p@h/d")


def test_startup_refuses_a_superuser_connection(db: DbHandle) -> None:
    """Never connect the API as owner/superuser: the lifespan check refuses to start the app."""
    database = Database(db.admin_dsn)  # postgres superuser (the harness uses trust auth)
    app = create_app(make_settings(db), database=database, modules_package=PROBE_PACKAGE)
    with pytest.raises(ConfigError, match="superuser or BYPASSRLS"), TestClient(app):
        pass
    database.dispose()


def test_startup_survives_an_unreachable_database_and_readyz_says_so(db: DbHandle) -> None:
    dead = Database("postgresql://dwaar_app:x@127.0.0.1:1/none")
    app = create_app(make_settings(db), database=dead, modules_package=PROBE_PACKAGE)
    with TestClient(app) as client:
        res = client.get("/readyz")
        assert res.status_code == 503
        assert res.json() == {
            "status": "not_ready",
            "checks": {"database": "fail", "migrations": "unknown"},
        }
        assert client.get("/healthz").status_code == 200  # liveness does not depend on the database
