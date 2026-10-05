"""App assembly: module registry, /healthz /readyz /v1/meta, request id, access log, OpenAPI shape."""

from __future__ import annotations

import io
import json
import logging
import re
import uuid

import pytest
from fastapi import APIRouter

from dwaar_api.core.authz import Permission, PermissionRegistry
from dwaar_api.core.config import ConfigError
from dwaar_api.core.registry import ModuleError, discover_modules
from dwaar_api.main import create_app
from dwaar_common.logging import build_handler
from tests.integration.core._support import (
    COMMITTEE_A,
    PROBE_PACKAGE,
    SOCIETY_A,
    CoreHarness,
    make_settings,
)

pytestmark = pytest.mark.req("ARCH-03")


def test_registry_discovers_module_without_shared_edits(core: CoreHarness) -> None:
    specs = discover_modules(PROBE_PACKAGE)
    assert [s.name for s in specs] == ["core_probe"]
    assert specs[0].router is not None
    assert {p.action for p in specs[0].permissions} >= {"probe.read", "probe.write"}
    assert core.app.state.core_probe_registered is True  # register(app) hook ran
    assert "probe.write" in core.app.state.permissions
    assert "/v1/probe/{society_id}/things" in core.app.openapi()["paths"]


def test_default_modules_package_loads_cleanly(db) -> None:  # type: ignore[no-untyped-def]
    """The shipped dwaar_api.modules package (other builders' modules included) must assemble."""
    from dwaar_api.core.db import Database

    database = Database.from_settings(make_settings(db))
    try:
        app = create_app(make_settings(db), database=database)
        assert app.title == "Dwaar API"
    finally:
        database.dispose()


def test_missing_package_is_empty_and_broken_module_is_loud(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    assert discover_modules("no_such_modules_package_xyz") == []
    pkg = tmp_path / "bad_mods"
    (pkg / "empty_one").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "empty_one" / "__init__.py").write_text("# exposes nothing\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    with pytest.raises(ModuleError, match="exposes none"):
        discover_modules("bad_mods")


def test_wrong_router_type_rejected(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    pkg = tmp_path / "bad_mods2"
    (pkg / "m").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "m" / "__init__.py").write_text("router = object()\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    with pytest.raises(ModuleError, match="APIRouter"):
        discover_modules("bad_mods2")


def test_duplicate_conflicting_permission_rejected() -> None:
    registry = PermissionRegistry([Permission("a.b", frozenset({"x"}))])
    registry.register(Permission("a.b", frozenset({"x"})))  # identical: fine
    with pytest.raises(ConfigError):
        registry.register(Permission("a.b", frozenset({"y"})))


def test_route_requiring_undeclared_permission_fails_startup(db, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from dwaar_api.core.authz import require
    from dwaar_api.core.db import Database

    pkg = tmp_path / "undeclared_mods"
    (pkg / "m").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "m" / "__init__.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from dwaar_api.core.authz import require\n"
        "router = APIRouter()\n"
        "@router.get('/v1/x/{society_id}')\n"
        "def x(auth=Depends(require('ghost.action'))):\n    return {}\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    assert require  # imported for the side effect of proving the symbol exists
    database = Database.from_settings(make_settings(db))
    try:
        with pytest.raises(ConfigError, match=r"ghost\.action"):
            create_app(make_settings(db), database=database, modules_package="undeclared_mods")
    finally:
        database.dispose()


def test_ops_endpoints(core: CoreHarness) -> None:
    with core.client() as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        ready = client.get("/readyz")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready", "checks": {"database": "ok", "migrations": "ok"}}
        meta = client.get("/v1/meta")
        body = meta.json()
        assert body["api_version"] == "v1"
        assert body["environment"] == "test"
        assert body["simulation"] is True
        assert body["service"] == "dwaar_api"
        assert not {"database_url", "password"} & set(json.dumps(body).lower().split('"'))


def test_readyz_reports_failure_without_leaking(core: CoreHarness) -> None:
    with core.client() as client:
        with core.db.admin_conn() as conn:
            conn.execute("DROP TABLE schema_migrations")
        res = client.get("/readyz")
    assert res.status_code == 503
    assert res.json()["status"] == "not_ready"
    assert "does not exist" not in res.text
    assert "schema_migrations" not in res.text


def test_request_id_header_and_inbound_validation(core: CoreHarness) -> None:
    with core.client() as client:
        res = client.get("/v1/meta")
        rid = res.headers["x-request-id"]
        assert uuid.UUID(rid).version == 7
        mine = str(uuid.uuid4())
        assert (
            client.get("/v1/meta", headers={"X-Request-ID": mine}).headers["x-request-id"] == mine
        )
        hostile = client.get("/v1/meta", headers={"X-Request-ID": "x\ninjected log line"})
        assert uuid.UUID(hostile.headers["x-request-id"])  # replaced by a server-generated id
        assert res.headers["cache-control"] == "no-store"
        assert res.headers["x-content-type-options"] == "nosniff"


def test_access_log_has_route_template_status_latency_and_no_query(core: CoreHarness) -> None:
    stream = io.StringIO()
    handler = build_handler("dwaar-api-test", stream)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
    try:
        with core.client() as client:
            client.get(
                f"/v1/probe/{SOCIETY_A}/whoami?phone=%2B919999900123&token=abc.def.ghi",
                headers=core.auth(COMMITTEE_A),
            )
    finally:
        logging.getLogger().removeHandler(handler)
    lines = [
        json.loads(line) for line in stream.getvalue().splitlines() if '"dwaar_api.access"' in line
    ]
    assert lines, stream.getvalue()
    entry = lines[-1]
    assert entry["route"] == "/v1/probe/{society_id}/whoami"
    assert entry["status"] == 200
    assert entry["method"] == "GET"
    assert entry["latency_ms"] >= 0
    assert re.fullmatch(r"soc_[0-9a-f]{12}", entry["society_token"])
    assert entry["correlation_id"]
    raw = "\n".join(line for line in stream.getvalue().splitlines() if '"dwaar_api.access"' in line)
    assert "919999900123" not in raw
    assert "abc.def.ghi" not in raw
    assert str(SOCIETY_A) not in raw


def test_openapi_documents_error_body_and_bearer_auth(core: CoreHarness) -> None:
    schema = core.app.openapi()
    assert "ErrorBody" in schema["components"]["schemas"]
    assert "bearerAuth" in schema["components"]["securitySchemes"]
    assert "/v1/meta" in schema["paths"]
    create = schema["paths"]["/v1/probe/{society_id}/things"]["post"]
    header = next(p for p in create["parameters"] if p["name"] == "Idempotency-Key")
    assert header["in"] == "header"
    assert header["required"] is True  # the contract says so; clients cannot miss it
    assert "409" in create["responses"]
    assert "400" in create["responses"]
    assert "HTTPValidationError" not in json.dumps(schema)


def test_unknown_route_and_method_use_error_body(core: CoreHarness) -> None:
    with core.client() as client:
        missing = client.get("/v1/nope")
        wrong = client.delete("/v1/meta")
    assert missing.status_code == 404
    assert missing.json()["code"] == "not_found"
    assert missing.json()["request_id"]
    assert wrong.status_code == 405
    assert wrong.json()["code"] == "invalid_schema"
    assert isinstance(APIRouter(), APIRouter)
