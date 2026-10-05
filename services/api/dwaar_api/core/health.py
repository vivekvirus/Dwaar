"""Operational endpoints: ``/healthz`` (liveness), ``/readyz`` (readiness), ``/v1/meta`` (public build info).

REQ: PRD 13 / OBS (instrumented operations), BUILD_BRIEF section 3. None of these reveal secrets, hostnames,
credentials, member data or exception text; ``/readyz`` reports check names and ``ok``/``fail`` only.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from dwaar_common.timeutil import format_iso_utc, utc_now

from .. import SERVICE_NAME, __version__
from .authz import public_route
from .db import Database
from .migrate import shipped_versions

log = logging.getLogger("dwaar_api.health")
router = APIRouter(
    tags=["ops"],
    dependencies=[Depends(public_route("liveness, readiness and build info are public by design"))],
)


@router.get("/healthz", summary="Liveness: the process is up (no dependencies checked)")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", summary="Readiness: database reachable and all shipped migrations applied")
def readyz(request: Request) -> JSONResponse:
    db: Database = request.app.state.db
    checks: dict[str, str] = {}
    try:
        db.ping()
        checks["database"] = "ok"
    except Exception as exc:
        log.warning("readiness: database check failed", extra={"exc_type": type(exc).__name__})
        checks["database"] = "fail"
    if checks["database"] == "ok":
        # Re-run on EVERY readiness probe (not only at boot): a role promoted to superuser/BYPASSRLS, or given
        # role-level defaults, after the pool filled must take the instance out of rotation (ARCH-03, R2-02/03).
        try:
            db.assert_restricted_role()
            checks["role"] = "ok"
        except Exception as exc:
            log.warning("readiness: role check failed", extra={"exc_type": type(exc).__name__})
            checks["role"] = "fail"
        try:
            checks["role_defaults"] = "drift" if db.role_default_settings() else "ok"
        except Exception as exc:
            log.warning(
                "readiness: role defaults check failed", extra={"exc_type": type(exc).__name__}
            )
            checks["role_defaults"] = "fail"
        try:
            with db.app_engine.connect() as conn:
                applied = {
                    int(r[0]) for r in conn.execute(text("SELECT version FROM schema_migrations"))
                }
                conn.rollback()
            checks["migrations"] = "ok" if shipped_versions() <= applied else "pending"
        except Exception as exc:
            log.warning("readiness: migration check failed", extra={"exc_type": type(exc).__name__})
            checks["migrations"] = "fail"
    else:
        checks["role"] = "unknown"
        checks["role_defaults"] = "unknown"
        checks["migrations"] = "unknown"
    ready = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not_ready", "checks": checks},
        headers={"Retry-After": "5"} if not ready else None,
    )


@router.get("/v1/meta", summary="Public service metadata", tags=["meta"])
def meta(request: Request) -> dict[str, Any]:
    settings = request.app.state.settings
    return {
        "service": SERVICE_NAME,
        "version": __version__,
        "api_version": "v1",
        "environment": settings.env.value,
        "simulation": settings.simulation,
        "server_time": format_iso_utc(utc_now()),
    }
