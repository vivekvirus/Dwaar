"""Application assembly: ``create_app()``.

Run locally with ``make api`` (uvicorn ``dwaar_api.main:app``). ``app`` is created lazily on first access so
importing this module (tests, OpenAPI export) never requires production settings.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from dwaar_common.logging import configure_logging

from . import __version__
from .core import health
from .core.authn import IdentityProvider, OidcIdentityProvider, SessionStore
from .core.authz import (
    DenyAllGrantResolver,
    GrantResolver,
    Permission,
    PermissionRegistry,
    check_requirements,
)
from .core.config import ConfigError, Settings, load_settings
from .core.db import Database
from .core.errors import ERROR_RESPONSES, install_error_handlers
from .core.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from .core.pagination import Paginator
from .core.registry import DEFAULT_PACKAGE, load_modules

log = logging.getLogger("dwaar_api")


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    identity_provider: IdentityProvider | None = None,
    session_store: SessionStore | None = None,
    grant_resolver: GrantResolver | None = None,
    modules_package: str | None = DEFAULT_PACKAGE,
    extra_permissions: tuple[Permission, ...] = (),
) -> FastAPI:
    """Build the API. Explicit arguments override what modules register (tests, special deployments)."""
    settings = settings or load_settings()
    configure_logging(service="dwaar-api", level=settings.log_level)
    db = database or Database.from_settings(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            db.assert_restricted_role()
        except ConfigError:
            raise  # wrong role (superuser/BYPASSRLS): refuse to start
        except Exception as exc:  # database down at boot: stay up, /readyz reports it
            log.warning(
                "startup role check skipped (database unreachable)",
                extra={"exc_type": type(exc).__name__},
            )
        yield
        db.dispose()

    app = FastAPI(
        title="Dwaar API",
        version=__version__,
        summary="Dwaar community operating platform, cloud API",
        description="Versioned under /v1. Errors follow PRD 12.2. Authorisation is derived on the server.",
        lifespan=lifespan,
        docs_url=None
        if not settings.simulation and settings.env.value == "production"
        else "/docs",
        redoc_url=None,
        responses=ERROR_RESPONSES,
    )
    permissions = PermissionRegistry(extra_permissions)
    app.state.settings = settings
    app.state.db = db
    app.state.permissions = permissions
    app.state.paginator = Paginator(settings.require_cursor_key(), settings.max_page_size)
    app.state.grant_resolver = DenyAllGrantResolver()
    app.state.identity_provider = OidcIdentityProvider.from_settings(settings)
    app.state.session_store = None
    app.state.body_limits = {}  # path prefix -> max body bytes (per-route overrides, see middleware)

    install_error_handlers(app)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "X-Request-ID",
                "X-Society-Id",
            ],
            expose_headers=["X-Request-ID", "Idempotent-Replayed", "Retry-After"],
        )
    app.add_middleware(
        BodySizeLimitMiddleware, default_limit=settings.max_request_body_bytes
    )  # 413 before the body is buffered, hashed or validated
    app.add_middleware(RequestContextMiddleware)  # outermost: even CORS responses get a request id

    app.include_router(health.router)
    load_modules(app, permissions, modules_package)

    if identity_provider is not None:
        app.state.identity_provider = identity_provider
    if session_store is not None:
        app.state.session_store = session_store
    if grant_resolver is not None:
        app.state.grant_resolver = grant_resolver

    provider = app.state.identity_provider
    if provider is not None and provider.simulation and not settings.simulation:
        raise ConfigError(
            "a simulator identity provider is only allowed when DWAAR_ENV is local or test"
        )
    if app.state.session_store is None and not settings.simulation:
        # IAM-08: without a session store revocation silently does nothing (fail open). Refuse to start.
        raise ConfigError(
            "a session store is required outside local/test (revocation, IAM-08); "
            "pass session_store= to create_app"
        )
    check_requirements(app, permissions)
    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    """Lazy ``app`` for ``uvicorn dwaar_api.main:app`` without import-time side effects."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
