"""Identity and permissions module (IAM-01..IAM-14, PRD 5, ADR-0011).

Auto-discovered by ``dwaar_api.core.registry``: exposes ``router``, ``permissions`` and ``register``.

What it provides
----------------
* Schema (migrations 0130-0135, 0190): persons + encrypted vault, OTP challenges, sessions/devices with rotating refresh
  tokens, MFA factors (global, schema ``iam``, reachable only through reviewed SQL functions); memberships,
  verification cases, committee holds and role grants (society-owned, RLS).
* Auth: phone OTP -> tokens through a labelled SIMULATOR issuer (local/test) or a real OIDC provider (verification via the
  core ``JwtVerifier``), refresh rotation with reuse detection, session list/revoke, TOTP step-up.
* Authz: the database-backed ``GrantResolver`` and ``SessionStore`` of the core protocols, and the PRD 5.2 permission
  matrix registered as data.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI

from ...core.authz import DenyAllGrantResolver
from ...core.errors import register_society_scoped_unique
from . import matrix, routes_auth, routes_people
from .auth_service import AuthService
from .config import IdentityConfig
from .glue import PgGrantResolver, PgSessionStore
from .issuer import SimulatorIssuer, TokenIssuer
from .runtime import IdentityRuntime, oidc_router, sim_router

log = logging.getLogger("dwaar_api.identity")

# One live claim per (society, person, unit, kind): the collision is inside the caller's own society and own rows.
register_society_scoped_unique("memberships_live_claim_uq")

router = APIRouter()
router.include_router(routes_auth.router)
router.include_router(routes_people.router)

permissions = matrix.permissions


def register(app: FastAPI) -> None:
    """Wire the identity runtime into the app. Explicit ``create_app`` arguments still win (they are applied afterwards)."""
    settings = app.state.settings
    db = app.state.db
    config = IdentityConfig.from_environment(settings)
    issuer: TokenIssuer | None = None
    if app.state.identity_provider is None and config.simulation:
        simulator = SimulatorIssuer.create(config)
        app.state.identity_provider = simulator.provider(settings)
        issuer = simulator
        app.include_router(sim_router)
        app.include_router(oidc_router)
        log.warning("identity SIMULATOR issuer active (simulation=true): local/test only")
    app.state.identity = IdentityRuntime(db, config, AuthService(db, config, issuer), issuer)
    if app.state.session_store is None:
        app.state.session_store = PgSessionStore(db)
    if isinstance(app.state.grant_resolver, DenyAllGrantResolver):
        app.state.grant_resolver = PgGrantResolver(db, config)
