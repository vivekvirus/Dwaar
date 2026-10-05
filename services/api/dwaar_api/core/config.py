"""Environment-driven configuration (fail closed).

REQ: ARCH-03/ARCH-04 (restricted DB role; secrets only from the environment), IAM-14 (OIDC settings),
BUILD_BRIEF section 3 (simulators only when DWAAR_ENV is local or test).

Rules:
* ``DWAAR_ENV`` is mandatory (local | test | staging | production). There is no implicit default.
* Local development defaults (database URLs, signing key, ...) exist ONLY when ``DWAAR_ENV=local``.
  In every other environment a missing required value is a startup error that names the variable
  (never its value).
* The API role must not be the owner or a superuser (never connect the API as ``dwaar_owner``).
* Secrets are ``SecretStr`` and never appear in ``repr`` or in error messages.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from enum import StrEnum
from functools import lru_cache
from typing import Any, Final

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class ConfigError(Exception):
    """Invalid or incomplete configuration. The message never contains secret values."""


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def allows_simulators(self) -> bool:
        return self in (Environment.LOCAL, Environment.TEST)


ASYMMETRIC_JWT_ALGORITHMS: Final = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

# Placeholders for DWAAR_ENV=local ONLY. Not secrets: the local cluster is trust-auth on 127.0.0.1.
_LOCAL_DEFAULTS: Final[Mapping[str, str]] = {
    "database_url": "postgresql://dwaar_app:dwaar-local-app@127.0.0.1:55432/dwaar",
    "database_worker_url": "postgresql://dwaar_worker:dwaar-local-worker@127.0.0.1:55432/dwaar",
    "cursor_signing_key": "local-only-cursor-signing-key-not-a-secret",
}

_FORBIDDEN_API_DB_USERS: Final = frozenset({"dwaar_owner", "postgres", "postgresql", "root"})


class Settings(BaseSettings):
    """All API settings. Construct via :func:`load_settings` in production code."""

    model_config = SettingsConfigDict(env_prefix="DWAAR_", extra="ignore", case_sensitive=False)

    env: Environment
    log_level: str = "INFO"

    database_url: SecretStr | None = None
    database_worker_url: SecretStr | None = None
    # Owner URL is used by the migration CLI only; the API process never needs (or uses) it.
    database_owner_url: SecretStr | None = None
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=10, ge=0, le=100)
    db_statement_timeout_ms: int = Field(default=30_000, ge=100, le=600_000)
    db_lock_timeout_ms: int = Field(default=15_000, ge=100, le=600_000)

    cors_origins: str = ""

    oidc_issuer_url: str = ""
    oidc_audience: str = "dwaar-api"
    oidc_jwks_url: str = ""
    oidc_algorithms: str = "RS256,ES256,EdDSA"
    oidc_leeway_seconds: int = Field(default=30, ge=0, le=300)
    # IAM-08: access tokens are short-lived; the verifier rejects exp - iat above this (default 1 h).
    access_token_max_lifetime_seconds: int = Field(default=3600, ge=60, le=86_400)

    cursor_signing_key: SecretStr | None = None
    # Request body size limit (413 above it). Modules may raise it for one path prefix via
    # app.state.body_limits; the reverse proxy must enforce its own limit too.
    max_request_body_bytes: int = Field(default=1_048_576, ge=1_024, le=64 * 1_048_576)
    idempotency_ttl_seconds: int = Field(default=7 * 86_400, ge=60, le=30 * 86_400)
    max_page_size: int = Field(default=100, ge=1, le=100)
    max_date_range_days: int = Field(default=92, ge=1, le=3660)

    @field_validator("log_level")
    @classmethod
    def _log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        return level

    @field_validator("oidc_algorithms")
    @classmethod
    def _algorithms(cls, value: str) -> str:
        names = [a.strip() for a in value.split(",") if a.strip()]
        if not names:
            raise ValueError("oidc_algorithms must not be empty")
        bad = [a for a in names if a not in ASYMMETRIC_JWT_ALGORITHMS]
        if bad:
            raise ValueError(
                "oidc_algorithms may only contain asymmetric algorithms (no none, no HS*)"
            )
        return ",".join(names)

    @model_validator(mode="after")
    def _apply_environment_rules(self) -> Settings:
        missing: list[str] = []
        if self.env is Environment.LOCAL:
            for name, default in _LOCAL_DEFAULTS.items():
                if getattr(self, name) is None:
                    setattr(self, name, SecretStr(default))
        else:
            for name in ("database_url", "cursor_signing_key"):
                if getattr(self, name) is None:
                    missing.append(f"DWAAR_{name.upper()}")
            if not self.env.allows_simulators:
                if not self.oidc_issuer_url:
                    missing.append("DWAAR_OIDC_ISSUER_URL")
                if not self.oidc_jwks_url:
                    missing.append("DWAAR_OIDC_JWKS_URL")
                if not self.cors_origins:
                    missing.append("DWAAR_CORS_ORIGINS")
        if missing:
            raise ValueError("missing required settings: " + ", ".join(sorted(missing)))
        for label, secret in (
            ("DWAAR_DATABASE_URL", self.database_url),
            ("DWAAR_DATABASE_WORKER_URL", self.database_worker_url),
        ):
            if secret is not None:
                _check_app_role(label, secret.get_secret_value())
        if (
            self.oidc_issuer_url
            and not self.oidc_issuer_url.startswith("https://")
            and not self.env.allows_simulators
        ):
            raise ValueError("DWAAR_OIDC_ISSUER_URL must be https outside local/test")
        if (
            self.oidc_jwks_url
            and not self.oidc_jwks_url.startswith("https://")
            and not self.env.allows_simulators
        ):
            # Whoever can alter the JWKS fetch can swap the signing keys and mint tokens for any person.
            raise ValueError("DWAAR_OIDC_JWKS_URL must be https outside local/test")
        if not self.env.allows_simulators and self.cursor_signing_key is not None:
            _check_cursor_key(self.cursor_signing_key.get_secret_value())
        if "*" in self.cors_origin_list:
            raise ValueError("DWAAR_CORS_ORIGINS must list explicit origins, never '*'")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def jwt_algorithms(self) -> tuple[str, ...]:
        return tuple(a for a in self.oidc_algorithms.split(",") if a)

    @property
    def simulation(self) -> bool:
        """True when simulators are permitted (labelled simulation=true everywhere they appear)."""
        return self.env.allows_simulators

    def require_cursor_key(self) -> bytes:
        if self.cursor_signing_key is None:  # unreachable after validation; belt and braces
            raise ConfigError("DWAAR_CURSOR_SIGNING_KEY is required")
        return self.cursor_signing_key.get_secret_value().encode("utf-8")


MIN_CURSOR_KEY_CHARS: Final = 32
MIN_CURSOR_KEY_DISTINCT: Final = 12


def _check_cursor_key(value: str) -> None:
    """Cursors are HMAC-signed with this key: a short or repetitive key can be brute-forced and cursors forged.

    The message never contains the value. Generate one with ``python -c "import secrets; print(secrets.token_urlsafe(32))"``.
    """
    if len(value) < MIN_CURSOR_KEY_CHARS or len(set(value)) < MIN_CURSOR_KEY_DISTINCT:
        raise ValueError(
            f"DWAAR_CURSOR_SIGNING_KEY must be at least {MIN_CURSOR_KEY_CHARS} random characters "
            "outside local/test (for example secrets.token_urlsafe(32))"
        )


def _check_app_role(label: str, url: str) -> None:
    try:
        user = make_url(url).username
    except Exception as exc:  # malformed URL; do not echo it (it may contain a password)
        raise ValueError(f"{label} is not a valid database URL") from exc
    if user is None or user.lower() in _FORBIDDEN_API_DB_USERS:
        raise ValueError(
            f"{label} must use the restricted application role, never the owner or a superuser"
        )


def load_settings(environ: Mapping[str, str] | None = None, **overrides: Any) -> Settings:
    """Build :class:`Settings` from ``environ`` (default ``os.environ``) plus keyword overrides.

    Raises :class:`ConfigError` with a message that lists problems by variable name only.
    """
    source = os.environ if environ is None else environ
    values: dict[str, Any] = {}
    prefix = "DWAAR_"
    for key, raw in source.items():
        if key.upper().startswith(prefix):
            values[key[len(prefix) :].lower()] = raw
    values.update(overrides)
    if "env" not in values or not str(values["env"]).strip():
        raise ConfigError("DWAAR_ENV must be set to one of: local, test, staging, production")
    # Bypass pydantic-settings' own env reading so ``environ`` is the single source of truth.
    try:
        return Settings.model_validate(values)
    except ValidationError as exc:
        problems = []
        for err in exc.errors(include_input=False, include_url=False):
            where = ".".join(str(p) for p in err["loc"]) or "settings"
            problems.append(f"{where}: {err['msg']}")
        raise ConfigError("invalid configuration: " + "; ".join(problems)) from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings from the real environment (cached; ``get_settings.cache_clear()`` in tests)."""
    return load_settings()
