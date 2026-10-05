"""Authentication framework: identity-provider adapter, session store protocol, OIDC/JWT verifier.

REQ: IAM-14 (maintained OIDC/JWT library, no invented token formats: PyJWT + JWKS), IAM-08 (short-lived
access tokens, revocation; sensitive actions re-check current grants, never JWT claims), IAM-13/INV-01
(roles and scope never come from the token).

What this module does NOT do: it never reads roles, society ids or permissions from the token. A
``Principal`` only says WHO the caller is. What the caller may do is decided by ``dwaar_api.core.authz``
from server-side grants. The identity module (slice 1, step 3) supplies the concrete ``IdentityProvider``
(labelled simulator issuer in local/test, a real OIDC IdP elsewhere) and the ``SessionStore``.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Final, NoReturn, Protocol, runtime_checkable

import jwt
from fastapi import Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWK, PyJWKClient, PyJWKClientConnectionError, PyJWKClientError, PyJWKSet

from dwaar_common.errors import DependencyUnavailable, Unauthenticated

from .config import ASYMMETRIC_JWT_ALGORITHMS, ConfigError, Settings

log = logging.getLogger("dwaar_api.authn")
MAX_TOKEN_LENGTH: Final = 8192
REQUIRED_CLAIMS: Final = ("exp", "iat", "sub", "iss", "aud")
DEFAULT_MAX_TOKEN_LIFETIME_SECONDS: Final = 3600


@dataclass(frozen=True)
class Principal:
    """The authenticated caller. Carries identity only, never roles or scope."""

    subject: str
    person_id: uuid.UUID
    session_id: str | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    simulation: bool = False


@runtime_checkable
class IdentityProvider(Protocol):
    """Adapter between a bearer token and a :class:`Principal`. Raise ``Unauthenticated`` on any failure."""

    @property
    def name(self) -> str: ...

    @property
    def simulation(self) -> bool:
        """True for the labelled simulator issuer. Refused at startup outside local/test."""
        ...

    def authenticate(self, bearer_token: str) -> Principal: ...


@runtime_checkable
class SessionStore(Protocol):
    """Server-side session/device state (revocation, IAM-02/IAM-08)."""

    def is_active(
        self, *, session_id: str | None, subject: str, issued_at: datetime | None
    ) -> bool: ...


class InMemorySessionStore:
    """Test/local session store: revoke one session or every token a subject got before a moment."""

    def __init__(self) -> None:
        self._revoked_sessions: set[str] = set()
        self._revoked_before: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def revoke_session(self, session_id: str) -> None:
        with self._lock:
            self._revoked_sessions.add(session_id)

    def revoke_subject_before(self, subject: str, moment: datetime) -> None:
        with self._lock:
            self._revoked_before[subject] = moment

    def is_active(
        self, *, session_id: str | None, subject: str, issued_at: datetime | None
    ) -> bool:
        with self._lock:
            if session_id is not None and session_id in self._revoked_sessions:
                return False
            cutoff = self._revoked_before.get(subject)
        return not (cutoff is not None and (issued_at is None or issued_at <= cutoff))


# --------------------------------------------------------------------------------------- JWKS sources
class JwksSource(Protocol):
    def signing_key(self, token: str, header: Mapping[str, Any]) -> Any:
        """Return the verification key for this token. Raise ``Unauthenticated`` if unknown."""
        ...


class StaticJwks:
    """A fixed JWK set (local simulator issuer, tests). Keys are selected by ``kid`` only."""

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        try:
            self._set = PyJWKSet.from_dict(dict(jwks))
        except Exception as exc:  # malformed JWKS is a configuration error
            raise ConfigError("invalid JWKS document") from exc
        self._by_kid: dict[str, PyJWK] = {k.key_id: k for k in self._set.keys if k.key_id}

    def signing_key(self, token: str, header: Mapping[str, Any]) -> Any:
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self._by_kid:
            raise Unauthenticated()
        return self._by_kid[kid].key


class RemoteJwks:
    """JWKS fetched from the identity provider's configured URL (never from token headers)."""

    def __init__(self, url: str, *, lifespan_seconds: int = 300, timeout_seconds: int = 5) -> None:
        self._client = PyJWKClient(
            url,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=lifespan_seconds,
            timeout=timeout_seconds,
        )

    def signing_key(self, token: str, header: Mapping[str, Any]) -> Any:
        if not isinstance(header.get("kid"), str):
            raise Unauthenticated()
        try:
            return self._client.get_signing_key_from_jwt(token).key
        except PyJWKClientConnectionError as exc:
            log.warning("jwks fetch failed", extra={"exc_type": type(exc).__name__})
            raise DependencyUnavailable(retry_after=5) from None
        except (PyJWKClientError, jwt.PyJWTError):
            raise Unauthenticated() from None


# --------------------------------------------------------------------------------------- verifier
@dataclass(frozen=True)
class VerifiedToken:
    claims: Mapping[str, Any]
    algorithm: str
    key_id: str | None


class JwtVerifier:
    """Verify an OIDC access token: signature, ``exp``, ``nbf``, ``aud``, ``iss`` all enforced.

    * The algorithm allow-list contains only asymmetric algorithms; ``none`` and ``HS*`` can never be
      configured, so algorithm-confusion attacks are impossible by construction.
    * Keys come from the configured :class:`JwksSource` by ``kid``; ``jku``/``x5u``/embedded ``jwk``
      headers are ignored.
    * ``iat`` is required and ``exp - iat`` may not exceed ``max_lifetime_seconds`` (default 1 h, IAM-08
      short-lived access tokens): the verifier itself enforces it, so a long-lived token from a
      misconfigured or compromised issuer is useless.
    * Every failure raises the same bare ``Unauthenticated`` (the reason goes to the log as a code).
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: JwksSource,
        algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA"),
        leeway_seconds: int = 30,
        max_lifetime_seconds: int = DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
    ) -> None:
        if not issuer or not audience:
            raise ConfigError("issuer and audience are required")
        if max_lifetime_seconds < 1:
            raise ConfigError("max_lifetime_seconds must be positive")
        bad = [a for a in algorithms if a not in ASYMMETRIC_JWT_ALGORITHMS]
        if bad or not algorithms:
            raise ConfigError(
                "JWT algorithms must be a non-empty subset of the asymmetric allow-list"
            )
        self.issuer = issuer
        self.audience = audience
        self._jwks = jwks
        self._algorithms = algorithms
        self._leeway = leeway_seconds
        self._max_lifetime = max_lifetime_seconds

    def verify(self, token: str) -> VerifiedToken:
        if (
            not isinstance(token, str)
            or not token
            or len(token) > MAX_TOKEN_LENGTH
            or token.count(".") != 2
        ):
            self._reject("malformed")
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            self._reject("malformed")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._algorithms:
            self._reject("alg_not_allowed")
        key = self._jwks.signing_key(token, header)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self._leeway,
                options={"require": list(REQUIRED_CLAIMS), "verify_signature": True},
            )
        except jwt.ExpiredSignatureError:
            self._reject("expired")
        except jwt.ImmatureSignatureError:
            self._reject("not_yet_valid")
        except jwt.InvalidAudienceError:
            self._reject("bad_audience")
        except jwt.InvalidIssuerError:
            self._reject("bad_issuer")
        except jwt.InvalidSignatureError:
            self._reject("bad_signature")
        except jwt.MissingRequiredClaimError:
            self._reject("missing_claim")
        except (
            Exception
        ):  # PyJWTError, but also TypeError/ValueError/crypto errors on key/algorithm mismatch
            self._reject("invalid")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            self._reject("bad_subject")
        issued, expires = claims.get("iat"), claims.get("exp")
        if (
            isinstance(issued, bool)
            or isinstance(expires, bool)
            or not isinstance(issued, int | float)
            or not isinstance(expires, int | float)
            or expires - issued > self._max_lifetime
        ):
            self._reject("lifetime_too_long")
        kid = header.get("kid")
        return VerifiedToken(claims, alg, kid if isinstance(kid, str) else None)

    @staticmethod
    def _reject(reason: str) -> NoReturn:
        log.info("token rejected", extra={"reason": reason})
        raise Unauthenticated()


SubjectMapper = Callable[[str, Mapping[str, Any]], uuid.UUID | None]


class OidcIdentityProvider:
    """``IdentityProvider`` for a standard OIDC issuer. ``sub`` is the person id (UUID) unless a mapper says otherwise."""

    def __init__(
        self,
        verifier: JwtVerifier,
        *,
        name: str = "oidc",
        simulation: bool = False,
        subject_mapper: SubjectMapper | None = None,
    ) -> None:
        self._verifier = verifier
        self._name = name
        self._simulation = simulation
        self._mapper = subject_mapper

    @property
    def name(self) -> str:
        return self._name

    @property
    def simulation(self) -> bool:
        return self._simulation

    @classmethod
    def from_settings(cls, settings: Settings) -> OidcIdentityProvider | None:
        """Real issuer from settings, or ``None`` when none is configured (local/test simulator case)."""
        if not settings.oidc_issuer_url or not settings.oidc_jwks_url:
            return None
        verifier = JwtVerifier(
            issuer=settings.oidc_issuer_url,
            audience=settings.oidc_audience,
            jwks=RemoteJwks(settings.oidc_jwks_url),
            algorithms=settings.jwt_algorithms,
            leeway_seconds=settings.oidc_leeway_seconds,
            max_lifetime_seconds=settings.access_token_max_lifetime_seconds,
        )
        return cls(verifier)

    def authenticate(self, bearer_token: str) -> Principal:
        verified = self._verifier.verify(bearer_token)
        claims = verified.claims
        subject = str(claims["sub"])
        person_id: uuid.UUID | None
        try:
            person_id = uuid.UUID(subject)
        except ValueError:
            person_id = self._mapper(subject, claims) if self._mapper else None
        if person_id is None:
            log.info("token rejected", extra={"reason": "unmapped_subject"})
            raise Unauthenticated()
        sid = claims.get("sid")
        return Principal(
            subject=subject,
            person_id=person_id,
            session_id=sid if isinstance(sid, str) else None,
            issued_at=_ts(claims.get("iat")),
            expires_at=_ts(claims.get("exp")),
            simulation=self._simulation,
        )


def _ts(value: Any) -> datetime | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=UTC)
    return None


# --------------------------------------------------------------------------------------- dependency
_bearer = HTTPBearer(
    auto_error=False, scheme_name="bearerAuth", description="OIDC access token (JWT)"
)


def current_principal(
    request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)]
) -> Principal:
    """FastAPI dependency: the authenticated caller, or 401 ``unauthenticated`` (fail closed)."""
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise Unauthenticated()
    provider: IdentityProvider | None = getattr(request.app.state, "identity_provider", None)
    if provider is None:
        log.error("no identity provider configured; refusing every request")
        raise Unauthenticated()
    principal = provider.authenticate(credentials.credentials)
    sessions: SessionStore | None = getattr(request.app.state, "session_store", None)
    if sessions is not None and not sessions.is_active(
        session_id=principal.session_id, subject=principal.subject, issued_at=principal.issued_at
    ):
        raise Unauthenticated()
    request.scope.setdefault("state", {})["principal_person"] = str(principal.person_id)
    return principal
