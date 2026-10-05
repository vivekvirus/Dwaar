"""The labelled SIMULATOR identity issuer (local/test only) and the production adapter wiring.

REQ: IAM-14 (maintained OIDC/JWT library, no invented token formats: PyJWT, EdDSA/Ed25519, standard claims), IAM-08
(short-lived access tokens), BUILD_BRIEF section 3 (simulators only when DWAAR_ENV is local or test, always
``simulation=true``).

The simulator is a real OIDC issuer in miniature: an Ed25519 key, a JWKS document, a discovery document and tokens
carrying only the standard claims ``sub iss aud exp iat jti sid`` (+ ``typ`` and a ``simulation`` marker). It NEVER puts
roles, society ids or permissions in a token: authorisation is re-derived from the database (core.authz). Verification
goes through the SAME core ``JwtVerifier`` / ``OidcIdentityProvider`` path a real IdP uses; only the key source differs
(a static JWKS in-process instead of ``RemoteJwks``).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any, Final, Protocol

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm

from ...core.authn import JwtVerifier, OidcIdentityProvider, StaticJwks
from ...core.config import ConfigError, Settings
from .config import IdentityConfig

SIMULATION_CLAIM: Final = "simulation"


class TokenIssuer(Protocol):
    """Mints access tokens for an authenticated session. A real IdP integration implements this too."""

    @property
    def simulation(self) -> bool: ...

    def mint(self, person_id: uuid.UUID, session_id: uuid.UUID, *, ttl_seconds: int) -> str: ...


@dataclass
class SimulatorIssuer:
    """Ed25519 OIDC issuer. Key: ``DWAAR_SIM_ISSUER_KEY`` (PEM, base64) or a fresh ephemeral key per process."""

    issuer: str
    audience: str
    private_key: Ed25519PrivateKey
    kid: str = "dwaar-sim-1"
    simulation: bool = True

    @classmethod
    def create(cls, config: IdentityConfig, environ: dict[str, str] | None = None) -> SimulatorIssuer:
        env = os.environ if environ is None else environ
        pem_b64 = env.get("DWAAR_SIM_ISSUER_KEY", "")
        key: Ed25519PrivateKey
        if pem_b64:
            try:
                loaded = serialization.load_pem_private_key(base64.b64decode(pem_b64), password=None)
            except Exception:
                raise ConfigError("DWAAR_SIM_ISSUER_KEY is not a base64 PEM Ed25519 key") from None
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ConfigError("DWAAR_SIM_ISSUER_KEY must be an Ed25519 key")
            key = loaded
        else:
            key = Ed25519PrivateKey.generate()
        return cls(config.sim_issuer, config.audience, key)

    @property
    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(OKPAlgorithm.to_jwk(self.private_key.public_key()))
        jwk.update({"kid": self.kid, "alg": "EdDSA", "use": "sig"})
        return {"keys": [jwk]}

    def discovery(self, base_url: str) -> dict[str, Any]:
        base = base_url.rstrip("/")
        return {
            "issuer": self.issuer,
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": ["EdDSA"],
            "subject_types_supported": ["public"],
            "response_types_supported": ["token"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "jti", "sid"],
            SIMULATION_CLAIM: True,
            "description": "Dwaar local SIMULATOR issuer. Not a real identity provider.",
        }

    def mint(
        self,
        person_id: uuid.UUID,
        session_id: uuid.UUID,
        *,
        ttl_seconds: int,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        now = dt.datetime.now(dt.UTC)
        claims: dict[str, Any] = {
            "sub": str(person_id),
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(now.timestamp()),
            "exp": int(now.timestamp()) + ttl_seconds,
            "jti": str(uuid.uuid4()),
            "sid": str(session_id),
            SIMULATION_CLAIM: True,
        }
        claims.update(extra_claims or {})  # tests only: forged role claims must be ignored by the server
        return jwt.encode(
            claims, self.private_key, algorithm="EdDSA", headers={"kid": self.kid, "typ": "at+jwt"}
        )

    def provider(self, settings: Settings) -> OidcIdentityProvider:
        verifier = JwtVerifier(
            issuer=self.issuer,
            audience=self.audience,
            jwks=StaticJwks(self.jwks),
            algorithms=("EdDSA",),
            leeway_seconds=settings.oidc_leeway_seconds,
            max_lifetime_seconds=settings.access_token_max_lifetime_seconds,
        )
        return OidcIdentityProvider(verifier, name="dwaar-simulator", simulation=True)
