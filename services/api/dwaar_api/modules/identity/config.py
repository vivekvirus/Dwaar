"""Identity module configuration: keys, OTP/session timings, the labelled DLT template.

REQ: IAM-06 (OTP expiry, attempts, templates), IAM-08 (short-lived access tokens), ARCH-02 / SEC-02 (field encryption
keys come from the environment; local/test get clearly-labelled placeholder keys, every other environment refuses to
start without real ones), INV-10 (operational thresholds are configuration, not code).
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from dwaar_common.crypto import (
    CryptoError,
    EnvelopeCipher,
    KeyRing,
    key_from_b64,
    key_to_b64,
)

from ...core.config import ConfigError, Settings

# Local/test placeholders: derived from a fixed label, NOT secrets, never accepted outside local/test.
_LOCAL_LABEL: Final = b"dwaar-local-development-only-identity-key"


def _local_key(purpose: str) -> bytes:
    return hashlib.sha256(_LOCAL_LABEL + b"|" + purpose.encode()).digest()


@dataclass(frozen=True)
class IdentityConfig:
    """Everything the identity module reads from the environment, validated once at start."""

    keyring: KeyRing
    hmac_key: bytes
    simulation: bool
    sim_issuer: str = "urn:dwaar:simulator"
    audience: str = "dwaar-api"
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5
    otp_request_capacity: int = 3  # requests per phone per refill window
    otp_request_refill_seconds: int = 300
    otp_verify_capacity: int = 10
    otp_verify_refill_seconds: int = 120
    ip_capacity: int = 30
    ip_refill_seconds: int = 60
    access_ttl_seconds: int = 900
    refresh_ttl_seconds: int = 30 * 86_400
    max_sessions_per_person: int = 20
    mfa_ttl_seconds: int = 8 * 3600
    phone_dormancy_days: int = 90
    dlt_template_id: str = "SIM-DLT-OTP-LOGIN"
    dlt_template_text_key: str = "iam.otp.sms"
    membership_request_capacity: int = 10  # applications per person per refill window
    membership_request_refill_seconds: int = 3600

    @property
    def cipher(self) -> EnvelopeCipher:
        return EnvelopeCipher(self.keyring)

    @classmethod
    def from_environment(
        cls, settings: Settings, environ: Mapping[str, str] | None = None
    ) -> IdentityConfig:
        env = os.environ if environ is None else environ
        simulation = settings.simulation
        try:
            keys, active = env.get("DWAAR_PII_KEYS", ""), env.get("DWAAR_PII_ACTIVE_KEY_ID", "")
            if keys and active:
                keyring = KeyRing.from_env_value(keys, active)
            elif simulation:
                keyring = KeyRing({"local-dev": _local_key("pii")}, "local-dev")
            else:
                raise ConfigError("DWAAR_PII_KEYS and DWAAR_PII_ACTIVE_KEY_ID are required")
            hmac_raw = env.get("DWAAR_PHONE_HMAC_KEY", "")
            if hmac_raw:
                hmac_key = key_from_b64(hmac_raw)
            elif simulation:
                hmac_key = _local_key("hmac")
            else:
                raise ConfigError("DWAAR_PHONE_HMAC_KEY is required")
        except CryptoError as exc:
            raise ConfigError(f"invalid identity key configuration: {exc}") from None

        def number(name: str, default: int, low: int, high: int) -> int:
            raw = env.get(f"DWAAR_{name}")
            if raw is None or not raw.strip():
                return default
            try:
                value = int(raw)
            except ValueError:
                raise ConfigError(f"DWAAR_{name} must be an integer") from None
            if not low <= value <= high:
                raise ConfigError(f"DWAAR_{name} must be between {low} and {high}")
            return value

        return cls(
            keyring=keyring,
            hmac_key=hmac_key,
            simulation=simulation,
            sim_issuer=env.get("DWAAR_SIM_ISSUER", "urn:dwaar:simulator"),
            audience=settings.oidc_audience,
            otp_ttl_seconds=number("OTP_TTL_SECONDS", 300, 60, 900),
            otp_max_attempts=number("OTP_MAX_ATTEMPTS", 5, 1, 10),
            access_ttl_seconds=min(
                number("ACCESS_TOKEN_TTL_SECONDS", 900, 60, 3600),
                settings.access_token_max_lifetime_seconds,
            ),
            refresh_ttl_seconds=number("REFRESH_TOKEN_TTL_SECONDS", 30 * 86_400, 3600, 90 * 86_400),
            mfa_ttl_seconds=number("MFA_TTL_SECONDS", 8 * 3600, 300, 24 * 3600),
            phone_dormancy_days=number("PHONE_DORMANCY_DAYS", 90, 7, 3650),
            dlt_template_id=env.get("DWAAR_OTP_DLT_TEMPLATE_ID", "SIM-DLT-OTP-LOGIN"),
        )


def generate_local_key_b64() -> str:
    """Helper for docs and tests: a fresh random 32-byte key in the env-var format."""
    from dwaar_common.crypto import generate_key

    return key_to_b64(generate_key())
