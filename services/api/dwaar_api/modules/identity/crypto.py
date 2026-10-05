"""Phone tokens, OTP hashes, vault encryption: thin, purpose-separated wrappers over dwaar_common.crypto.

REQ: ARCH-02, IAM-06, PRD 7.4 (field-level envelope encryption; salted keyed hashes for lookup).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

from dwaar_common.crypto import build_aad, keyed_hash, normalize_phone_in

from .config import IdentityConfig


def normalise_phone(raw: str) -> str:
    """E.164 +91 form or ``InvalidPhoneError``."""
    return normalize_phone_in(raw)


def phone_token(config: IdentityConfig, e164: str) -> str:
    return keyed_hash(e164, config.hmac_key, purpose="phone_token")


def rate_key(config: IdentityConfig, scope: str, value: str) -> str:
    """Opaque rate-limit key: never a raw phone, IP or token (ratelimit.py contract)."""
    return f"iam:{scope}:" + keyed_hash(value, config.hmac_key, purpose="rate_key")[:40]


def new_otp_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def otp_hash(config: IdentityConfig, token: str, challenge_id: uuid.UUID, code: str) -> str:
    return keyed_hash(f"{token}|{challenge_id}|{code}", config.hmac_key, purpose="otp_code")


def hashes_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def new_refresh_secret() -> str:
    return secrets.token_urlsafe(48)


def refresh_hash(config: IdentityConfig, secret: str) -> str:
    return keyed_hash(secret, config.hmac_key, purpose="refresh_token")


def vault_aad(person_id: uuid.UUID, field: str) -> bytes:
    return build_aad("person_vault", field, person_id)


def delivery_aad(delivery_id: uuid.UUID) -> bytes:
    return build_aad("otp_delivery", delivery_id)


def mfa_aad(person_id: uuid.UUID) -> bytes:
    return build_aad("mfa_factor", "totp", person_id)


def fingerprint(value: str) -> str:
    """Short non-reversible tag for logs/audit when something must be referenced without its value."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]
