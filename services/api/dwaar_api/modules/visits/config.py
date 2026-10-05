"""Visits module configuration: pass signing key, keyed-hash key, operational thresholds.

REQ: GATE-01 (signed QR: Ed25519 via dwaar_common.signing; 6-digit codes are rate-limited), GATE-13 / PRD 7.4 (the visitor
number is only ever a keyed hash, the visitor contact token), GATE-11 (overstay thresholds are configuration, INV-10),
ARCH-02 (keys come from the environment; local and test get clearly labelled placeholder keys, other environments get a
503 on the endpoints that need a key instead of a placeholder).

Environment variables (add them to ``.env.example`` when the platform owner next edits it; see ADR-0013):

* ``DWAAR_PASS_SIGNING_KEY``  Ed25519 seed, base64url, 32 bytes. Signs the QR of an invitation.
* ``DWAAR_PASS_KEY_ID``       optional key id (default: derived from the public key).
* ``DWAAR_VISITOR_HMAC_KEY``  base64url, 32 bytes. Keyed hash of visitor numbers and 6-digit codes.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.crypto import CryptoError, key_from_b64
from dwaar_common.signing import (
    SigningError,
    b64url_encode,
    check_key_id,
    key_id_for,
    private_key_from_b64,
)

from ...core.config import ConfigError, Settings

log = logging.getLogger("dwaar_api.visits")

# Local/test placeholders derived from a fixed label: NOT secrets, never accepted outside local/test.
_LOCAL_LABEL: Final = b"dwaar-local-development-only-visits-key"


def _local_bytes(purpose: str) -> bytes:
    return hashlib.sha256(_LOCAL_LABEL + b"|" + purpose.encode()).digest()


@dataclass(frozen=True)
class VisitsConfig:
    signing_key: Ed25519PrivateKey
    key_id: str
    hmac_key: bytes
    simulation: bool
    # 6-digit code redemption: attempts per (society, unit) and per (society, guard); the space is only 10**6
    code_unit_capacity: int = 10
    code_unit_refill_seconds: int = 300
    code_actor_capacity: int = 30
    code_actor_refill_seconds: int = 60
    max_stops_per_visit: int = 10
    max_windows_per_invitation: int = 62

    @classmethod
    def from_environment(
        cls, settings: Settings, environ: Mapping[str, str] | None = None
    ) -> VisitsConfig:
        env = os.environ if environ is None else environ
        simulation = settings.simulation
        try:
            raw_sign = env.get("DWAAR_PASS_SIGNING_KEY", "").strip()
            if raw_sign:
                signing_key = private_key_from_b64(raw_sign)
            elif simulation:
                signing_key = private_key_from_b64(b64url_encode(_local_bytes("pass-signing")))
            else:
                raise ConfigError("DWAAR_PASS_SIGNING_KEY is required")
            raw_hmac = env.get("DWAAR_VISITOR_HMAC_KEY", "").strip()
            if raw_hmac:
                hmac_key = key_from_b64(raw_hmac)
            elif simulation:
                hmac_key = _local_bytes("visitor-hmac")
            else:
                raise ConfigError("DWAAR_VISITOR_HMAC_KEY is required")
            key_id = env.get("DWAAR_PASS_KEY_ID", "").strip() or key_id_for(
                signing_key.public_key()
            )
            check_key_id(key_id)
        except (CryptoError, SigningError) as exc:
            raise ConfigError(f"invalid visits key configuration: {exc}") from None
        return cls(signing_key, key_id, hmac_key, simulation)
