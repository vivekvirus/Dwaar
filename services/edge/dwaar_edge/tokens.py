"""Signed terminal device tokens (issued at commissioning; local API only).

Token text: ``<base64url(canonical JSON)>.<ed25519:signature>`` signed by the gateway's token key. A token names
one device and one role; it expires; it can be revoked (``terminal_tokens``). There is no inbound internet port:
the API is bound to the security LAN.
"""

# REQ: EDGE-01, EDGE-09

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.events import canonical_json
from dwaar_common.signing import (
    SigningError,
    b64url_decode,
    b64url_encode,
    sign_bytes,
    verify_bytes,
)

TOKEN_TYPE: Final = "dwaar.terminal"  # noqa: S105  (a type label, not a secret)
Role = Literal["guard", "supervisor", "admin"]
ROLES: Final = ("guard", "supervisor", "admin")


@dataclass(frozen=True)
class TokenClaims:
    device_id: uuid.UUID
    role: Role
    jti: uuid.UUID
    society_id: uuid.UUID
    expires_at: datetime


def mint(
    key: Ed25519PrivateKey,
    *,
    society_id: uuid.UUID,
    device_id: uuid.UUID,
    role: Role,
    jti: uuid.UUID,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    body = canonical_json(
        {
            "typ": TOKEN_TYPE,
            "v": 1,
            "sid": str(society_id),
            "did": str(device_id),
            "role": role,
            "jti": str(jti),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
    )
    return f"{b64url_encode(body)}.{sign_bytes(key, body)}"


def parse(token: str, key: Ed25519PrivateKey) -> TokenClaims | None:
    """Verified claims, or None for ANY problem (never raises). Expiry and revocation are checked by the caller."""
    try:
        if len(token) > 1000 or token.count(".") != 1:
            return None
        body_part, signature = token.split(".", 1)
        body = b64url_decode(body_part)
        if not verify_bytes(key.public_key(), body, signature):
            return None
        data = json.loads(body)
        if data.get("typ") != TOKEN_TYPE or data.get("v") != 1 or data.get("role") not in ROLES:
            return None
        return TokenClaims(
            device_id=uuid.UUID(data["did"]),
            role=data["role"],
            jti=uuid.UUID(data["jti"]),
            society_id=uuid.UUID(data["sid"]),
            expires_at=datetime.fromtimestamp(int(data["exp"]), UTC),
        )
    except (SigningError, ValueError, KeyError, TypeError, AttributeError):
        return None
