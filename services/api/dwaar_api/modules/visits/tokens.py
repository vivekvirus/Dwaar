"""Signed pass (QR) payloads, 6-digit codes and the visitor contact token.

REQ: GATE-01 (the QR is an Ed25519-signed payload that carries OPAQUE ids, an expiry and a nonce, and NO phone number or
address; 6-digit codes are hashed and never a free bearer credential), GATE-13 / PRD 7.4 (the visitor number is stored only
as a keyed hash), EDGE-04 spirit (``dwaar_common.signing``; verification never raises on bad input).

QR text:  ``<base64url(canonical JSON payload)>.<ed25519:signature>``.  Payload members::

    v    format version (1)            typ  "dwaar.pass"
    iid  invitation id (UUIDv7)        sid  society id
    n    nonce (random, also stored)   nbf  not-before (epoch seconds)   exp  expiry (epoch seconds)
    kid  signing key id                g    gate id when the pass is gate-bound (optional)

Nothing in the payload names a person, a phone, a unit label or an address. The server still checks the pass against the
database (state, revocation version, windows, uses): the signature proves who issued the text, the database decides.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Final

from dwaar_common.crypto import InvalidPhoneError, keyed_hash, normalize_phone_in
from dwaar_common.errors import InvalidSchema
from dwaar_common.events import canonical_json
from dwaar_common.signing import (
    SigningError,
    b64url_decode,
    b64url_encode,
    sign_bytes,
    verify_bytes,
)

from .config import VisitsConfig

QR_TYPE: Final = "dwaar.pass"
QR_VERSION: Final = 1
MAX_QR_CHARS: Final = 2000


@dataclass(frozen=True)
class PassPayload:
    invitation_id: uuid.UUID
    society_id: uuid.UUID
    nonce: str
    not_before: int
    expires: int
    key_id: str
    gate_id: uuid.UUID | None


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def build_qr(
    cfg: VisitsConfig,
    *,
    invitation_id: uuid.UUID,
    society_id: uuid.UUID,
    nonce: str,
    not_before: dt.datetime,
    expires: dt.datetime,
    gate_id: uuid.UUID | None,
) -> str:
    payload: dict[str, Any] = {
        "v": QR_VERSION,
        "typ": QR_TYPE,
        "iid": str(invitation_id),
        "sid": str(society_id),
        "n": nonce,
        "nbf": int(not_before.timestamp()),
        "exp": int(expires.timestamp()),
        "kid": cfg.key_id,
    }
    if gate_id is not None:
        payload["g"] = str(gate_id)
    body = canonical_json(payload)
    return f"{b64url_encode(body)}.{sign_bytes(cfg.signing_key, body)}"


def parse_qr(cfg: VisitsConfig, text: str) -> PassPayload | None:
    """The verified payload, or ``None`` for ANY problem (malformed, wrong key, wrong type, bad member). Never raises."""
    try:
        if len(text) > MAX_QR_CHARS or text.count(".") != 1:
            return None
        body_part, signature = text.split(".", 1)
        body = b64url_decode(body_part)
        if not verify_bytes(cfg.signing_key.public_key(), body, signature):
            return None
        data = json.loads(body)
        if (
            not isinstance(data, dict)
            or data.get("v") != QR_VERSION
            or data.get("typ") != QR_TYPE
            or data.get("kid") != cfg.key_id
        ):
            return None
        gate = data.get("g")
        nbf, exp = data["nbf"], data["exp"]
        if isinstance(nbf, bool) or isinstance(exp, bool) or not isinstance(nbf, int | float):
            return None
        if not isinstance(exp, int | float) or not isinstance(data["n"], str):
            return None
        return PassPayload(
            uuid.UUID(str(data["iid"])),
            uuid.UUID(str(data["sid"])),
            data["n"],
            int(nbf),
            int(exp),
            str(data["kid"]),
            uuid.UUID(str(gate)) if gate is not None else None,
        )
    except (SigningError, ValueError, KeyError, TypeError, AttributeError):
        return None


def contact_token(cfg: VisitsConfig, society_id: uuid.UUID, phone: str) -> str:
    """Keyed hash of the visitor number, scoped to the society (the same number in two societies gives two tokens).
    The number is validated and then dropped; it is never stored or logged."""
    try:
        e164 = normalize_phone_in(phone)
    except InvalidPhoneError:
        raise InvalidSchema.for_fields([("visitor_phone", "invalid_phone")]) from None
    return keyed_hash(f"{society_id}|{e164}", cfg.hmac_key, purpose="visitor_contact_token")


def code_hash(
    cfg: VisitsConfig,
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    invitation_id: uuid.UUID,
    code: str,
) -> str:
    return keyed_hash(
        f"{society_id}|{unit_id}|{invitation_id}|{code}", cfg.hmac_key, purpose="invite_code"
    )
