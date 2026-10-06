"""Guest pass QR parsing on the edge (same wire format the cloud visits module issues).

QR text: ``<base64url(canonical JSON)>.<ed25519:signature>``; members v, typ, iid, sid, n, nbf, exp, kid, g(optional).
The gateway verifies the signature with a provisioned PASS public key. If no key for ``kid`` is provisioned the
signature is reported as unchecked (``None``): the pass is then only as strong as its secret nonce matching the
signed policy snapshot, and the decision evidence says so.
"""

# REQ: GATE-01, EDGE-05

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from dwaar_common.signing import SigningError, b64url_decode, verify_bytes

from .decision import GuestPass

QR_TYPE: Final = "dwaar.pass"
MAX_QR_CHARS: Final = 2000


def parse_qr(
    text: str, pass_keys: Mapping[str, Ed25519PublicKey], society_id: uuid.UUID
) -> tuple[GuestPass, uuid.UUID | None] | None:
    """(GuestPass, qr_gate_id) or None for anything malformed. A society mismatch returns None too."""
    try:
        if len(text) > MAX_QR_CHARS or text.count(".") != 1:
            return None
        body_part, signature = text.split(".", 1)
        body = b64url_decode(body_part)
        data = json.loads(body)
        if not isinstance(data, dict) or data.get("v") != 1 or data.get("typ") != QR_TYPE:
            return None
        if uuid.UUID(str(data["sid"])) != society_id:
            return None
        kid = data.get("kid")
        key = pass_keys.get(kid) if isinstance(kid, str) else None
        sig_ok: bool | None = None if key is None else verify_bytes(key, body, signature)
        nonce = data["n"]
        nbf, exp = data["nbf"], data["exp"]
        if not isinstance(nonce, str) or isinstance(nbf, bool) or isinstance(exp, bool):
            return None
        gate = data.get("g")
        return (
            GuestPass(
                invitation_id=uuid.UUID(str(data["iid"])),
                nonce=nonce,
                qr_signature_ok=sig_ok,
                qr_not_before=datetime.fromtimestamp(int(nbf), UTC),
                qr_expires=datetime.fromtimestamp(int(exp), UTC),
            ),
            uuid.UUID(str(gate)) if gate is not None else None,
        )
    except (SigningError, ValueError, KeyError, TypeError, OverflowError, OSError):
        return None
