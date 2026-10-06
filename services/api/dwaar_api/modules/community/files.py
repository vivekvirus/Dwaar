"""Upload validation and signed download tokens (COM-04, SEC-03, SEC-04).

REQ: SEC-03 (uploads type- and size-validated), SEC-04 (short-lived signed URLs issued after current access checks; URL
possession never grants permanent access).

Type validation checks the DECLARED ``Content-Type`` against the BYTES (magic numbers; text must be strict UTF-8 without NUL):
a PDF-named executable or a type that disagrees with its content is refused. Allowed: PDF, PNG, JPEG, plain text, CSV. There is
no archive type, so no archive extraction exists to attack (SEC-03 decompression and traversal concerns are out of scope by
construction).

A download token is ``b64url(payload).b64url(HMAC-SHA256)`` with ``{v, sid, vid, pid, sess, exp, n}``: society, version, person,
session, expiry and a random nonce. It names no file path and no storage key. Expiry is in the token; use re-checks the person's
CURRENT access (see ``routes_documents.redeem``), so revoking a membership or withdrawing the version kills outstanding URLs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Final

from dwaar_common.errors import InvalidSchema

ALLOWED: Final = {"application/pdf", "image/png", "image/jpeg", "text/plain", "text/csv"}
_FILENAME: Final = re.compile(r"[^A-Za-z0-9._ -]")


def safe_filename(name: str | None) -> str:
    """Display name only: never a path (no directory part, no control characters, bounded)."""
    base = (name or "document").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _FILENAME.sub("_", base).strip(" .")[:120]
    return cleaned or "document"


def sniff(data: bytes) -> str | None:
    """The media type the BYTES actually are, or None when not an allowed type."""
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if b"\x00" not in data:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return "text/plain"  # text and CSV are indistinguishable by content; the declared type decides between them
    return None


def validate_upload(data: bytes, declared: str | None, max_bytes: int) -> str:
    if not data:
        raise InvalidSchema.for_fields([("body", "empty_file")])
    if len(data) > max_bytes:
        raise InvalidSchema(details={"reason": "payload_too_large", "max_bytes": max_bytes})
    kind = (declared or "").split(";", 1)[0].strip().lower()
    if kind not in ALLOWED:
        raise InvalidSchema.for_fields([("content_type", "unsupported_type")])
    seen = sniff(data)
    ok = seen == kind or (seen == "text/plain" and kind == "text/csv")
    if not ok:
        raise InvalidSchema.for_fields([("content_type", "content_does_not_match_type")])
    return kind


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class DownloadClaim:
    society_id: uuid.UUID
    version_id: uuid.UUID
    person_id: uuid.UUID
    session_id: str | None
    expires_at: int


def issue_token(key: bytes, claim: DownloadClaim) -> str:
    payload = json.dumps(
        {"v": 1, "sid": str(claim.society_id), "vid": str(claim.version_id), "pid": str(claim.person_id),
         "sess": claim.session_id, "exp": claim.expires_at, "n": secrets.token_urlsafe(8)},
        separators=(",", ":"), sort_keys=True,
    ).encode()  # fmt: skip
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{_b64(payload)}.{_b64(mac)}"


def read_token(key: bytes, token: str, now: int) -> DownloadClaim | None:
    """The claim of a genuine, unexpired token, else None (every failure looks the same to the caller)."""
    try:
        body, sig = token.split(".", 1)
        payload = _unb64(body)
        if not hmac.compare_digest(_unb64(sig), hmac.new(key, payload, hashlib.sha256).digest()):
            return None
        data = json.loads(payload)
        if data.get("v") != 1 or not isinstance(data.get("exp"), int) or data["exp"] <= now:
            return None
        return DownloadClaim(
            uuid.UUID(data["sid"]),
            uuid.UUID(data["vid"]),
            uuid.UUID(data["pid"]),
            data.get("sess"),
            data["exp"],
        )
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        return None
