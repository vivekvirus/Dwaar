"""Ed25519 signing of canonical event envelopes and policy snapshots.

REQ: EDGE-02 (signature field), EDGE-04 (signed policy snapshots, issuer key ID).

Signature wire format: ``ed25519:<base64url, no padding>`` of the 64-byte signature.
Key IDs are opaque short strings (`[A-Za-z0-9._-]{1,64}`) carried next to the signature
by the caller (for snapshots: the issuer key ID); `key_id_for` derives a stable ID from a
public key. Verification never raises on bad input: it returns False.
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from dwaar_common.events import EdgeEvent, canonical_json

SIGNATURE_PREFIX: Final = "ed25519:"
KEY_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SIGNATURE_LEN: Final = 64


class SigningError(ValueError):
    """Malformed key, key ID or signature."""


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strict base64url decode: alphabet, no padding AND canonical (re-encoding gives the same text).

    Plain base64 decoders ignore the unused trailing bits of the last character, so several different
    strings would decode to the same bytes (signature malleability); those are rejected here.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise SigningError("not base64url (no padding)")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:  # binascii.Error (impossible length) is a ValueError
        raise SigningError("not base64url") from exc
    if b64url_encode(raw) != text:
        raise SigningError("non-canonical base64url encoding")
    return raw


def check_key_id(key_id: str) -> str:
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.match(key_id):
        raise SigningError("key id must match [A-Za-z0-9._-]{1,64}")
    return key_id


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_b64(key: Ed25519PrivateKey) -> str:
    """32-byte seed as base64url (for env/KMS storage; treat as a secret)."""
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return b64url_encode(raw)


def private_key_from_b64(text: str) -> Ed25519PrivateKey:
    raw = b64url_decode(text)
    if len(raw) != 32:
        raise SigningError("Ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_to_b64(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64url_encode(raw)


def public_key_from_b64(text: str) -> Ed25519PublicKey:
    raw = b64url_decode(text)
    if len(raw) != 32:
        raise SigningError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """Stable key ID: ``ed-`` + first 16 hex chars of SHA-256 over the raw public key."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed-" + hashlib.sha256(raw).hexdigest()[:16]


def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign raw bytes; returns ``ed25519:<b64url>``."""
    return SIGNATURE_PREFIX + b64url_encode(private_key.sign(data))


def parse_signature(signature: str) -> bytes:
    """Decode a signature string to its 64 raw bytes; raises SigningError if malformed."""
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        raise SigningError("signature must start with 'ed25519:'")
    raw = b64url_decode(signature[len(SIGNATURE_PREFIX) :])
    if len(raw) != _SIGNATURE_LEN:
        raise SigningError("Ed25519 signature must be 64 bytes")
    return raw


def verify_bytes(public_key: Ed25519PublicKey, data: bytes, signature: str | None) -> bool:
    """True only if `signature` is a well-formed valid signature of `data`."""
    if signature is None:
        return False
    try:
        raw = parse_signature(signature)
        public_key.verify(raw, data)
    except (SigningError, InvalidSignature, ValueError):
        return False
    return True


def sign_envelope(private_key: Ed25519PrivateKey, envelope: Mapping[str, Any]) -> str:
    """Sign the canonical JSON of a dict, ignoring any `signature` member."""
    body = {k: v for k, v in envelope.items() if k != "signature"}
    return sign_bytes(private_key, canonical_json(body))


def verify_envelope(
    public_key: Ed25519PublicKey, envelope: Mapping[str, Any], signature: str | None = None
) -> bool:
    body = {k: v for k, v in envelope.items() if k != "signature"}
    sig = signature if signature is not None else envelope.get("signature")
    return verify_bytes(public_key, canonical_json(body), sig if isinstance(sig, str) else None)


def sign_edge_event(private_key: Ed25519PrivateKey, event: EdgeEvent) -> EdgeEvent:
    """Return a copy of `event` carrying a signature over its canonical envelope-minus-signature."""
    return event.with_signature(sign_bytes(private_key, event.signing_bytes()))


def verify_edge_event(public_key: Ed25519PublicKey, event: EdgeEvent) -> bool:
    """Signature valid, payload_hash consistent with payload, and ``occurred_at`` exactly representable in
    the signed (millisecond) form: a sub-millisecond difference would otherwise share one valid signature."""
    return (
        event.has_signable_timestamp()
        and event.payload_hash_matches()
        and verify_bytes(public_key, event.signing_bytes(), event.signature)
    )


@dataclass(frozen=True)
class Signer:
    """A private key bound to its key ID."""

    key_id: str
    private_key: Ed25519PrivateKey = field(repr=False)

    def __post_init__(self) -> None:
        check_key_id(self.key_id)

    @classmethod
    def generate(cls, key_id: str | None = None) -> Signer:
        key = generate_private_key()
        return cls(key_id or key_id_for(key.public_key()), key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def sign_event(self, event: EdgeEvent) -> EdgeEvent:
        return sign_edge_event(self.private_key, event)

    def sign_envelope(self, envelope: Mapping[str, Any]) -> str:
        return sign_envelope(self.private_key, envelope)


class VerifierRing:
    """Public keys by key ID, with revocation and optional tenant binding.

    Unknown or revoked key IDs never verify. A key registered with ``society_id`` (and optionally
    ``device_id``) verifies ONLY events that claim exactly that society/device, so a compromised device
    key cannot forge events for another tenant (INV-01). A key registered without a binding is a
    platform-wide key (for example the policy issuer); with ``require_binding=True`` such keys never
    verify events, which is how the edge-sync endpoint should construct its ring.
    """

    def __init__(
        self,
        keys: Mapping[str, Ed25519PublicKey] | None = None,
        *,
        require_binding: bool = False,
    ) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._bindings: dict[str, tuple[uuid.UUID | None, uuid.UUID | None]] = {}
        self._revoked: set[str] = set()
        self._require_binding = require_binding
        for key_id, key in (keys or {}).items():
            self.add(key_id, key)

    def add(
        self,
        key_id: str,
        key: Ed25519PublicKey,
        *,
        society_id: uuid.UUID | None = None,
        device_id: uuid.UUID | None = None,
    ) -> None:
        if device_id is not None and society_id is None:
            raise SigningError("a device binding needs its society_id")
        check_key_id(key_id)
        self._keys[key_id] = key
        self._bindings[key_id] = (society_id, device_id)

    def revoke(self, key_id: str) -> None:
        self._revoked.add(key_id)

    def has(self, key_id: str) -> bool:
        return key_id in self._keys and key_id not in self._revoked

    def verify_event(self, key_id: str, event: EdgeEvent) -> bool:
        if not self.has(key_id):
            return False
        society, device = self._bindings[key_id]
        if society is None and self._require_binding:
            return False
        if society is not None and event.society_id != society:
            return False
        if device is not None and event.device_id != device:
            return False
        return verify_edge_event(self._keys[key_id], event)

    def verify_envelope(
        self, key_id: str, envelope: Mapping[str, Any], signature: str | None = None
    ) -> bool:
        if not self.has(key_id):
            return False
        return verify_envelope(self._keys[key_id], envelope, signature)
