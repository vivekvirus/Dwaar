"""Field-level envelope encryption, keyed lookup hashes and phone normalisation.

REQ: PRD privacy/PII design (person_vault field encryption, phone lookup token),
INV-01 (AAD binds ciphertext to its society/table/column/row so values cannot be moved).

Ciphertext format: ``v1:<key_id>:<nonce b64url>:<ciphertext+tag b64url>`` (AES-256-GCM,
96-bit random nonce, AAD supplied by the caller). Key rotation: new writes use the
ring's active key; old keys stay decrypt-only until `rotate` has re-encrypted every value.
The master keys come from the environment (simulated KMS adapter) via `KeyRing.from_env_value`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Mapping
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CIPHERTEXT_VERSION: Final = "v1"
KEY_BYTES: Final = 32
NONCE_BYTES: Final = 12
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class CryptoError(Exception):
    """Base class for crypto failures. Messages never contain plaintext or key material."""


class DecryptionError(CryptoError):
    """Ciphertext is malformed, uses an unknown key, was tampered with, or AAD mismatched."""


class UnknownKeyError(DecryptionError):
    """Ciphertext references a key ID that is not in the ring."""


class InvalidPhoneError(ValueError):
    """Not a valid Indian mobile number."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise DecryptionError("malformed ciphertext")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_key() -> bytes:
    """32 random bytes suitable for AES-256-GCM or HMAC-SHA256."""
    return secrets.token_bytes(KEY_BYTES)


def key_to_b64(key: bytes) -> str:
    return _b64e(key)


def key_from_b64(text: str) -> bytes:
    raw = _b64d(text.strip())
    if len(raw) != KEY_BYTES:
        raise CryptoError(f"key must be {KEY_BYTES} bytes")
    return raw


class KeyRing:
    """Master keys by ID, with one active key for new encryptions."""

    def __init__(self, keys: Mapping[str, bytes], active_key_id: str) -> None:
        if not keys:
            raise CryptoError("key ring must contain at least one key")
        for key_id, key in keys.items():
            if not _KEY_ID.match(key_id):
                raise CryptoError("key id must match [A-Za-z0-9_-]{1,64}")
            if len(key) != KEY_BYTES:
                raise CryptoError(f"key {key_id!r} must be {KEY_BYTES} bytes")
        if active_key_id not in keys:
            raise CryptoError("active key id is not in the ring")
        self._keys = dict(keys)
        self.active_key_id = active_key_id

    def __repr__(self) -> str:  # never print key material
        return f"KeyRing(key_ids={sorted(self._keys)!r}, active={self.active_key_id!r})"

    @property
    def key_ids(self) -> list[str]:
        return sorted(self._keys)

    def get(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise UnknownKeyError("unknown key id") from None

    def with_key(self, key_id: str, key: bytes, *, activate: bool = False) -> KeyRing:
        """New ring with an extra key (rotation step 1: add; step 2: activate)."""
        keys = {**self._keys, key_id: key}
        return KeyRing(keys, key_id if activate else self.active_key_id)

    @classmethod
    def from_env_value(cls, value: str, active_key_id: str) -> KeyRing:
        """Parse ``id1=<b64url>,id2=<b64url>`` (the format of DWAAR_PII_KEYS)."""
        keys: dict[str, bytes] = {}
        for part in value.split(","):
            if not part.strip():
                continue
            key_id, sep, material = part.strip().partition("=")
            if not sep:
                raise CryptoError("expected id=base64url pairs")
            keys[key_id.strip()] = key_from_b64(material)
        return cls(keys, active_key_id)

    @classmethod
    def from_env(
        cls,
        keys_var: str = "DWAAR_PII_KEYS",
        active_var: str = "DWAAR_PII_ACTIVE_KEY_ID",
    ) -> KeyRing:
        value = os.environ.get(keys_var)
        active = os.environ.get(active_var)
        if not value or not active:
            raise CryptoError(f"{keys_var} and {active_var} must be set")
        return cls.from_env_value(value, active)


def build_aad(*parts: object) -> bytes:
    """Deterministic AAD from parts, e.g. ``build_aad(society_id, 'person_vault', 'phone', row_id)``."""
    texts = [str(p) for p in parts]
    if any("|" in t for t in texts):
        raise CryptoError("AAD parts must not contain '|'")
    return ("dwaar-aad|" + "|".join(texts)).encode("utf-8")


class EnvelopeCipher:
    """AES-256-GCM with key IDs embedded in the ciphertext."""

    def __init__(self, keyring: KeyRing) -> None:
        self.keyring = keyring

    def encrypt(self, plaintext: str | bytes, aad: bytes = b"") -> str:
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        key_id = self.keyring.active_key_id
        nonce = secrets.token_bytes(NONCE_BYTES)
        sealed = AESGCM(self.keyring.get(key_id)).encrypt(nonce, data, aad)
        return f"{CIPHERTEXT_VERSION}:{key_id}:{_b64e(nonce)}:{_b64e(sealed)}"

    @staticmethod
    def _parse(token: str) -> tuple[str, bytes, bytes]:
        parts = token.split(":") if isinstance(token, str) else []
        if len(parts) != 4 or parts[0] != CIPHERTEXT_VERSION or not _KEY_ID.match(parts[1]):
            raise DecryptionError("malformed ciphertext")
        nonce = _b64d(parts[2])
        sealed = _b64d(parts[3])
        if len(nonce) != NONCE_BYTES or len(sealed) < 16:
            raise DecryptionError("malformed ciphertext")
        return parts[1], nonce, sealed

    def decrypt_bytes(self, token: str, aad: bytes = b"") -> bytes:
        key_id, nonce, sealed = self._parse(token)
        key = self.keyring.get(key_id)
        try:
            return AESGCM(key).decrypt(nonce, sealed, aad)
        except InvalidTag:
            raise DecryptionError("authentication failed") from None

    def decrypt(self, token: str, aad: bytes = b"") -> str:
        try:
            return self.decrypt_bytes(token, aad).decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptionError("plaintext is not UTF-8") from None

    def key_id_of(self, token: str) -> str:
        return self._parse(token)[0]

    def needs_rotation(self, token: str) -> bool:
        return self.key_id_of(token) != self.keyring.active_key_id

    def rotate(self, token: str, aad: bytes = b"") -> str:
        """Re-encrypt under the active key (no-op, same token, if already active)."""
        if not self.needs_rotation(token):
            # still authenticate so corrupted values are surfaced during rotation sweeps
            self.decrypt_bytes(token, aad)
            return token
        return self.encrypt(self.decrypt_bytes(token, aad), aad)


def keyed_hash(value: str | bytes, key: bytes) -> str:
    """HMAC-SHA256 hex digest, for deterministic lookup tokens (e.g. phone_token)."""
    if len(key) < KEY_BYTES:
        raise CryptoError(f"HMAC key must be at least {KEY_BYTES} bytes")
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hmac.new(key, data, hashlib.sha256).hexdigest()


_PHONE_SEPARATORS = re.compile(r"[\s().-]")


def normalize_phone_in(raw: str) -> str:
    """Normalise an Indian mobile number to E.164 (``+91XXXXXXXXXX``).

    Accepts spaces/hyphens/brackets and the prefixes ``+91``, ``91``, ``0091``, ``0`` or none.
    The national number must be ten digits starting 6-9. Raises InvalidPhoneError otherwise.
    """
    if not isinstance(raw, str):
        raise InvalidPhoneError("phone must be a string")
    text = _PHONE_SEPARATORS.sub("", raw.strip())
    if text.startswith("+"):
        if not text.startswith("+91"):
            raise InvalidPhoneError("only Indian (+91) numbers are supported")
        text = text[3:]
    elif text.startswith("0091"):
        text = text[4:]
    elif len(text) == 12 and text.startswith("91"):
        text = text[2:]
    elif len(text) == 11 and text.startswith("0"):
        text = text[1:]
    # ASCII digits only: Unicode digits (Arabic-Indic, Devanagari ...) would produce a second, different
    # phone_token / rate-limit key for the same SIM (IAM-06).
    if not re.fullmatch(r"[6-9][0-9]{9}", text, re.ASCII):
        raise InvalidPhoneError("not a valid Indian mobile number")
    return "+91" + text
