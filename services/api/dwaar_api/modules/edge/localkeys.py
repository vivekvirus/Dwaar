"""Deterministic LOCAL-ONLY keys for the simulator (never accepted outside ``DWAAR_ENV=local|test``).

REQ: EDGE-04 (signed snapshots, issuer key), EDGE-09 (per-device key), BUILD_BRIEF 7 (simulators are labelled and cannot reach real
providers). The seeds are plain SHA-256 of public labels: anybody can derive them, so they are worth nothing, which is the point.
``docs/contracts/edge-sync.md`` section 8 documents the derivation for the edge agent.
"""

from __future__ import annotations

import hashlib
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.signing import b64url_encode, public_key_to_b64

ISSUER_LABEL: Final = b"dwaar-local-edge-policy-issuer"
REF_LABEL: Final = b"dwaar-local-edge-opaque-reference-key"
DEVICE_LABEL_PREFIX: Final = b"dwaar-local-edge-device|"
#: name of the edge gateway device the optional seed step enrols (docs/contracts/edge-sync.md section 8)
SEED_DEVICE_NAME: Final = "Main gate edge gateway"
SEED_SOCIETY_KEY: Final = "mh"


def device_seed(label: str) -> bytes:
    """32-byte Ed25519 seed of the local device ``label`` (``"<society key>:<device name>"``)."""
    return hashlib.sha256(DEVICE_LABEL_PREFIX + label.encode()).digest()


def device_private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(device_seed(label))


def device_public_key_b64(label: str) -> str:
    return public_key_to_b64(device_private_key(label).public_key())


def device_seed_b64(label: str) -> str:
    return b64url_encode(device_seed(label))


def issuer_seed() -> bytes:
    return hashlib.sha256(ISSUER_LABEL).digest()


def ref_key() -> bytes:
    return hashlib.sha256(REF_LABEL).digest()
