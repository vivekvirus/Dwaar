"""Commissioning: pin the cloud's trust anchors (policy issuer keys, guest-pass verification keys) into the gateway configuration.

REQ: EDGE-04 (issuer keys are PROVISIONED, never taken from a snapshot), EDGE-09 (per-device identity; no secret leaves the device),
GATE-01 (pass keys verify the QR offline).

The flow an installer follows (docs/adr/0019):

1. A guard terminal requests the device enrolment with the gateway's PUBLIC key; a different supervisor approves it (cloud routes, not here).
2. The gateway signs ``GET /v1/edge/keys`` with its own device key. The answer lists the issuer keys and the pass keys.
3. The installer compares the printed key fingerprints with the ones shown in the admin console (an out-of-band check: this is trust on
   first use otherwise) and stores the result as ``DWAAR_EDGE_ISSUER_KEYS`` / ``DWAAR_EDGE_PASS_KEYS``.

After this step the gateway verifies every snapshot against the pinned keys only. A key rotation needs the new key to be provisioned again
(``refresh`` never trusts a key that arrives inside a snapshot).

Run: ``python -m dwaar_edge.provision`` with ``DWAAR_EDGE_CLOUD_URL``, ``DWAAR_EDGE_DEVICE_ID`` and ``DWAAR_EDGE_DEVICE_KEY`` set; it prints the
two environment lines and the fingerprints and writes nothing.
"""

# REQ: EDGE-04, EDGE-09, GATE-01

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from dwaar_common.signing import (
    SigningError,
    private_key_from_b64,
    public_key_from_b64,
    public_key_to_b64,
    sign_bytes,
)
from dwaar_common.timeutil import format_iso_utc

from .sync import HttpxTransport, Transport, TransportError


class ProvisioningError(Exception):
    """The cloud refused the request or answered something unusable. Nothing was pinned."""


@dataclass(frozen=True)
class TrustAnchors:
    issuer_keys: Mapping[str, Ed25519PublicKey]
    pass_keys: Mapping[str, Ed25519PublicKey] = field(default_factory=dict)
    simulation: bool = False

    def env_lines(self) -> dict[str, str]:
        def join(keys: Mapping[str, Ed25519PublicKey]) -> str:
            return ",".join(f"{k}={public_key_to_b64(v)}" for k, v in sorted(keys.items()))

        return {
            "DWAAR_EDGE_ISSUER_KEYS": join(self.issuer_keys),
            "DWAAR_EDGE_PASS_KEYS": join(self.pass_keys),
        }

    def fingerprints(self) -> dict[str, str]:
        """Short SHA-256 fingerprints for the out-of-band comparison."""
        out = {}
        for kind, keys in (("issuer", self.issuer_keys), ("pass", self.pass_keys)):
            for key_id, key in sorted(keys.items()):
                digest = hashlib.sha256(public_key_to_b64(key).encode()).hexdigest()[:16]
                out[f"{kind}:{key_id}"] = digest
        return out


def _parse_keys(raw: object, label: str) -> dict[str, Ed25519PublicKey]:
    if not isinstance(raw, list):
        raise ProvisioningError(f"{label}: expected a list")
    keys: dict[str, Ed25519PublicKey] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise ProvisioningError(f"{label}: malformed entry")
        key_id, material = item.get("key_id"), item.get("public_key")
        if not isinstance(key_id, str) or not isinstance(material, str):
            raise ProvisioningError(f"{label}: malformed entry")
        try:
            keys[key_id] = public_key_from_b64(material)
        except (SigningError, ValueError) as exc:
            raise ProvisioningError(f"{label}: unusable key {key_id!r}") from exc
    return keys


def fetch_trust_anchors(
    transport: Transport,
    device_id: uuid.UUID,
    device_key: Ed25519PrivateKey,
    *,
    now: datetime | None = None,
) -> TrustAnchors:
    """Ask the cloud (signed with the DEVICE key) for the keys this gateway should pin. Raises :class:`ProvisioningError` on any refusal."""
    target = "/v1/edge/keys"
    stamp = format_iso_utc(now or datetime.now(UTC))
    canonical = f"GET\n{target}\n{stamp}\n{hashlib.sha256(b'').hexdigest()}".encode()
    headers = {
        "X-Dwaar-Device": str(device_id),
        "X-Dwaar-Timestamp": stamp,
        "X-Dwaar-Signature": sign_bytes(device_key, canonical),
    }
    try:
        resp = transport.request("GET", target, headers, b"")
    except TransportError as exc:
        raise ProvisioningError(f"cloud unreachable: {exc}") from exc
    if resp.status != 200 or not isinstance(resp.json, dict):
        raise ProvisioningError(
            f"the cloud refused provisioning (HTTP {resp.status}); is the device enrolled and approved?"
        )
    issuer = _parse_keys(resp.json.get("keys"), "keys")
    if not issuer:
        raise ProvisioningError("the cloud returned no issuer key")
    passes = _parse_keys(resp.json.get("pass_keys", []), "pass_keys")
    simulation = any(
        isinstance(k, dict) and k.get("simulation") is True for k in resp.json.get("keys", [])
    )
    return TrustAnchors(issuer, passes, simulation)


def main() -> int:
    env = os.environ
    anchors = fetch_trust_anchors(
        HttpxTransport(env["DWAAR_EDGE_CLOUD_URL"]),
        uuid.UUID(env["DWAAR_EDGE_DEVICE_ID"]),
        private_key_from_b64(env["DWAAR_EDGE_DEVICE_KEY"]),
    )
    out = sys.stdout
    if anchors.simulation:
        out.write("# SIMULATION issuer key: never provision this into a production gateway\n")
    for name, value in anchors.env_lines().items():
        out.write(f"{name}={value}\n")
    for label, digest in anchors.fingerprints().items():
        out.write(
            f"# fingerprint {label} {digest}  (compare with the admin console before using)\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
