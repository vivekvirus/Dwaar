"""Gateway configuration, provisioned at commissioning (never read from a policy snapshot)."""

# REQ: EDGE-01, EDGE-04

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from dwaar_common.crypto import KeyRing
from dwaar_common.signing import (
    private_key_from_b64,
    public_key_from_b64,
)

# GATE-07: "defined local authority". The society configures the list; these are the shipped defaults.
DEFAULT_LOCAL_AUTHORITIES: Final = frozenset(
    {
        "security_supervisor",
        "society_secretary",
        "committee_chair",
        "fire_marshal",
        "medical_emergency",
    }
)


@dataclass(frozen=True)
class EdgeConfig:
    society_id: uuid.UUID
    device_id: uuid.UUID  # the gateway's own device id (events carry it)
    data_dir: Path
    device_key: Ed25519PrivateKey = field(
        repr=False
    )  # per-device key: signs events and cloud requests
    device_key_id: str
    issuer_keys: Mapping[str, Ed25519PublicKey]  # policy issuer public keys (provisioned)
    keyring: KeyRing = field(repr=False)  # field encryption master keys
    token_key: Ed25519PrivateKey = field(repr=False)  # signs terminal device tokens
    pass_keys: Mapping[str, Ed25519PublicKey] = field(
        default_factory=dict
    )  # QR signing public keys
    simulation: bool = True
    wan_down_after_s: int = 180
    admission_valid_s: int = (
        600  # a guard/supervisor admission must be followed by the observed entry within this
    )
    hold_ttl_s: int = 120  # a reserved single-use pass use is released if no entry is observed
    max_override_s: int = 16 * 3600
    stale_terminal_s: int = 3600
    inside_stale_after_s: int = 24 * 3600
    decision_log_keep_s: int = 14 * 24 * 3600  # operational retention of local decision rows
    feed_keep_s: int = 24 * 3600
    client_action_keep_s: int = 72 * 3600  # must cover the longest plausible terminal retry window
    local_authorities: frozenset[str] = DEFAULT_LOCAL_AUTHORITIES
    full_integrity_on_open: bool = True

    @property
    def db_path(self) -> Path:
        return self.data_dir / "edge.sqlite3"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> EdgeConfig:
        """Commissioning values from the environment (see .env.example). Secrets never live in the repo."""
        env = os.environ if environ is None else environ
        issuer = {}
        for part in env["DWAAR_EDGE_ISSUER_KEYS"].split(","):
            key_id, _, material = part.strip().partition("=")
            issuer[key_id] = public_key_from_b64(material)
        pass_keys = {}
        for part in env.get("DWAAR_EDGE_PASS_KEYS", "").split(","):
            if part.strip():
                key_id, _, material = part.strip().partition("=")
                pass_keys[key_id] = public_key_from_b64(material)
        return cls(
            society_id=uuid.UUID(env["DWAAR_EDGE_SOCIETY_ID"]),
            device_id=uuid.UUID(env["DWAAR_EDGE_DEVICE_ID"]),
            data_dir=Path(env["DWAAR_EDGE_DATA_DIR"]),
            device_key=private_key_from_b64(env["DWAAR_EDGE_DEVICE_KEY"]),
            device_key_id=env["DWAAR_EDGE_DEVICE_KEY_ID"],
            issuer_keys=issuer,
            pass_keys=pass_keys,
            keyring=KeyRing.from_env_value(
                env["DWAAR_EDGE_PII_KEYS"], env["DWAAR_EDGE_PII_ACTIVE_KEY_ID"]
            ),
            token_key=private_key_from_b64(env["DWAAR_EDGE_TOKEN_KEY"]),
            simulation=env.get("DWAAR_EDGE_SIMULATION", "true").lower() != "false",
        )
