"""Edge module configuration: policy issuer key (KMS adapter, simulated locally), opaque-reference key, limits.

REQ: EDGE-04 (issuer key id on every snapshot; rotation without breaking edges), EDGE-03 (batch limits), ARCH-02/ARCH-04 (keys only
from the environment; a placeholder key is accepted ONLY when simulators are allowed), OBS-02.

The policy issuer is behind the :class:`PolicySigner` protocol. ``SimulatedKmsSigner`` holds an Ed25519 seed in process memory and is
labelled ``simulation=True``; a real KMS/HSM adapter implements the same two members. Key rotation: configure the new key as the active
signer and list the old PUBLIC key in ``DWAAR_EDGE_RETIRED_KEYS`` so edges can still verify older snapshots; the publisher issues a new
snapshot (``reason = key_rotation``) even when the content did not change.

Environment (add to ``.env.example`` when the platform owner next edits it; see ADR-0017):

* ``DWAAR_EDGE_POLICY_SIGNING_KEY``  Ed25519 seed, base64url, 32 bytes (simulated KMS: the key material itself).
* ``DWAAR_EDGE_POLICY_KEY_ID``       optional key id (default derived from the public key).
* ``DWAAR_EDGE_RETIRED_KEYS``        ``id:publickey_b64url`` pairs, comma separated (rotated-out issuers, public halves only).
* ``DWAAR_EDGE_REF_KEY``             base64url, 32 bytes: keyed hash behind ``credential_ref`` / ``person_ref``.
* ``DWAAR_EDGE_PUBLISH_ON_POLL``     ``true`` (default) until a worker runs the publisher.
* ``DWAAR_EDGE_RATE_CAPACITY`` / ``DWAAR_EDGE_RATE_REFILL_PER_S``  per-device request budget.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.crypto import CryptoError, key_from_b64
from dwaar_common.signing import (
    SigningError,
    check_key_id,
    key_id_for,
    private_key_from_b64,
    public_key_from_b64,
    public_key_to_b64,
    sign_bytes,
)

from ...core.config import ConfigError, Settings
from . import localkeys

log = logging.getLogger("dwaar_api.edge")

MAX_BATCH_EVENTS: Final = 500
MAX_BATCH_BYTES: Final = (
    1_048_576  # 1 MiB (EDGE-03 says 1 MB: the binary reading is the more tolerant one for the edge)
)
SCHEMA_VERSION: Final = 1


@runtime_checkable
class PolicySigner(Protocol):
    """Signs snapshot bytes. A KMS adapter implements exactly this."""

    @property
    def key_id(self) -> str: ...

    @property
    def public_key_b64(self) -> str: ...

    @property
    def simulation(self) -> bool: ...

    def sign(self, data: bytes) -> str:
        """``ed25519:<b64url>`` signature of ``data``."""
        ...


@dataclass(frozen=True)
class SimulatedKmsSigner:
    """Local stand-in for a KMS key: SIMULATION, the private seed lives in this process."""

    _key: Ed25519PrivateKey = field(repr=False)
    key_id: str
    simulation: bool = True

    @classmethod
    def from_seed_b64(cls, seed_b64: str, key_id: str | None = None) -> SimulatedKmsSigner:
        key = private_key_from_b64(seed_b64)
        return cls(key, key_id or key_id_for(key.public_key()))

    @property
    def public_key_b64(self) -> str:
        return public_key_to_b64(self._key.public_key())

    def sign(self, data: bytes) -> str:
        return sign_bytes(self._key, data)


@dataclass(frozen=True)
class EdgeConfig:
    signer: PolicySigner
    ref_key: bytes
    simulation: bool
    retired_keys: Mapping[str, str] = field(default_factory=dict)  # key id -> public key b64url
    publish_on_poll: bool = True
    refresh_interval_s: int = 6 * 3600
    revocation_retention_days: int = 30
    max_skew_s: int = 120
    rate_capacity: int = 60
    rate_refill_per_s: float = 5.0
    ip_rate_capacity: int = 600
    ip_rate_refill_per_s: float = 100.0
    future_grace_ms: int = 5_000
    last_seen_touch_s: int = 30
    max_payload_bytes: int = 2_048
    max_gaps: int = 200

    def key_list(self) -> list[dict[str, object]]:
        """Issuer public keys an edge may trust: the active signer first, then retired ones (sorted)."""
        keys: list[dict[str, object]] = [
            {
                "key_id": self.signer.key_id,
                "public_key": self.signer.public_key_b64,
                "status": "active",
                "simulation": self.signer.simulation,
            }
        ]
        keys += [
            {"key_id": kid, "public_key": pub, "status": "retired", "simulation": False}
            for kid, pub in sorted(self.retired_keys.items())
            if kid != self.signer.key_id
        ]
        return keys

    @classmethod
    def from_environment(
        cls, settings: Settings, environ: Mapping[str, str] | None = None
    ) -> EdgeConfig:
        env = os.environ if environ is None else environ
        simulation = settings.simulation
        try:
            raw_key = env.get("DWAAR_EDGE_POLICY_SIGNING_KEY", "").strip()
            if raw_key:
                signer = SimulatedKmsSigner.from_seed_b64(
                    raw_key, env.get("DWAAR_EDGE_POLICY_KEY_ID", "").strip() or None
                )
                # a key from the environment is whatever the operator provisioned: it is only "simulation" when the
                # environment itself allows simulators
                signer = SimulatedKmsSigner(signer._key, signer.key_id, simulation)  # noqa: SLF001
            elif simulation:
                key = Ed25519PrivateKey.from_private_bytes(localkeys.issuer_seed())
                signer = SimulatedKmsSigner(key, key_id_for(key.public_key()), True)
            else:
                raise ConfigError("DWAAR_EDGE_POLICY_SIGNING_KEY is required")
            check_key_id(signer.key_id)
            raw_ref = env.get("DWAAR_EDGE_REF_KEY", "").strip()
            if raw_ref:
                ref_key = key_from_b64(raw_ref)
            elif simulation:
                ref_key = localkeys.ref_key()
            else:
                raise ConfigError("DWAAR_EDGE_REF_KEY is required")
            retired = _parse_retired(env.get("DWAAR_EDGE_RETIRED_KEYS", ""))
        except (CryptoError, SigningError) as exc:
            raise ConfigError(f"invalid edge key configuration: {exc}") from None
        return cls(
            signer=signer,
            ref_key=ref_key,
            simulation=simulation,
            retired_keys=retired,
            publish_on_poll=env.get("DWAAR_EDGE_PUBLISH_ON_POLL", "true").strip().lower()
            not in {"0", "false", "no", "off"},
            rate_capacity=_int(env, "DWAAR_EDGE_RATE_CAPACITY", 60, 1, 10_000),
            rate_refill_per_s=float(_int(env, "DWAAR_EDGE_RATE_REFILL_PER_S", 5, 1, 1_000)),
        )


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")
    return value


def _parse_retired(raw: str) -> dict[str, str]:
    retired: dict[str, str] = {}
    for item in (p.strip() for p in raw.split(",")):
        if not item:
            continue
        key_id, _, pub = item.partition(":")
        check_key_id(key_id)
        public_key_from_b64(pub)  # validates length and alphabet
        retired[key_id] = pub
    return retired
