"""``python -m dwaar_api.modules.edge.localdev``: print the LOCAL-ONLY ids and keys the edge simulator needs (simulation, never real).

REQ: EDGE-09, EDGE-04, BUILD_BRIEF 7. Prints JSON with the seed society and device ids (deterministic, see the seed step), the device's
Ed25519 seed (public by construction: sha256 of a label) and the policy issuer's public key. Refuses unless ``DWAAR_ENV`` is ``local``.
"""

from __future__ import annotations

import json
import os
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.ids import uuid7
from dwaar_common.signing import key_id_for, private_key_from_b64, public_key_to_b64

from ...seed.ids import deterministic_ids, scoped_uuid
from . import localkeys


def device_scope(
    society_key: str = localkeys.SEED_SOCIETY_KEY, name: str = localkeys.SEED_DEVICE_NAME
) -> str:
    """The seed transaction scope of the device enrolment."""
    return f"edge:device:{society_key}:{name}"


def seed_device_id(scope: str) -> uuid.UUID:
    """The device id minted by the seed: the SECOND id of the scope (the first is the transaction's request id, the second is ``enrol_device``'s)."""
    with deterministic_ids(scope):
        uuid7()
        return uuid7()


def describe(
    society_key: str = localkeys.SEED_SOCIETY_KEY, name: str = localkeys.SEED_DEVICE_NAME
) -> dict[str, object]:
    label = f"{society_key}:{name}"
    configured = os.environ.get(
        "DWAAR_EDGE_POLICY_SIGNING_KEY", ""
    ).strip()  # `make setup` generates one: the API then signs with it
    issuer = (
        private_key_from_b64(configured).public_key()
        if configured
        else Ed25519PrivateKey.from_private_bytes(localkeys.issuer_seed()).public_key()
    )
    key_id = os.environ.get("DWAAR_EDGE_POLICY_KEY_ID", "").strip() if configured else ""
    return {
        "simulation": True,
        "society_id": str(scoped_uuid(f"society:{society_key}")),
        "device_id": str(seed_device_id(device_scope(society_key, name))),
        "device_name": name,
        "device_label": label,
        "device_seed_b64url": localkeys.device_seed_b64(label),
        "device_public_key": localkeys.device_public_key_b64(label),
        "policy_issuer_key_id": key_id or key_id_for(issuer),
        "policy_issuer_public_key": public_key_to_b64(issuer),
    }


def main() -> int:
    if (os.environ.get("DWAAR_ENV") or "").strip().lower() != "local":
        sys.stderr.write(
            "localdev: refusing to run unless DWAAR_ENV=local (these keys are public by construction)\n"
        )
        return 2
    sys.stdout.write(json.dumps(describe(), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
