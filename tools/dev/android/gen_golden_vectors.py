#!/usr/bin/env python3
# ruff: noqa: C408
"""Generate cross-language golden vectors from the Python reference (packages/dwaar-common).

Output: apps/guard-android/core/src/test/resources/golden/edge_vectors.json
Run:    uv run --no-sync python tools/dev/android/gen_golden_vectors.py
The Kotlin :core tests (GoldenVectorTest) must reproduce canonical JSON, payload hashes, signing bytes and Ed25519
signatures byte for byte. Ed25519 is deterministic, so signatures are pinned too. Seeds here are TEST-ONLY keys.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dwaar_common.events import CanonicalJsonError, EdgeEvent, canonical_json, payload_hash
from dwaar_common.signing import b64url_encode, key_id_for, public_key_to_b64

OUT = (
    Path(__file__).resolve().parents[3]
    / "apps/guard-android/core/src/test/resources/golden/edge_vectors.json"
)

CANON_INPUTS = [
    '{"b":1,"a":2}',
    '{"z":[3,2,1],"y":{"d":null,"c":true,"b":false}}',
    '{"text":"quote \\" backslash \\\\ nl \\n cr \\r tab \\t bs \\b ff \\f ctl \\u0001 \\u001f del \\u007f"}',
    '{"hindi":"\\u0907\\u0928\\u094d\\u091f\\u0930\\u0928\\u0947\\u091f \\u0928\\u0939\\u0940\\u0902","mr":"\\u0917\\u0947\\u091f"}',
    '{"\\ud83d\\ude00":1,"\\uffee":2,"a":3}',
    '{"\\u00e9":1,"e":2,"E":3,"_":4,"0":5}',
    '{"n":[0,-1,9223372036854775807,-9223372036854775808],"empty":{},"arr":[]}',
    '{"lane_id":"lane-1","decision_source":"guard_assisted","unit":"A-1204"}',
    "[]",
]
REJECT_INPUTS = ['{"f":1.5}', '{"f":1e3}', '{"n":[{"deep":2.0}]}']

SEEDS = {
    "seed-a": bytes(range(32)),
    "seed-b": bytes([0xA5] * 32),
}


def event_vectors() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = [
        dict(
            seed="seed-a",
            seq=18452,
            type="EntryObserved",
            entity_version=2,
            policy_version=913,
            occurred_at=datetime(2026, 10, 5, 13, 41, 7, 250000, tzinfo=UTC),
            clock_uncertainty_ms=120,
            payload={
                "lane_id": "0192f300-0000-7000-8000-0000000000a1",
                "decision_source": "guard_assisted",
            },
        ),
        dict(
            seed="seed-b",
            seq=0,
            type="EntryObserved",
            entity_version=1,
            policy_version=0,
            occurred_at=datetime(2026, 1, 1, 0, 0, 0, 0, tzinfo=UTC),
            clock_uncertainty_ms=0,
            payload={},
        ),
        dict(
            seed="seed-a",
            seq=9007199254740,
            type="ApprovalRequested",
            entity_version=7,
            policy_version=12,
            occurred_at=datetime(2026, 12, 31, 23, 59, 59, 999000, tzinfo=UTC),
            clock_uncertainty_ms=60000,
            payload={
                "visitor_alias": "राजेश",
                "note": 'tab\there "q"',
                "unit_ids": ["u-2", "u-1"],
                "count": 3,
            },
        ),
    ]
    for i, s in enumerate(specs):
        key = Ed25519PrivateKey.from_private_bytes(SEEDS[s["seed"]])
        ev = EdgeEvent.build(
            society_id=UUID("0192f300-0000-7000-8000-000000000001"),
            device_id=UUID("0192f300-0000-7000-8000-0000000000d1"),
            seq=s["seq"],
            entity_id=UUID("0192f3a1-0000-7000-8000-000000000f01"),
            entity_version=s["entity_version"],
            type=s["type"],
            policy_version=s["policy_version"],
            payload=s["payload"],
            occurred_at=s["occurred_at"],
            clock_uncertainty_ms=s["clock_uncertainty_ms"],
            event_id=UUID(f"0192f3b2-1111-7aaa-8bbb-ccccdddd{i + 1:04x}"),
        )
        signature = "ed25519:" + b64url_encode(key.sign(ev.signing_bytes()))
        signed = ev.with_signature(signature)
        pub = key.public_key()
        cases.append(
            {
                "seed_hex": SEEDS[s["seed"]].hex(),
                "public_key_b64url": public_key_to_b64(pub),
                "key_id": key_id_for(pub),
                "unsigned_wire": {k: v for k, v in ev.to_wire().items() if k != "signature"},
                "payload_hash": ev.payload_hash,
                "signing_bytes": ev.signing_bytes().decode("utf-8"),
                "signature": signature,
                "canonical_full": signed.canonical_bytes().decode("utf-8"),
            }
        )
    return cases


def main() -> None:
    canon = []
    for text in CANON_INPUTS:
        value = json.loads(text)
        out = canonical_json(value)
        canon.append(
            {
                "input_json": text,
                "canonical": out.decode("utf-8"),
                "sha256_hex": payload_hash(value)[len("sha256:") :]
                if isinstance(value, dict)
                else None,
            }
        )
    for text in REJECT_INPUTS:
        try:
            canonical_json(json.loads(text))
        except CanonicalJsonError:
            pass
        else:  # pragma: no cover
            raise SystemExit(f"python accepted {text}")
    doc = {
        "generated_by": "tools/dev/android/gen_golden_vectors.py (dwaar_common reference implementation)",
        "note": "TEST-ONLY keys. Do not edit by hand; regenerate.",
        "canonical_cases": canon,
        "reject_cases": REJECT_INPUTS,
        "edge_events": event_vectors(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("wrote", OUT)


if __name__ == "__main__":
    main()
