"""QR parsing, token parsing, config loading and outbox state-machine properties."""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dwaar_common.signing import Signer, generate_private_key, private_key_to_b64, public_key_to_b64
from dwaar_edge.config import EdgeConfig
from dwaar_edge.errors import InvalidRequest
from dwaar_edge.outbox import MAX_PAYLOAD_BYTES
from dwaar_edge.qr import parse_qr
from dwaar_edge.tokens import parse
from tests.integration.edge_gateway.support import START, World, standard_world_with_policy

W = World()
INV = uuid.uuid4()


def test_qr_valid_forged_wrong_society_unknown_key() -> None:
    keys = {W.pass_signer.key_id: W.pass_signer.public_key}
    good = W.qr(INV, "n-12345678", nbf=START, exp=START + timedelta(hours=1), gate=W.gate_a)
    parsed = parse_qr(good, keys, W.society_id)
    assert (
        parsed is not None
        and parsed[0].invitation_id == INV
        and parsed[0].qr_signature_ok is True
        and parsed[1] == W.gate_a
    )
    forged = W.qr(
        INV,
        "n-12345678",
        nbf=START,
        exp=START + timedelta(hours=1),
        signer=Signer(W.pass_signer.key_id, generate_private_key()),
    )
    p = parse_qr(forged, keys, W.society_id)
    assert p is not None and p[0].qr_signature_ok is False
    assert parse_qr(good, keys, uuid.uuid4()) is None  # another society
    unknown = W.qr(
        INV,
        "n-12345678",
        nbf=START,
        exp=START + timedelta(hours=1),
        signer=Signer("other-key", generate_private_key()),
    )
    q = parse_qr(unknown, keys, W.society_id)
    assert q is not None and q[0].qr_signature_ok is None  # unchecked is reported, not hidden


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=300))
def test_qr_and_token_parsers_never_raise(text: str) -> None:
    assert parse_qr(text, {}, W.society_id) is None
    assert parse(text, W.token_key) is None


def test_payload_size_limit_is_enforced(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        with pytest.raises(InvalidRequest):
            gw.outbox.append(
                type="EntryObserved",
                entity_id=uuid.uuid4(),
                entity_version=1,
                payload={"pad": "x" * (MAX_PAYLOAD_BYTES + 1)},
                occurred_at=t.wall_now,
                clock_uncertainty_ms=0,
                policy_version=1,
            )
        assert gw.store.get_meta("last_seq") == "0"  # a refused event consumes no sequence number
    finally:
        gw.stop()


def test_config_from_env_roundtrip(tmp_path: Path) -> None:
    from dwaar_common.crypto import generate_key, key_to_b64

    issuer = generate_private_key()
    env = {
        "DWAAR_EDGE_SOCIETY_ID": str(uuid.uuid4()),
        "DWAAR_EDGE_DEVICE_ID": str(uuid.uuid4()),
        "DWAAR_EDGE_DATA_DIR": str(tmp_path),
        "DWAAR_EDGE_DEVICE_KEY": private_key_to_b64(generate_private_key()),
        "DWAAR_EDGE_DEVICE_KEY_ID": "gw-1",
        "DWAAR_EDGE_ISSUER_KEYS": f"issuer-1={public_key_to_b64(issuer.public_key())}",
        "DWAAR_EDGE_PII_KEYS": f"k1={key_to_b64(generate_key())}",
        "DWAAR_EDGE_PII_ACTIVE_KEY_ID": "k1",
        "DWAAR_EDGE_TOKEN_KEY": private_key_to_b64(generate_private_key()),
    }
    cfg = EdgeConfig.from_env(env)
    assert (
        cfg.simulation is True
        and "issuer-1" in cfg.issuer_keys
        and cfg.db_path.name == "edge.sqlite3"
    )


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    ops=st.lists(
        st.sampled_from(["append", "ack_all", "ack_one", "quarantine_one", "gap"]),
        min_size=1,
        max_size=25,
    )
)
def test_outbox_state_machine_properties(ops: list[str]) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        w, t, gw = standard_world_with_policy(Path(d))
        try:
            seen_seqs: list[int] = []
            for op in ops:
                if op == "append":
                    with gw.store.transaction():
                        e = gw.outbox.append(
                            type="EntryObserved",
                            entity_id=uuid.uuid4(),
                            entity_version=1,
                            payload={"g": "x"},
                            occurred_at=t.wall_now,
                            clock_uncertainty_ms=0,
                            policy_version=1,
                        )
                    seen_seqs.append(e.seq)
                elif op == "ack_all":
                    rows = gw.outbox.pending_batch()
                    gw.outbox.apply_outcomes(
                        [(str(r.event_id), "accepted", None) for r in rows], [], t.wall_now
                    )
                elif op == "ack_one":
                    rows = gw.outbox.pending_batch(max_events=1)
                    gw.outbox.apply_outcomes(
                        [(str(r.event_id), "duplicate", None) for r in rows], [], t.wall_now
                    )
                elif op == "quarantine_one":
                    rows = gw.outbox.pending_batch(max_events=1)
                    gw.outbox.apply_outcomes(
                        [(str(x.event_id), "quarantined", "bad") for x in rows], [], t.wall_now
                    )
                elif op == "gap" and seen_seqs:
                    gw.outbox.apply_outcomes(
                        [], [(1, max(seen_seqs))], t.wall_now
                    )  # cloud claims it lacks everything
            assert (
                seen_seqs == sorted(set(seen_seqs)) == list(range(1, len(seen_seqs) + 1))
            )  # strictly monotonic, never reused
            stats = gw.outbox.stats()
            assert stats["last_seq"] == len(seen_seqs)
            assert stats["pending"] + stats["acked"] + stats["quarantined"] + stats[
                "rejected"
            ] == len(seen_seqs)
            # a quarantined event is never offered for sending again
            batch = {r.seq for r in gw.outbox.pending_batch(max_events=1000)}
            q = {
                int(r["seq"])
                for r in gw.store.all("SELECT seq FROM outbox WHERE state='quarantined'")
            }
            assert not (batch & q)
        finally:
            gw.stop()
