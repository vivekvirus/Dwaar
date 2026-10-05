import base64
import re
import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from dwaar_common.events import EdgeEvent
from dwaar_common.signing import (
    Signer,
    SigningError,
    VerifierRing,
    check_key_id,
    generate_private_key,
    key_id_for,
    parse_signature,
    private_key_from_b64,
    private_key_to_b64,
    public_key_from_b64,
    public_key_to_b64,
    sign_bytes,
    sign_edge_event,
    sign_envelope,
    verify_bytes,
    verify_edge_event,
    verify_envelope,
)

SIG_FORMAT = re.compile(r"^ed25519:[A-Za-z0-9_-]{86}$")  # 64 bytes -> 86 chars, no padding


def make_event(seq: int = 1) -> EdgeEvent:
    return EdgeEvent.build(
        society_id=uuid.UUID("0192f300-0000-7000-8000-000000000001"),
        device_id=uuid.UUID("0192f300-0000-7000-8000-0000000000d1"),
        seq=seq,
        entity_id=uuid.UUID("0192f3a1-0000-7000-8000-000000000a01"),
        entity_version=1,
        type="EntryObserved",
        policy_version=7,
        payload={"lane_id": "l1"},
        occurred_at=datetime(2026, 10, 5, 13, 41, 7, 250_000, tzinfo=UTC),
    )


def test_signature_format_is_ed25519_prefix_and_base64url_nopad() -> None:
    key = generate_private_key()
    sig = sign_bytes(key, b"hello")
    assert SIG_FORMAT.match(sig)
    assert "=" not in sig
    assert len(parse_signature(sig)) == 64


def test_sign_verify_roundtrip_and_tamper() -> None:
    key = generate_private_key()
    sig = sign_bytes(key, b"hello")
    assert verify_bytes(key.public_key(), b"hello", sig)
    assert not verify_bytes(key.public_key(), b"hellp", sig)
    assert not verify_bytes(generate_private_key().public_key(), b"hello", sig)


@pytest.mark.parametrize(
    "bad",
    [None, "", "ed25519:", "ed25519:abc", "rsa:xyz", "ed25519:" + "A" * 86 + "=", "ed25519:!!"],
)
def test_verify_never_raises_on_malformed_signature(bad: str | None) -> None:
    key = generate_private_key()
    assert verify_bytes(key.public_key(), b"x", bad) is False


def test_parse_signature_errors() -> None:
    with pytest.raises(SigningError):
        parse_signature("nope")
    with pytest.raises(SigningError):
        parse_signature("ed25519:AAAA")


def test_edge_event_sign_verify() -> None:
    signer = Signer.generate()
    event = signer.sign_event(make_event())
    assert event.signature is not None
    assert SIG_FORMAT.match(event.signature)
    assert verify_edge_event(signer.public_key, event)


def test_edge_event_tamper_detection() -> None:
    key = generate_private_key()
    event = sign_edge_event(key, make_event())
    pub = key.public_key()
    for field, value in [
        ("seq", 2),
        ("entity_version", 9),
        ("policy_version", 8),
        ("type", "ExitObserved"),
        ("clock_uncertainty_ms", 5),
        ("occurred_at", datetime(2026, 10, 5, 13, 41, 8, tzinfo=UTC)),
        ("society_id", uuid.uuid4()),
        ("event_id", uuid.uuid4()),
    ]:
        assert not verify_edge_event(pub, event.model_copy(update={field: value})), field
    # payload changed but hash left alone -> hash mismatch
    assert not verify_edge_event(pub, event.model_copy(update={"payload": {"lane_id": "l2"}}))
    # payload and hash both rewritten -> signature mismatch
    forged = EdgeEvent.build(
        society_id=event.society_id, device_id=event.device_id, seq=event.seq,
        entity_id=event.entity_id, entity_version=event.entity_version, type=event.type,
        policy_version=event.policy_version, payload={"lane_id": "l2"},
        occurred_at=event.occurred_at, event_id=event.event_id,
    ).with_signature(event.signature or "")  # fmt: skip
    assert not verify_edge_event(pub, forged)
    assert not verify_edge_event(pub, make_event())  # unsigned


def test_signature_is_independent_of_dict_key_order() -> None:
    key = generate_private_key()
    envelope = {"b": 2, "a": 1, "nested": {"y": 1, "x": 2}}
    reordered = {"nested": {"x": 2, "y": 1}, "a": 1, "b": 2}
    sig = sign_envelope(key, envelope)
    assert verify_envelope(key.public_key(), reordered, sig)
    assert verify_envelope(key.public_key(), {**reordered, "signature": sig})
    assert not verify_envelope(key.public_key(), {**reordered, "a": 3}, sig)


@given(st.binary(max_size=200))
def test_roundtrip_property(data: bytes) -> None:
    key = generate_private_key()
    assert verify_bytes(key.public_key(), data, sign_bytes(key, data))


def test_key_serialisation_roundtrip_and_key_id() -> None:
    key = generate_private_key()
    restored = private_key_from_b64(private_key_to_b64(key))
    assert sign_bytes(restored, b"x") == sign_bytes(key, b"x")  # Ed25519 is deterministic
    pub = public_key_from_b64(public_key_to_b64(key.public_key()))
    assert key_id_for(pub) == key_id_for(key.public_key())
    assert re.fullmatch(r"ed-[0-9a-f]{16}", key_id_for(pub))
    with pytest.raises(SigningError):
        private_key_from_b64(base64.urlsafe_b64encode(b"short").decode())
    with pytest.raises(SigningError):
        public_key_from_b64("AAAA")


def test_key_id_validation() -> None:
    assert check_key_id("issuer-2026.10_a") == "issuer-2026.10_a"
    for bad in ["", "has space", "x" * 65, "a:b"]:
        with pytest.raises(SigningError):
            check_key_id(bad)


def test_verifier_ring_rotation_and_revocation() -> None:
    old, new = Signer.generate("k-old"), Signer.generate("k-new")
    ring = VerifierRing({"k-old": old.public_key, "k-new": new.public_key})
    event_old = old.sign_event(make_event(1))
    event_new = new.sign_event(make_event(2))
    assert ring.verify_event("k-old", event_old)
    assert ring.verify_event("k-new", event_new)
    assert not ring.verify_event("k-new", event_old)  # wrong key
    assert not ring.verify_event("k-unknown", event_old)
    ring.revoke("k-old")
    assert not ring.verify_event("k-old", event_old)
    assert not ring.has("k-old")
    envelope = {"sequence": 5}
    sig = new.sign_envelope(envelope)
    assert ring.verify_envelope("k-new", envelope, sig)
    assert not ring.verify_envelope("k-old", envelope, sig)


def test_signer_repr_hides_private_key() -> None:
    signer = Signer.generate()
    assert "Ed25519PrivateKey" not in repr(signer)
    assert signer.key_id in repr(signer)
