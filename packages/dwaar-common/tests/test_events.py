import json
import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from dwaar_common.events import (
    KNOWN_EVENT_TYPES,
    CanonicalJsonError,
    DomainEvent,
    EdgeEvent,
    canonical_json,
    payload_hash,
)
from dwaar_common.ids import uuid7

SOCIETY = uuid.UUID("0192f300-0000-7000-8000-000000000001")
DEVICE = uuid.UUID("0192f300-0000-7000-8000-0000000000d1")
ENTITY = uuid.UUID("0192f3a1-0000-7000-8000-000000000a01")
WHEN = datetime(2026, 10, 5, 13, 41, 7, 250_000, tzinfo=UTC)


def make_edge(**over: object) -> EdgeEvent:
    base: dict[str, object] = {
        "society_id": SOCIETY,
        "device_id": DEVICE,
        "seq": 18452,
        "entity_id": ENTITY,
        "entity_version": 2,
        "type": "EntryObserved",
        "policy_version": 913,
        "payload": {"lane_id": "lane-1", "decision_source": "cached_policy"},
        "occurred_at": WHEN,
        "clock_uncertainty_ms": 120,
        "event_id": uuid.UUID("0192f3b2-1111-7aaa-8bbb-ccccdddd0001"),
    }
    base.update(over)
    return EdgeEvent.build(**base)  # type: ignore[arg-type]


def test_canonical_json_sorted_compact_utf8() -> None:
    assert canonical_json({"b": 1, "a": {"z": [1, 2], "y": "₹"}}) == (
        '{"a":{"y":"₹","z":[1,2]},"b":1}'.encode()
    )


def test_canonical_json_rejects_floats_nan_and_non_str_keys() -> None:
    with pytest.raises(CanonicalJsonError, match="float"):
        canonical_json({"a": 1.5})
    with pytest.raises(CanonicalJsonError, match=r"\$\.a\[1\]"):
        canonical_json({"a": [1, 2.0]})
    with pytest.raises(CanonicalJsonError):
        canonical_json({"a": float("nan")})
    with pytest.raises(CanonicalJsonError, match="key"):
        canonical_json({1: "x"})
    with pytest.raises(CanonicalJsonError):
        canonical_json({"a": object()})


def test_canonical_json_serialises_uuid_and_datetime() -> None:
    out = json.loads(canonical_json({"id": SOCIETY, "at": WHEN}))
    assert out == {"id": str(SOCIETY), "at": "2026-10-05T13:41:07.250Z"}


@given(
    st.dictionaries(
        st.text(max_size=8),
        st.recursive(
            st.none()
            | st.booleans()
            | st.integers(min_value=-(2**63), max_value=2**63 - 1)
            | st.text(max_size=8),
            lambda inner: (
                st.lists(inner, max_size=3)
                | st.dictionaries(st.text(max_size=5), inner, max_size=3)
            ),
            max_leaves=8,
        ),
        max_size=5,
    )
)
def test_canonical_json_is_order_independent_and_roundtrips(payload: dict[str, object]) -> None:
    shuffled = dict(reversed(list(payload.items())))
    assert canonical_json(payload) == canonical_json(shuffled)
    assert json.loads(canonical_json(payload)) == payload
    assert payload_hash(payload) == payload_hash(shuffled)


def test_payload_hash_format_and_stability() -> None:
    value = payload_hash({"a": 1})
    assert value.startswith("sha256:")
    assert len(value) == len("sha256:") + 64
    # sha256 of the bytes {"a":1}
    assert value == "sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"


def test_edge_event_matches_prd_example_shape() -> None:
    event = make_edge()
    wire = event.to_wire()
    assert list(wire) == [
        "event_id", "society_id", "device_id", "seq", "entity_id", "entity_version", "type",
        "policy_version", "occurred_at", "clock_uncertainty_ms", "payload_hash", "payload",
        "signature",
    ]  # fmt: skip
    assert wire["occurred_at"] == "2026-10-05T13:41:07.250Z"
    assert wire["signature"] is None
    assert event.payload_hash_matches()
    assert EdgeEvent.from_wire(wire) == event


def test_edge_event_validation() -> None:
    with pytest.raises(ValidationError):
        make_edge(seq=-1)
    with pytest.raises(ValidationError):
        make_edge(type="")
    with pytest.raises(ValidationError):
        make_edge(occurred_at=datetime(2026, 1, 1))
    with pytest.raises(ValidationError):
        EdgeEvent.from_wire({**make_edge().to_wire(), "payload_hash": "md5:abc"})
    with pytest.raises(ValidationError):
        EdgeEvent.from_wire({**make_edge().to_wire(), "unexpected": 1})


def test_edge_event_non_utc_input_is_normalised() -> None:
    from dwaar_common.timeutil import IST

    event = make_edge(occurred_at=WHEN.astimezone(IST))
    assert event.to_wire()["occurred_at"] == "2026-10-05T13:41:07.250Z"
    assert event.occurred_at == WHEN


def test_signing_bytes_exclude_signature_and_are_stable() -> None:
    event = make_edge()
    signed = event.with_signature("ed25519:abc")
    assert event.signing_bytes() == signed.signing_bytes()
    assert b"signature" not in event.signing_bytes()
    assert event.canonical_bytes() != signed.canonical_bytes()


def test_tampered_payload_is_detected_by_hash() -> None:
    event = make_edge()
    tampered = event.model_copy(update={"payload": {"lane_id": "lane-9"}})
    assert not tampered.payload_hash_matches()


def test_event_ids_are_not_regenerated_on_rebuild_from_wire() -> None:
    event = make_edge()
    assert EdgeEvent.from_wire(json.loads(json.dumps(event.to_wire()))).event_id == event.event_id


def test_build_generates_uuid7_event_id() -> None:
    event = make_edge(event_id=None)
    assert event.event_id.version == 7


def test_domain_event_contract_fields_and_wire() -> None:
    correlation = uuid7()
    event = DomainEvent.new(
        society_id=SOCIETY,
        aggregate_type="visit",
        aggregate_id=ENTITY,
        aggregate_version=4,
        event_type="ApprovalDecided",
        actor_ref="person:0192f3a1-0000-7000-8000-0000000000aa",
        correlation_id=correlation,
        payload={"decision": "approve"},
        occurred_at=WHEN,
    )
    wire = event.to_wire()
    assert set(wire) == {
        "event_id", "schema_version", "society_id", "aggregate_type", "aggregate_id",
        "aggregate_version", "event_type", "occurred_at", "actor_ref", "correlation_id",
        "causation_id", "payload",
    }  # fmt: skip
    assert wire["schema_version"] == 1
    assert wire["causation_id"] is None
    assert DomainEvent.from_wire(wire) == event
    assert event.canonical_bytes() == canonical_json(wire)
    assert event.payload_hash() == payload_hash({"decision": "approve"})
    assert "ApprovalDecided" in KNOWN_EVENT_TYPES
    assert len(KNOWN_EVENT_TYPES) == 21


def test_domain_event_rejects_bad_input() -> None:
    kwargs: dict[str, object] = {
        "society_id": SOCIETY,
        "aggregate_type": "visit",
        "aggregate_id": ENTITY,
        "aggregate_version": 1,
        "event_type": "Bad Name",
        "actor_ref": "system:test",
        "correlation_id": uuid7(),
    }
    with pytest.raises(ValidationError):
        DomainEvent.new(**kwargs)  # type: ignore[arg-type]
    kwargs.update(event_type="Ok", schema_version=0)
    with pytest.raises(ValidationError):
        DomainEvent.new(**kwargs)  # type: ignore[arg-type]
