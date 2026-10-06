"""FakeCloud versus the REAL cloud: the same signed requests to both, outcome by outcome (ADR-0019, conformance).

The fake is registered with the SAME device id and key as the real enrolment, so identical bytes go to both. Every case below is either
asserted EQUAL on both sides or listed in ``KNOWN_DIFFERENCES`` with the reason: a difference nobody documented fails this test.
SIMULATION (loopback, one machine).
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from dwaar_common.events import EdgeEvent
from dwaar_common.signing import generate_private_key, sign_edge_event
from dwaar_edge.sync import HttpxTransport
from tests.integration.edge._support import EdgeWorld
from tests.integration.edge_e2e._cloud import Site
from tests.integration.edge_gateway.fakecloud import FakeCloud

pytestmark = [pytest.mark.req("EDGE-03", "EDGE-07"), pytest.mark.simulation]

#: case -> why the real cloud and the fake legitimately answer differently
KNOWN_DIFFERENCES: dict[str, str] = {
    "entry_twice_same_entity": "the fake keeps a toy entity state machine; the real cloud records both observations of an edge-local movement",
    "exit_without_entry": "the real cloud rejects (and opens an exception for) an exit with no earlier entry of the movement; the fake accepts",
    "unknown_type": "same status; the real cloud adds reason=recorded_not_projected",
}


class Both:
    def __init__(self, site: Site) -> None:
        self.site = site
        self.fake = FakeCloud(site.ew.soc.id, site.now)
        self.fake.register_device(site.device.device_id, site.device.key.public_key())
        self.fake_t = self.fake.transport()
        self.real_t = HttpxTransport(site.live.url)
        self.seq = 0

    def headers(self, method: str, target: str, body: bytes, key: Any = None) -> dict[str, str]:
        h = self.site.client.signed_headers(method, target, body, self.site.now())
        if key is not None:
            import hashlib

            from dwaar_common.signing import sign_bytes

            canonical = f"{method}\n{target}\n{h['X-Dwaar-Timestamp']}\n{hashlib.sha256(body).hexdigest()}".encode()
            h["X-Dwaar-Signature"] = sign_bytes(key, canonical)
        return h

    def post(self, body: bytes, **kw: Any) -> tuple[Any, Any]:
        h = self.headers("POST", "/v1/edge/sync/batches", body, **kw)
        return (
            self.fake_t.request("POST", "/v1/edge/sync/batches", h, body),
            self.real_t.request("POST", "/v1/edge/sync/batches", h, body),
        )

    def get(self, target: str, **kw: Any) -> tuple[Any, Any]:
        h = self.headers("GET", target, b"", **kw)
        return self.fake_t.request("GET", target, h, b""), self.real_t.request(
            "GET", target, h, b""
        )

    def event(self, **kw: Any) -> dict[str, Any]:
        self.seq += 1
        s = self.site
        payload = kw.pop(
            "payload",
            {
                "gate_id": str(s.gate_a),
                "lane_id": str(s.lane_a_in),
                "decision_source": "cached_policy",
                "credential_kind": "resident_app",
            },
        )
        base = EdgeEvent.build(
            society_id=kw.pop("society_id", s.ew.soc.id), device_id=s.device.device_id, seq=kw.pop("seq", self.seq),
            entity_id=kw.pop("entity_id", uuid.uuid4()), entity_version=1, type=kw.pop("type", "EntryObserved"),
            policy_version=1, payload=payload, occurred_at=datetime.now(UTC) - timedelta(seconds=5), clock_uncertainty_ms=50,
        )  # fmt: skip
        return sign_edge_event(kw.pop("signer", s.device.key), base).to_wire()

    def batch(self, events: list[Any]) -> bytes:
        return json.dumps(
            {"device_id": str(self.site.device.device_id), "events": events}, separators=(",", ":")
        ).encode()


def outcome_of(resp: Any) -> list[tuple[str, str | None]]:
    return [(o["status"], o.get("reason")) for o in resp.json["outcomes"]]


def statuses_of(resp: Any) -> list[str]:
    return [o["status"] for o in resp.json["outcomes"]]


@pytest.fixture
def both(ew: EdgeWorld, site: Site) -> Both:
    ew.household("A-101", tenant=False, family=False)
    site.sync()
    return Both(site)


def test_valid_duplicate_forged_and_foreign_events_get_the_same_answers(both: Both) -> None:
    e1, e2 = both.event(), both.event()
    f, r = both.post(both.batch([e1, e2]))
    assert f.status == r.status == 200 and statuses_of(f) == statuses_of(r) == [
        "accepted",
        "accepted",
    ]
    assert (
        f.json["highest_contiguous_seq"] == r.json["highest_contiguous_seq"] == 2
        and f.json["gaps"] == r.json["gaps"] == []
    )
    f, r = both.post(both.batch([e1]))  # identical resend
    assert statuses_of(f) == statuses_of(r) == ["duplicate"]
    forged = both.event(signer=generate_private_key())
    foreign = both.event(society_id=uuid.uuid4())
    f, r = both.post(both.batch([forged, foreign]))
    assert (
        outcome_of(f)
        == outcome_of(r)
        == [("quarantined", "bad_signature"), ("quarantined", "wrong_society")]
    )
    assert (
        f.json["highest_contiguous_seq"] == r.json["highest_contiguous_seq"] == 4
    )  # quarantined seqs are disposed: the cursor moves on


def test_gaps_and_late_fill_are_computed_alike(both: Both) -> None:
    ahead = [both.event(seq=10), both.event(seq=12)]
    f, r = both.post(both.batch(ahead))
    assert f.json["highest_contiguous_seq"] == r.json["highest_contiguous_seq"] == 0
    assert f.json["gaps"] == r.json["gaps"] == [[1, 9], [11, 11]]
    fill = [both.event(seq=s) for s in (1, 2, 3, 4, 5, 6, 7, 8, 9, 11)]
    f, r = both.post(both.batch(fill))
    assert (
        f.json["highest_contiguous_seq"] == r.json["highest_contiguous_seq"] == 12
        and f.json["gaps"] == r.json["gaps"] == []
    )


def test_conflicting_seq_oversized_payload_and_unknown_type_are_judged_alike(both: Both) -> None:
    first = both.event(seq=1)
    both.post(both.batch([first]))
    clash = both.event(seq=1)  # same seq, another event id
    big = both.event(
        seq=2,
        payload={
            "gate_id": str(both.site.gate_a),
            "lane_id": str(both.site.lane_a_in),
            "pad": "x" * 2100,
        },
    )
    odd = both.event(seq=3, type="SomethingNew")
    f, r = both.post(both.batch([clash, big, odd]))
    assert (
        outcome_of(f)[:2]
        == outcome_of(r)[:2]
        == [("quarantined", "seq_conflict"), ("quarantined", "payload_too_large")]
    )
    assert (
        statuses_of(f)[2] == statuses_of(r)[2] == "accepted"
    )  # KNOWN_DIFFERENCES['unknown_type']: reason only on the real cloud


def test_limits_and_request_authentication_answer_alike(both: Both) -> None:
    f, r = both.post(both.batch([{"x": i} for i in range(501)]))
    assert f.status == r.status == 413
    big = both.batch([{"x": "y" * 1000} for _ in range(1100)])
    assert len(big) > 1_048_576
    f, r = both.post(big)
    assert f.status == r.status == 413
    wrong = json.dumps({"device_id": str(uuid.uuid4()), "events": []}).encode()
    f, r = both.post(wrong)
    assert f.status == r.status == 400
    f, r = both.post(both.batch([]), key=generate_private_key())
    assert f.status == r.status == 401
    h = both.site.client.signed_headers(
        "GET", "/v1/edge/policy?after=0", b"", both.site.now() - timedelta(minutes=3)
    )  # outside +-120 s
    assert (
        both.fake_t.request("GET", "/v1/edge/policy?after=0", h, b"").status
        == both.real_t.request("GET", "/v1/edge/policy?after=0", h, b"").status
        == 401
    )


def test_policy_cursor_answers_alike_for_behind_equal_and_ahead(both: Both) -> None:
    real_latest = both.site.device.policy(0).json()
    both.fake.publish_policy(real_latest)  # the fake serves the very snapshot the real cloud signed
    seq = real_latest["seq"]
    for after, expected in ((seq - 1, 200), (seq, 204), (seq + 1, 409)):
        f, r = both.get(f"/v1/edge/policy?after={after}")
        assert f.status == r.status == expected, after
    f, r = both.get(f"/v1/edge/policy?after={seq - 1}")
    assert f.json == r.json == real_latest


def test_the_known_differences_are_exactly_the_documented_ones(both: Both) -> None:
    entity = uuid.uuid4()
    again = [both.event(entity_id=entity), both.event(entity_id=entity)]
    f, r = both.post(both.batch(again))
    assert statuses_of(r) == [
        "accepted",
        "accepted",
    ]  # real: two observations of one edge-local movement are both recorded
    assert statuses_of(f) == ["accepted", "rejected_transition"]  # fake: toy entity machine
    lone_exit = both.event(
        type="ExitObserved", payload={"gate_id": str(both.site.gate_a), "exit_basis": "observed"}
    )
    f, r = both.post(both.batch([lone_exit]))
    assert statuses_of(r) == ["rejected_transition"] and statuses_of(f) == ["accepted"]
    assert set(KNOWN_DIFFERENCES) == {
        "entry_twice_same_entity",
        "exit_without_entry",
        "unknown_type",
    }
