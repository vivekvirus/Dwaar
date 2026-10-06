"""Edge-side fixes found by running the gateway against the REAL cloud (docs/adr/0019): Retry-After, revoked and departed passes, provisioning.

REQ: EDGE-03 (backoff honours the cloud), EDGE-04 (trust anchors are provisioned, never taken from a snapshot), GATE-01, INV-07.
These are unit-level twins of the end-to-end tests in tests/integration/edge_e2e (which need the cloud and a database).
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from dwaar_common.signing import generate_private_key
from dwaar_edge.policy_model import Invitation
from dwaar_edge.provision import ProvisioningError, fetch_trust_anchors
from dwaar_edge.sync import (
    HttpxTransport,
    SyncClient,
    SyncConfig,
    TransportError,
    TransportResponse,
)
from tests.integration.edge_gateway.fakecloud import FakeCloud
from tests.integration.edge_gateway.support import (
    START,
    ManualTime,
    World,
    standard_world_with_policy,
)

pytestmark = pytest.mark.req("EDGE-03", "EDGE-04")


# ------------------------------------------------------------------------------------------ Retry-After
class Throttling:
    """A cloud that answers 429 with a Retry-After, then behaves."""

    def __init__(self, inner: Any, retry_after: float | None) -> None:
        self.inner, self.retry_after, self.refused = inner, retry_after, 0

    def request(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> TransportResponse:
        if method == "POST" and self.refused < 1:
            self.refused += 1
            return TransportResponse(429, {"code": "rate_limited"}, None, 0, self.retry_after)
        return self.inner.request(method, target, headers, body)


def test_a_429_with_retry_after_delays_the_next_attempt_at_least_that_long(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        cloud = FakeCloud(w.society_id, t.wall)
        cloud.register_device(w.gateway_device, w.device_signer.public_key)
        gw.outbox.append(
            type="EntryObserved",
            entity_id=uuid.uuid4(),
            entity_version=1,
            payload={"gate_id": "g"},
            occurred_at=t.wall_now,
            clock_uncertainty_ms=50,
            policy_version=1,
        )
        client = SyncClient(
            gw,
            Throttling(cloud.transport(), 42.0),
            SyncConfig(backoff_base_s=0.5, backoff_cap_s=1.0),
            sleep=lambda s: None,
            rng=random.Random(3),
        )
        first = client.sync_once()
        assert first.failed and "429" in first.failed
        assert first.next_delay_s >= 42.0  # the jittered backoff alone would have been at most 1 s
        assert client.sync_once().acked == 1  # and the next attempt gets through; nothing was lost
    finally:
        gw.stop()


def test_without_a_retry_after_the_backoff_is_unchanged(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        cloud = FakeCloud(w.society_id, t.wall)
        cloud.register_device(w.gateway_device, w.device_signer.public_key)
        gw.outbox.append(
            type="EntryObserved",
            entity_id=uuid.uuid4(),
            entity_version=1,
            payload={"gate_id": "g"},
            occurred_at=t.wall_now,
            clock_uncertainty_ms=50,
            policy_version=1,
        )
        client = SyncClient(
            gw,
            Throttling(cloud.transport(), None),
            SyncConfig(backoff_base_s=0.5, backoff_cap_s=1.0),
            sleep=lambda s: None,
            rng=random.Random(3),
        )
        assert 0 <= client.sync_once().next_delay_s <= 1.0
    finally:
        gw.stop()


@pytest.mark.parametrize(
    ("header", "expected"),
    [("7", 7.0), ("0", 0.0), ("999999", 3600.0), ("soon", None), ("-5", 0.0)],
)
def test_the_transport_reads_retry_after_and_never_obeys_an_absurd_one(
    header: str, expected: float | None
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": header}, json={"code": "rate_limited"})

    transport = HttpxTransport("http://cloud.invalid")
    transport._client = httpx.Client(
        base_url="http://cloud.invalid", transport=httpx.MockTransport(handler)
    )  # noqa: SLF001
    assert transport.request("GET", "/v1/edge/policy?after=0", {}, b"").retry_after_s == expected


# ------------------------------------------------------------------------------------------ revoked and departed passes
def invitation(**kw: Any) -> Invitation:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "gate_id": None, "window_start": START, "window_end": START + timedelta(hours=3), "max_uses": 4,
        "uses_remaining": 4, "revoked_version": 0, "nonce": "nonce-abcdefgh", "kind": "guest",
    }  # fmt: skip
    base.update(kw)
    return Invitation.model_validate(base)


def test_a_revoked_pass_publishes_zero_remaining_uses_which_says_nothing_about_use() -> None:
    live = invitation(uses_remaining=1)
    revoked = invitation(
        uses_remaining=0, revoked_version=7
    )  # the real cloud's shape for a revoked pass
    assert live.cloud_used == 3
    assert revoked.cloud_used == 0  # not 'all four uses were consumed'
    assert (
        invitation(uses_remaining=0, revoked_version=None).cloud_used == 4
    )  # an exhausted live pass still is


def test_entries_before_a_revocation_are_not_flagged_as_reuse_after_the_revoked_snapshot_arrives(
    tmp_path: Path,
) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        inv_id = uuid.uuid4()
        gw.apply_policy(
            w.snapshot(
                seq=2,
                issued_at=t.wall_now,
                manifest=w.manifest(
                    residents=[w.resident()],
                    invitations=[
                        w.invitation(
                            inv_id,
                            gate=None,
                            start=t.wall_now - timedelta(minutes=5),
                            end=t.wall_now + timedelta(hours=3),
                            max_uses=4,
                        )
                    ],
                ),
            )
        )
        # the cloud revokes the pass later: uses_remaining 0 and a revoked_version
        t.advance(3600)
        gw.apply_policy(
            w.snapshot(
                seq=3,
                issued_at=t.wall_now,
                manifest=w.manifest(
                    residents=[w.resident()],
                    invitations=[
                        w.invitation(
                            inv_id,
                            gate=None,
                            start=t.wall_now - timedelta(hours=2),
                            end=t.wall_now + timedelta(hours=1),
                            max_uses=4,
                            uses_remaining=0,
                            revoked_version=3,
                        )
                    ],
                    revocations=[{"ref": str(inv_id), "version": 3}],
                ),
            )
        )
        actor = w.actor(gw, w.term_a)
        with gw.store.transaction() as c:
            flagged = gw._consume_pass(
                c, inv_id, None, w.gate_a, actor.device_id, uuid.uuid4(), t.wall_now
            )  # noqa: SLF001
        assert (
            flagged is False
        )  # the first use of a four-use pass is a use, whatever the revoked row says
    finally:
        gw.stop()


def test_a_pass_that_left_the_policy_is_judged_by_the_limit_the_observer_knew_not_by_a_guess_of_one(
    tmp_path: Path,
) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        gone = (
            uuid.uuid4()
        )  # never in this policy: the cloud only publishes passes that are still live
        actor = w.actor(gw, w.term_a)
        with gw.store.transaction() as c:
            first = gw._consume_pass(
                c, gone, None, w.gate_a, actor.device_id, uuid.uuid4(), t.wall_now, 4
            )  # noqa: SLF001
            second = gw._consume_pass(
                c, gone, None, w.gate_a, actor.device_id, uuid.uuid4(), t.wall_now, 4
            )  # noqa: SLF001
            unknown_limit = gw._consume_pass(
                c, gone, None, w.gate_a, actor.device_id, uuid.uuid4(), t.wall_now, None
            )  # noqa: SLF001
        assert (first, second) == (False, False)
        assert (
            unknown_limit is True
        )  # without a stated limit the old conservative reading (one use) still flags
    finally:
        gw.stop()


# ------------------------------------------------------------------------------------------ provisioning
class Canned:
    def __init__(self, status: int, body: Any) -> None:
        self.status, self.body = status, body
        self.seen: list[tuple[str, str, dict[str, str]]] = []

    def request(
        self, method: str, target: str, headers: dict[str, str], payload: bytes
    ) -> TransportResponse:
        self.seen.append((method, target, headers))
        return TransportResponse(self.status, self.body)


def test_provisioning_signs_the_request_with_the_device_key_and_pins_both_key_lists() -> None:
    w = World()
    device, key = uuid.uuid4(), generate_private_key()
    body = {
        "keys": [
            {
                "key_id": "policy-1",
                "public_key": _b64(w.issuer.public_key),
                "status": "active",
                "simulation": True,
            }
        ],
        "pass_keys": [
            {
                "key_id": "pass-1",
                "public_key": _b64(w.pass_signer.public_key),
                "status": "active",
                "simulation": True,
            }
        ],
    }
    transport = Canned(200, body)
    anchors = fetch_trust_anchors(transport, device, key, now=ManualTime().wall_now)
    method, target, headers = transport.seen[0]
    assert (
        (method, target) == ("GET", "/v1/edge/keys")
        and headers["X-Dwaar-Device"] == str(device)
        and headers["X-Dwaar-Signature"].startswith("ed25519:")
    )
    assert (
        set(anchors.issuer_keys) == {"policy-1"}
        and set(anchors.pass_keys) == {"pass-1"}
        and anchors.simulation is True
    )
    lines = anchors.env_lines()
    assert lines["DWAAR_EDGE_ISSUER_KEYS"].startswith("policy-1=") and lines[
        "DWAAR_EDGE_PASS_KEYS"
    ].startswith("pass-1=")
    assert set(anchors.fingerprints()) == {"issuer:policy-1", "pass:pass-1"}


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (401, {"code": "unauthenticated"}),
        (403, {"code": "not_authorised"}),
        (200, {"keys": []}),
        (200, {"keys": "nope"}),
        (200, {"keys": [{"key_id": "k", "public_key": "short"}]}),
        (200, None),
    ],
)
def test_provisioning_refuses_anything_unusable_and_pins_nothing(status: int, body: Any) -> None:
    with pytest.raises(ProvisioningError):
        fetch_trust_anchors(Canned(status, body), uuid.uuid4(), generate_private_key())


def test_provisioning_reports_an_unreachable_cloud_as_a_provisioning_error() -> None:
    class Down:
        def request(self, *a: Any) -> TransportResponse:
            raise TransportError("connection refused")

    with pytest.raises(ProvisioningError):
        fetch_trust_anchors(Down(), uuid.uuid4(), generate_private_key())


def _b64(pub: Any) -> str:
    from dwaar_common.signing import public_key_to_b64

    return public_key_to_b64(pub)
