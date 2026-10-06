"""Device authentication: signature, replay window, clock skew, key and state attacks, rate limit, scrubbed logs.

REQ: EDGE-09 (per-device identity, revocation effective at once), EDGE-03, INV-01, OBS-01. Real mTLS is a deployment control and is not tested
(or claimed) here.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import uuid
from datetime import timedelta

import pytest

from dwaar_common.signing import generate_private_key
from tests.integration.edge._support import EdgeClient, EdgeWorld, iso, now

pytestmark = [pytest.mark.req("EDGE-09", "EDGE-03", "INV-01")]


def _shape(response: object) -> dict[str, object]:
    """The error body without the per-request id: every authentication failure must look exactly the same."""
    body = response.json()  # type: ignore[attr-defined]
    body.pop("request_id")
    return {"status": response.status_code, **body}  # type: ignore[attr-defined]


@pytest.fixture
def dev(ew: EdgeWorld) -> EdgeClient:
    return ew.edge_device()


def test_valid_request_is_accepted(dev: EdgeClient) -> None:
    assert dev.me().status_code == 200
    assert dev.policy().status_code == 200


def test_missing_headers_unknown_device_and_garbage_are_one_identical_401(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ok = dev.headers("GET", "/v1/edge/me")
    cases = {
        "none": {},
        "no_signature": {k: v for k, v in ok.items() if k != "X-Dwaar-Signature"},
        "no_timestamp": {k: v for k, v in ok.items() if k != "X-Dwaar-Timestamp"},
        "unknown_device": {**ok, "X-Dwaar-Device": str(uuid.uuid4())},
        "garbage_device": {**ok, "X-Dwaar-Device": "not-a-uuid"},
        "braced_uuid": {**ok, "X-Dwaar-Device": "{" + str(dev.device_id) + "}"},
        "garbage_signature": {**ok, "X-Dwaar-Signature": "ed25519:AAAA"},
        "empty_signature": {**ok, "X-Dwaar-Signature": ""},
        "huge_header": {**ok, "X-Dwaar-Signature": "ed25519:" + "A" * 5000},
        "bearer_token_is_not_device_auth": {"Authorization": "Bearer abc.def.ghi"},
    }
    shapes = {}
    for name, headers in cases.items():
        r = ew.client.get("/v1/edge/me", headers=headers)
        assert r.status_code == 401, name
        shapes[name] = _shape(r)
    assert all(s == shapes["none"] for s in shapes.values()), shapes
    assert shapes["none"]["code"] == "unauthenticated"


def test_tampered_signature_body_path_method_and_foreign_key_are_rejected(dev: EdgeClient) -> None:
    body = json.dumps({"device_id": str(dev.device_id), "events": []}).encode()
    good = dev.headers("POST", "/v1/edge/sync/batches", body)
    sig = good["X-Dwaar-Signature"]
    flipped = sig[:-3] + ("AAA" if not sig.endswith("AAA") else "BBB")
    r = dev.request(
        "POST", "/v1/edge/sync/batches", body=body, headers={"X-Dwaar-Signature": flipped}
    )
    assert r.status_code == 401
    # signed for another body: the body is swapped after signing
    other = json.dumps({"device_id": str(dev.device_id), "events": [], "cursor": 1}).encode()
    r = dev.request("POST", "/v1/edge/sync/batches", body=other, headers={k: good[k] for k in good})
    assert r.status_code == 401
    # signed for another path or query
    r = dev.request(
        "GET", "/v1/edge/policy?after=0", headers=dev.headers("GET", "/v1/edge/policy?after=1")
    )
    assert r.status_code == 401
    # signed for another method
    r = dev.request("GET", "/v1/edge/me", headers=dev.headers("POST", "/v1/edge/me"))
    assert r.status_code == 401
    # signed with a different key (an attacker who knows the device id)
    r = dev.request("GET", "/v1/edge/me", sign_as=generate_private_key())
    assert r.status_code == 401
    # a real device's key signing as ANOTHER device id
    r = dev.request("GET", "/v1/edge/me", headers={"X-Dwaar-Device": str(uuid.uuid4())})
    assert r.status_code == 401


def test_other_devices_key_cannot_speak_for_this_device(ew: EdgeWorld) -> None:
    a, b = ew.edge_device(), ew.edge_device()
    r = a.request("GET", "/v1/edge/me", sign_as=b.key)
    assert r.status_code == 401
    assert b.me().json()["device"]["id"] == str(b.device_id)


@pytest.mark.parametrize(
    ("offset_s", "expected"),
    [(0, 200), (-100, 200), (100, 200), (-125, 401), (125, 401), (-3600, 401), (86_400, 401)],
)
def test_clock_skew_window_is_plus_minus_120_seconds(
    dev: EdgeClient, offset_s: int, expected: int
) -> None:
    stamp = iso(now() + timedelta(seconds=offset_s))
    assert dev.request("GET", "/v1/edge/me", timestamp=stamp).status_code == expected


@pytest.mark.parametrize(
    "stamp",
    [
        "",
        "yesterday",
        "2026-10-05T13:41:07",
        "2026-10-05 13:41:07",
        "1759671667",
        "9999-99-99T00:00:00Z",
    ],
)
def test_malformed_or_naive_timestamps_are_rejected(dev: EdgeClient, stamp: str) -> None:
    r = dev.request("GET", "/v1/edge/me", timestamp=stamp, headers={"X-Dwaar-Timestamp": stamp})
    assert r.status_code == 401


def test_timestamp_is_part_of_the_signature(dev: EdgeClient) -> None:
    """Replaying an old capture with a refreshed timestamp header fails: the signature covers the timestamp."""
    old = iso(now() - timedelta(seconds=600))
    captured = dev.headers("GET", "/v1/edge/me", timestamp=old)
    refreshed = {**captured, "X-Dwaar-Timestamp": iso(now())}
    assert dev.request("GET", "/v1/edge/me", headers=refreshed).status_code == 401
    assert dev.request("GET", "/v1/edge/me", headers=captured).status_code == 401


def test_replay_inside_the_window_is_harmless_and_creates_nothing(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    """The documented limit: a captured request replays inside 120 s, but the endpoints are idempotent so nothing is created."""
    visit = ew.authorised_visit()
    body = json.dumps({"device_id": str(dev.device_id), "events": [dev.entry(visit)]}).encode()
    headers = dev.headers("POST", "/v1/edge/sync/batches", body)
    first = ew.client.post(
        "/v1/edge/sync/batches",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )
    again = ew.client.post(
        "/v1/edge/sync/batches",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert first.status_code == again.status_code == 200
    assert first.json()["outcomes"][0]["status"] == "accepted"
    assert again.json()["outcomes"][0]["status"] == "duplicate"
    assert ew.count("access_events") == 1
    assert ew.count("edge_events") == 1


def test_pending_and_rejected_devices_get_403_and_no_data(ew: EdgeWorld) -> None:
    pending = ew.edge_device(approve=False)
    for call in (pending.me, pending.policy):
        r = call()
        assert r.status_code == 403, r.text
        assert r.json()["code"] == "not_authorised"
        assert "seq" not in r.text and "manifest" not in r.text
    assert pending.sync([]).status_code == 403
    assert ew.count("edge_device_state", "device_id = %s", (pending.device_id,)) == 0
    # a rejected enrolment
    rejected = ew.edge_device(approve=False)
    version = ew.device_version(rejected.device_id)
    r = ew.call(
        ew.guard_sup, "POST", ew.s(f"devices/{rejected.device_id}/decision"),
        json={"decision": "reject", "expected_version": version, "reason": "unknown installer"},
    )  # fmt: skip
    assert r.status_code == 200, r.text
    assert rejected.me().status_code == 403


def test_revocation_takes_effect_on_the_very_next_request(ew: EdgeWorld, dev: EdgeClient) -> None:
    visit = ew.authorised_visit()
    assert dev.policy().status_code == 200
    assert dev.sync([]).status_code == 200
    ew.revoke_device(dev)
    for call in (
        dev.me,
        dev.policy,
        lambda: dev.sync([dev.entry(visit)]),
        lambda: dev.policy(after=0),
    ):
        r = call()
        assert r.status_code == 403, r.text
        assert "manifest" not in r.text and "outcomes" not in r.text
    assert ew.count("access_events") == 0
    assert ew.visit_state(visit) == "authorised"


def test_per_device_rate_limit_returns_429_with_retry_after(ew: EdgeWorld) -> None:
    cfg = ew.app.state.edge_config
    ew.app.state.edge_config = dataclasses.replace(cfg, rate_capacity=3, rate_refill_per_s=0.01)
    dev = ew.edge_device()
    other = ew.edge_device()
    codes = [dev.me().status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and set(codes[3:]) == {429}
    limited = dev.me()
    assert limited.headers["Retry-After"].isdigit()
    assert limited.json()["code"] == "rate_limited"
    assert other.me().status_code == 200  # budgets are per device


def test_logs_never_contain_signatures_keys_headers_or_raw_ids(
    ew: EdgeWorld, dev: EdgeClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    good = dev.headers("GET", "/v1/edge/me")
    forged = {**good, "X-Dwaar-Signature": "ed25519:" + "Q" * 86}
    ew.client.get("/v1/edge/me", headers=forged)
    ew.client.get("/v1/edge/me", headers={**good, "X-Dwaar-Device": str(uuid.uuid4())})
    dev.me()
    ew.revoke_device(dev)
    dev.me()
    blob = "\n".join(
        f"{r.getMessage()} {json.dumps(getattr(r, '__dict__', {}), default=str)}"
        for r in caplog.records
        if r.name.startswith(
            "dwaar_api"
        )  # the server's own loggers (httpx, the test client, logs URLs it was given)
    )
    assert any(r.name == "dwaar_api.edge.auth" for r in caplog.records)
    assert "Q" * 40 not in blob
    assert good["X-Dwaar-Signature"] not in blob
    assert "ed25519:" not in blob
    assert str(dev.device_id) not in blob
    assert good["X-Dwaar-Timestamp"] not in blob


def test_authentication_failures_are_counted_by_reason(ew: EdgeWorld, dev: EdgeClient) -> None:
    metrics = ew.app.state.edge_metrics
    before = metrics.total("auth_failures_total")
    ew.client.get("/v1/edge/me")
    dev.request("GET", "/v1/edge/me", sign_as=generate_private_key())
    assert metrics.total("auth_failures_total") == before + 2
    assert metrics.get("auth_failures_total", reason="missing_headers") >= 1
    assert metrics.get("auth_failures_total", reason="bad_signature") >= 1


def test_member_and_guard_tokens_do_not_open_the_edge_endpoints(ew: EdgeWorld) -> None:
    for who in (ew.guard, ew.guard_sup, ew.secretary):
        assert ew.client.get("/v1/edge/policy", headers=who.headers).status_code == 401
        assert (
            ew.client.post("/v1/edge/sync/batches", headers=who.headers, json={}).status_code == 401
        )


def test_device_credentials_do_not_open_the_society_endpoints(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    r = ew.client.get(
        f"/v1/societies/{ew.soc.id}/gates",
        headers=dev.headers("GET", f"/v1/societies/{ew.soc.id}/gates"),
    )
    assert r.status_code == 401
