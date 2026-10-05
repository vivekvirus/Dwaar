"""Idempotency-Key: replay, mismatch, binding, rollback semantics, and concurrent same-key serialisation."""

from __future__ import annotations

import datetime as dt
import json
import threading
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_api.core.authz import Grant
from dwaar_api.core.idempotency import request_hash
from tests.integration.core._support import (
    COMMITTEE_A,
    COMMITTEE_B,
    SOCIETY_A,
    SOCIETY_B,
    CoreHarness,
)

pytestmark = pytest.mark.req("INV-02", "INV-01")

URL = f"/v1/probe/{SOCIETY_A}/things"
ALT = f"/v1/probe/{SOCIETY_A}/things-alt"
EXTRA_COMMITTEE = uuid.UUID("0192f300-0000-7000-8000-0000000000c9")


def key() -> str:
    return "idem-" + uuid.uuid4().hex


def counts(core: CoreHarness) -> dict[str, int]:
    with core.db.admin_conn() as conn:
        out = {}
        for table in ("probe_things", "audit_log", "outbox", "idempotency_keys"):
            row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()  # type: ignore[call-overload]  # noqa: S608
            assert row is not None
            out[table] = int(row[0])
        return out


def post(
    client: TestClient,
    core: CoreHarness,
    k: str | None,
    body: dict[str, Any],
    url: str = URL,
    who: uuid.UUID = COMMITTEE_A,
) -> Any:
    headers = core.auth(who)
    if k is not None:
        headers["Idempotency-Key"] = k
    return client.post(url, json=body, headers=headers)


def test_header_is_required_and_validated(core: CoreHarness) -> None:
    with core.client() as client:
        missing = post(client, core, None, {"name": "x"})
        short = post(client, core, "short", {"name": "x"})
        spaces = post(client, core, "has spaces in it!", {"name": "x"})
    for res in (missing, short, spaces):
        assert res.status_code == 400
        assert res.json()["code"] == "invalid_schema"
    assert missing.json()["details"]["fields"] == [{"field": "Idempotency-Key", "issue": "missing"}]
    assert short.json()["details"]["fields"] == [
        {"field": "Idempotency-Key", "issue": "string_pattern_mismatch"}
    ]
    assert counts(core)["probe_things"] == 0


def test_replay_returns_stored_canonical_response_without_a_second_effect(
    core: CoreHarness,
) -> None:
    k = key()
    with core.client() as client:
        first = post(client, core, k, {"name": "Gate pass"})
        assert first.status_code == 201
        assert "idempotent-replayed" not in first.headers
        before = counts(core)
        assert before == {"probe_things": 1, "audit_log": 1, "outbox": 1, "idempotency_keys": 1}
        # the resource changes later; the replay must still return what was stored, not recompute it
        with core.db.owner_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
            conn.execute("UPDATE probe_things SET version = 9, name = 'renamed'")
        replay = post(client, core, k, {"name": "Gate pass"})
    assert replay.status_code == 201
    assert replay.headers["idempotent-replayed"] == "true"
    assert replay.json() == first.json()
    assert (
        replay.headers["x-request-id"] != first.headers["x-request-id"]
    )  # transport id is per request
    assert counts(core) == before  # no new thing, audit row, outbox row or key


def test_canonically_equal_json_is_the_same_request(core: CoreHarness) -> None:
    k = key()
    with core.client() as client:
        a = client.post(
            URL,
            content=b'{"name": "A", "phone": null}',
            headers={
                **core.auth(COMMITTEE_A),
                "Idempotency-Key": k,
                "Content-Type": "application/json",
            },
        )
        b = client.post(
            URL,
            content=b'{"phone":null,   "name":"A"}',
            headers={
                **core.auth(COMMITTEE_A),
                "Idempotency-Key": k,
                "Content-Type": "application/json",
            },
        )
    assert a.status_code == 201
    assert b.headers.get("idempotent-replayed") == "true"
    assert b.json() == a.json()
    assert counts(core)["probe_things"] == 1


def test_same_key_different_payload_is_409_and_changes_nothing(core: CoreHarness) -> None:
    k = key()
    with core.client() as client:
        assert post(client, core, k, {"name": "one"}).status_code == 201
        before = counts(core)
        clash = post(client, core, k, {"name": "two"})
    assert clash.status_code == 409
    body = clash.json()
    assert body["code"] == "duplicate_payload_mismatch"
    assert body["request_id"]
    assert counts(core) == before


def test_key_is_bound_to_the_endpoint(core: CoreHarness) -> None:
    k = key()
    with core.client() as client:
        assert post(client, core, k, {"name": "same body"}).status_code == 201
        other_endpoint = post(client, core, k, {"name": "same body"}, url=ALT)
    assert other_endpoint.status_code == 409
    assert other_endpoint.json()["code"] == "duplicate_payload_mismatch"
    assert counts(core)["probe_things"] == 1


def test_key_is_bound_to_the_actor(core: CoreHarness) -> None:
    core.resolver.add(EXTRA_COMMITTEE, Grant("committee", SOCIETY_A))
    k = key()
    with core.client() as client:
        first = post(client, core, k, {"name": "mine"}, who=COMMITTEE_A)
        second = post(client, core, k, {"name": "different actor, same key"}, who=EXTRA_COMMITTEE)
        replay_for_a = post(client, core, k, {"name": "mine"}, who=COMMITTEE_A)
    assert first.status_code == second.status_code == 201  # another actor's key is a different key
    assert second.json()["id"] != first.json()["id"]
    assert replay_for_a.headers["idempotent-replayed"] == "true"
    assert counts(core)["probe_things"] == 2


def test_key_is_bound_to_the_society(core: CoreHarness) -> None:
    core.resolver.add(COMMITTEE_A, Grant("committee", SOCIETY_B))  # one person, two societies
    k = key()
    with core.client() as client:
        in_a = post(client, core, k, {"name": "same"}, url=f"/v1/probe/{SOCIETY_A}/things")
        in_b = post(client, core, k, {"name": "same"}, url=f"/v1/probe/{SOCIETY_B}/things")
    assert in_a.status_code == in_b.status_code == 201
    assert in_a.json()["id"] != in_b.json()["id"]
    with core.db.admin_conn() as conn:
        societies = conn.execute("SELECT society_id FROM idempotency_keys").fetchall()
    assert {r[0] for r in societies} == {SOCIETY_A, SOCIETY_B}


def test_a_failed_request_stores_nothing_and_the_key_can_be_retried(core: CoreHarness) -> None:
    k = key()
    with core.client() as client:
        rejected = post(client, core, k, {"name": "__policy__"})
        crashed = post(client, core, key(), {"name": "__crash__"})
        assert counts(core) == {
            "probe_things": 0,
            "audit_log": 0,
            "outbox": 0,
            "idempotency_keys": 0,
        }
        retry = post(client, core, k, {"name": "now valid"})  # same key, corrected payload: allowed
    assert rejected.status_code == 422
    assert rejected.json()["code"] == "policy_violation"
    assert crashed.status_code == 500
    assert retry.status_code == 201
    assert counts(core)["probe_things"] == 1


def test_expired_key_can_be_reused(core: CoreHarness) -> None:
    k = key()
    with core.client() as client:
        first = post(client, core, k, {"name": "old"})
        with core.db.admin_conn() as conn:
            conn.execute("UPDATE idempotency_keys SET expires_at = now() - interval '1 minute'")
        again = post(client, core, k, {"name": "new content, expired key"})
    assert first.status_code == again.status_code == 201
    assert again.json()["id"] != first.json()["id"]
    assert "idempotent-replayed" not in again.headers
    with core.db.admin_conn() as conn:
        row = conn.execute(
            "SELECT state, expires_at > now(), response_body->>'name' FROM idempotency_keys"
        ).fetchone()
    assert row == ("completed", True, "new content, expired key")


def test_stored_row_shape(core: CoreHarness) -> None:
    k = key()
    with core.client() as client:
        post(client, core, k, {"name": "shape"})
    with core.db.admin_conn() as conn:
        row = conn.execute(
            "SELECT key, actor_id, society_id, endpoint, request_hash, state, response_status,"
            " completed_at IS NOT NULL, expires_at - created_at FROM idempotency_keys"
        ).fetchone()
    assert row is not None
    assert row[:3] == (k, COMMITTEE_A, SOCIETY_A)
    assert row[3] == "POST /v1/probe/{society_id}/things"
    assert row[4].startswith("sha256:")
    assert row[5:8] == ("completed", 201, True)
    # default retention is 7 days: longer than the 72 h offline buffer (NFR-09), so a queued offline retry
    # still finds its key (fix round 1, F11)
    assert (
        dt.timedelta(days=7) - dt.timedelta(minutes=1) < row[8] <= dt.timedelta(days=7, minutes=1)
    )


# ------------------------------------------------------------------------------------ concurrency
def _burst(core: CoreHarness, bodies: list[dict[str, Any]], keys: list[str]) -> list[Any]:
    results: list[Any] = [None] * len(bodies)
    barrier = threading.Barrier(len(bodies))

    def run(i: int) -> None:
        with core.client() as client:
            barrier.wait()
            results[i] = post(client, core, keys[i], bodies[i])

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(bodies))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert all(r is not None for r in results), "a request thread did not finish"
    return results


def test_concurrent_requests_with_the_same_key_run_the_work_once(core: CoreHarness) -> None:
    k = key()
    responses = _burst(core, [{"name": "slow:once"}] * 8, [k] * 8)
    assert [r.status_code for r in responses] == [201] * 8
    assert (
        len(
            {
                json.dumps({x: y for x, y in r.json().items() if x != "request_id"}, sort_keys=True)
                for r in responses
            }
        )
        == 1
    )
    replays = [r for r in responses if r.headers.get("idempotent-replayed") == "true"]
    assert len(replays) == 7  # exactly one request did the work; the rest waited and replayed
    assert counts(core) == {"probe_things": 1, "audit_log": 1, "outbox": 1, "idempotency_keys": 1}


def test_concurrent_same_key_with_different_payloads_one_wins_others_conflict(
    core: CoreHarness,
) -> None:
    k = key()
    responses = _burst(
        core, [{"name": "slow:alpha"}, {"name": "slow:beta"}, {"name": "slow:gamma"}], [k] * 3
    )
    assert sorted(r.status_code for r in responses) == [201, 409, 409]
    assert {r.json()["code"] for r in responses if r.status_code == 409} == {
        "duplicate_payload_mismatch"
    }
    assert counts(core)["probe_things"] == 1


def test_concurrent_requests_with_different_keys_all_succeed(core: CoreHarness) -> None:
    responses = _burst(
        core, [{"name": f"parallel-{i}"} for i in range(8)], [key() for _ in range(8)]
    )
    assert [r.status_code for r in responses] == [201] * 8
    assert counts(core) == {"probe_things": 8, "audit_log": 8, "outbox": 8, "idempotency_keys": 8}


def test_person_without_standing_in_the_society_is_told_not_found(core: CoreHarness) -> None:
    assert COMMITTEE_B != COMMITTEE_A
    with core.client() as client:
        res = post(client, core, key(), {"name": "x"}, who=COMMITTEE_B)
    assert res.status_code == 404  # COMMITTEE_B has no standing in society A


def test_request_hash_is_stable_and_discriminating() -> None:
    base = request_hash("POST", "/v1/x/1", "a=1&b=2", b'{"k": 1, "j": [1, 2]}')
    assert base == request_hash("post", "/v1/x/1", "b=2&a=1", b'{"j":[1,2],  "k":1}')
    assert base != request_hash("POST", "/v1/x/2", "a=1&b=2", b'{"k": 1, "j": [1, 2]}')
    assert base != request_hash("POST", "/v1/x/1", "a=1&b=3", b'{"k": 1, "j": [1, 2]}')
    assert base != request_hash("PUT", "/v1/x/1", "a=1&b=2", b'{"k": 1, "j": [1, 2]}')
    assert base != request_hash("POST", "/v1/x/1", "a=1&b=2", b'{"k": 1, "j": [2, 1]}')
    assert request_hash("POST", "/p", "", b"not json") != request_hash(
        "POST", "/p", "", b"not json!"
    )
    assert base.startswith("sha256:")
    assert len(base) == len("sha256:") + 64
