"""Local terminal API: authentication, flows, error shape, no direct DB access (EDGE-01, GATE-07, Appendix C)."""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dwaar_common.timeutil import format_iso_utc
from dwaar_edge.api import create_app
from tests.integration.edge_gateway.support import standard_world_with_policy

pytestmark = pytest.mark.req("EDGE-01", "GATE-07")

RES = {"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1}


@pytest.fixture
def env(tmp_path: Path):  # type: ignore[no-untyped-def]
    w, t, gw = standard_world_with_policy(tmp_path)
    client = TestClient(create_app(gw))
    tok = {
        "guard": gw.issue_terminal_token(w.term_a, "guard"),
        "sup": gw.issue_terminal_token(w.term_sup, "supervisor"),
    }
    yield w, t, gw, client, {k: {"Authorization": f"Bearer {v}"} for k, v in tok.items()}
    gw.stop()


def body(w, **kw):  # type: ignore[no-untyped-def]
    return {"gate_id": str(w.gate_a), "lane_id": str(w.lane_a_in), **kw}


def test_unauthenticated_calls_are_refused(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    assert c.get("/healthz").status_code == 200  # liveness only
    for path in ("/v1/terminal/status", "/v1/terminal/pending", "/v1/terminal/inside"):
        r = c.get(path)
        assert (
            r.status_code == 401
            and r.json()["code"] == "unauthenticated"
            and r.json()["request_id"]
        )
    assert c.get("/v1/terminal/status", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert c.get("/v1/terminal/status", headers={"Authorization": "Basic x"}).status_code == 401
    assert c.get("/openapi.json").status_code == 404 and c.get("/docs").status_code == 404


def test_revoked_token_stops_working(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    assert c.get("/v1/terminal/status", headers=h["guard"]).status_code == 200
    jti = gw.store.one("SELECT jti FROM terminal_tokens WHERE role='guard'")["jti"]
    gw.revoke_terminal_token(uuid.UUID(jti))
    assert c.get("/v1/terminal/status", headers=h["guard"]).status_code == 401


def test_evaluate_then_entry_then_exit_through_the_api(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    ev = c.post("/v1/terminal/evaluate", headers=h["guard"], json=body(w, credential=RES)).json()
    assert ev["decision"]["outcome"] == "allow" and ev["entry_observed"] is False
    e = c.post(
        "/v1/terminal/entries", headers=h["guard"], json=body(w, evaluation_id=ev["evaluation_id"])
    )
    assert e.status_code == 200 and e.json()["state"] == "inside"
    inside = c.get("/v1/terminal/inside", headers=h["guard"]).json()
    assert inside["count"] == 1 and inside["items"][0]["confidence"] == "observed"
    x = c.post(
        "/v1/terminal/exits",
        headers=h["guard"],
        json={
            "gate_id": str(w.gate_a),
            "lane_id": str(w.lane_a_out),
            "movement_id": e.json()["movement_id"],
        },
    )
    assert x.status_code == 200 and x.json()["state"] == "exited"
    assert c.get("/v1/terminal/inside", headers=h["guard"]).json()["count"] == 0


def test_error_shape_is_stable_and_safe(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    r = c.post("/v1/terminal/entries", headers=h["guard"], json=body(w, evaluation_id="nope"))
    assert r.status_code == 409 and set(r.json()) == {"code", "message", "request_id", "details"}
    assert r.json()["code"] == "no_authorising_decision"
    assert (
        c.post(
            "/v1/terminal/evaluate",
            headers=h["guard"],
            json={**body(w, credential=RES), "unexpected": 1},
        ).status_code
        == 422
    )
    assert (
        c.post("/v1/terminal/entries", headers=h["guard"], json=body(w)).json()["code"]
        == "authority_required"
    )


def test_guard_terminal_is_confined_to_its_assigned_gate(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    r = c.post(
        "/v1/terminal/evaluate",
        headers=h["guard"],
        json={"gate_id": str(w.gate_b), "lane_id": str(w.lane_b_in), "credential": RES},
    )
    assert r.status_code == 403 and r.json()["code"] == "gate_mismatch"


def test_override_is_supervisor_only_and_carries_a_reason(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    payload = {
        "supervisor_ref": "sup-1",
        "reason": "rush hour",
        "shift_end": format_iso_utc(t.wall_now + timedelta(hours=4)),
    }
    assert c.post("/v1/terminal/overrides", headers=h["guard"], json=payload).status_code == 403
    ok = c.post("/v1/terminal/overrides", headers=h["sup"], json=payload)
    assert ok.status_code == 200 and ok.json()["expires_at"] == format_iso_utc(
        t.wall_now + timedelta(hours=4)
    )
    assert (
        c.post(
            "/v1/terminal/overrides", headers=h["sup"], json={**payload, "reason": "x"}
        ).status_code
        == 422
    )
    assert c.get("/v1/terminal/review", headers=h["guard"]).status_code == 403


def test_emergency_entry_authority_and_reason(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    bad = c.post(
        "/v1/terminal/emergency-entries",
        headers=h["guard"],
        json=body(w, authority="neighbour", reason="please"),
    )
    assert bad.status_code == 403 and bad.json()["code"] == "authority_not_defined"
    good = c.post(
        "/v1/terminal/emergency-entries",
        headers=h["guard"],
        json=body(w, authority="medical_emergency", reason="ambulance for B-402"),
    )
    assert good.status_code == 200 and good.json()["entry_observed"] is True
    review = c.get("/v1/terminal/review", headers=h["sup"]).json()["items"]
    assert [i["kind"] for i in review] == ["emergency_entry"]


def test_pending_guard_decision_and_status_endpoints(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    ev = c.post(
        "/v1/terminal/evaluate", headers=h["guard"], json=body(w, credential={"kind": "none"})
    ).json()
    assert ev["decision"]["outcome"] == "needs_guard"
    pend = c.get("/v1/terminal/pending", headers=h["guard"]).json()["items"]
    assert [p["id"] for p in pend] == [ev["pending_id"]]
    d = c.post(
        "/v1/terminal/guard-decisions",
        headers=h["guard"],
        json={"pending_id": ev["pending_id"], "resolution": "intercom"},
    )
    assert d.status_code == 200 and d.json()["entry_observed"] is False
    s = c.get("/v1/terminal/status", headers=h["guard"]).json()
    assert (
        s["policy"]["seq"] == 1
        and "age_s" in s["policy"]
        and s["pending_count"] == 0
        and s["simulation"] is True
    )
    f = c.post("/v1/terminal/fresh-approvals", headers=h["guard"], json=body(w))
    assert f.json()["status"] == "fallback_required" and f.json()["auto_allow_on_timeout"] is False


def test_idempotent_replay_through_the_api(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    ev = c.post("/v1/terminal/evaluate", headers=h["guard"], json=body(w, credential=RES)).json()
    cid = str(uuid.uuid4())
    a = c.post(
        "/v1/terminal/entries",
        headers=h["guard"],
        json=body(w, evaluation_id=ev["evaluation_id"], client_action_id=cid),
    ).json()
    b = c.post(
        "/v1/terminal/entries",
        headers=h["guard"],
        json=body(w, evaluation_id=ev["evaluation_id"], client_action_id=cid),
    ).json()
    assert a["event_id"] == b["event_id"] and b["replayed"] is True


def test_feed_returns_new_items_and_long_poll_times_out_empty(env) -> None:  # type: ignore[no-untyped-def]
    w, t, gw, c, h = env
    first = c.get("/v1/terminal/feed", headers=h["guard"]).json()
    last = first["last_id"]
    c.post("/v1/terminal/evaluate", headers=h["guard"], json=body(w, credential=RES))
    nxt = c.get(f"/v1/terminal/feed?after={last}", headers=h["guard"]).json()
    assert [i["kind"] for i in nxt["items"]] == ["decision"]
    empty = c.get(
        f"/v1/terminal/feed?after={nxt['last_id']}&wait_ms=150", headers=h["guard"]
    ).json()
    assert empty["items"] == []


def test_api_layer_has_no_database_access() -> None:
    """Terminals never write to the SQLite file: the API module must not touch sqlite3 or the store directly."""
    import dwaar_edge.api as api

    src = open(api.__file__).read()  # noqa: SIM115, PTH123
    assert "sqlite3" not in src and "store." not in src and "EdgeStore" not in src
