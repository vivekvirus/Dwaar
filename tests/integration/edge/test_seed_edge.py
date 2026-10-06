"""The optional edge part of the synthetic seed (steps/s450_edge.py): a gateway with a deterministic LOCAL-ONLY key, standing rules, a signed
policy snapshot. The edge agent's own first requests are replayed against the seeded world exactly as the contract documents.

REQ: EDGE-04, EDGE-09, GATE-14, SOC-05, BUILD_BRIEF 7 (simulators are labelled; derived keys are worthless and local only).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

from dwaar_api import seed
from dwaar_api.modules.edge import localdev, localkeys
from dwaar_api.modules.edge.auth import sign_request_headers
from dwaar_api.seed.steps import s450_edge
from dwaar_common.events import EdgeEvent
from dwaar_common.signing import public_key_from_b64, sign_edge_event, verify_envelope
from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment

pytestmark = [pytest.mark.req("EDGE-04", "EDGE-09", "GATE-14")]


@pytest.fixture(scope="module")
def seeded(pg_server: PgServer, template_db: str) -> Iterator[World]:
    for handle in _clone(pg_server, template_db):
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("DWAAR_SEED_EDGE", "1")
            w = build_world(handle)
        try:
            yield w
        finally:
            w.database.dispose()


def _one(w: World, sql: str, *params: Any) -> Any:
    return w.admin_rows(sql, params)[0][0]


def signed(w: World, method: str, target: str, body: bytes = b"") -> Any:
    info = localdev.describe()
    key = localkeys.device_private_key(str(info["device_label"]))
    headers = sign_request_headers(key, uuid.UUID(str(info["device_id"])), method, target, body)
    if body:
        headers["Content-Type"] = "application/json"
    return w.client.request(method, target, headers=headers, content=body or None)


def test_step_is_on_by_default_and_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DWAAR_SEED_EDGE", raising=False)
    assert s450_edge.enabled() is True  # slice 3: default on (ADR-0019)
    monkeypatch.setenv("DWAAR_SEED_EDGE", "1")
    assert s450_edge.enabled() is True
    for off in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv("DWAAR_SEED_EDGE", off)
        assert s450_edge.enabled() is False
    assert s450_edge.ORDER == 450 and s450_edge.ORDER not in {
        m.ORDER for m in seed.discover_steps() if m is not s450_edge
    }


def test_gateways_exist_active_labelled_simulation_with_the_documented_key(seeded: World) -> None:
    rows = seeded.admin_rows(
        "SELECT name, kind, state, simulation, public_key FROM devices WHERE kind = 'gateway' ORDER BY name"
    )
    assert [(r[0], r[1], r[2], r[3]) for r in rows] == [
        ("Main gate edge gateway", "gateway", "active", True),
        ("Tower gate edge gateway", "gateway", "active", True),
    ]
    assert rows[0][4] == localkeys.device_public_key_b64("mh:Main gate edge gateway")
    # requested by a guard, approved by somebody else (maker != checker)
    assert (
        _one(
            seeded,
            "SELECT count(*) FROM devices WHERE kind = 'gateway' AND decided_by = requested_by",
        )
        == 0
    )


def test_ids_printed_by_localdev_are_the_real_ones(seeded: World) -> None:
    info = localdev.describe()
    assert info["simulation"] is True
    assert _one(
        seeded, "SELECT id FROM devices WHERE name = 'Main gate edge gateway'"
    ) == uuid.UUID(str(info["device_id"]))
    assert _one(seeded, "SELECT id FROM societies WHERE state = 'Maharashtra'") == uuid.UUID(
        str(info["society_id"])
    )


def test_the_edge_agent_can_authenticate_fetch_policy_and_sync_against_the_seeded_world(
    seeded: World,
) -> None:
    info = localdev.describe()
    me = signed(seeded, "GET", "/v1/edge/me")
    assert me.status_code == 200 and me.json()["device"]["society_id"] == info["society_id"]
    r = signed(seeded, "GET", "/v1/edge/policy?after=0")
    assert r.status_code == 200, r.text
    snap = r.json()
    assert snap["seq"] == 1 and snap["issuer_key_id"] == info["policy_issuer_key_id"]
    issuer = public_key_from_b64(
        str(info["policy_issuer_public_key"])
    )  # derived offline, as the contract says
    assert verify_envelope(issuer, snap)
    rules = snap["manifest"]["standing_rules"]
    assert {r["rule_kind"] for r in rules} == {"allow_window", "leave_at_gate"}
    assert len(snap["manifest"]["residents"]) > 20 and any(
        g["kind"] == "mixed" for g in snap["manifest"]["gates"]
    )
    assert any(
        i["revoked_version"] > 0 for i in snap["manifest"]["invitations"]
    )  # the seeded revoked pass is a tombstone
    assert (
        snap["manifest"]["revocations"][0]["version"]
        >= snap["manifest"]["revocations"][-1]["version"]
    )
    assert signed(seeded, "GET", "/v1/edge/policy?after=1").status_code == 204
    key = localkeys.device_private_key(str(info["device_label"]))
    ev = sign_edge_event(
        key,
        EdgeEvent.build(
            society_id=uuid.UUID(str(info["society_id"])), device_id=uuid.UUID(str(info["device_id"])), seq=1, entity_id=uuid.uuid4(),
            entity_version=1, type="DeviceHealth", policy_version=1, payload={"disk_pct": 12}, occurred_at=datetime.now(UTC),
        ),
    )  # fmt: skip
    body = json.dumps({"device_id": info["device_id"], "events": [ev.to_wire()]}).encode()
    out = signed(seeded, "POST", "/v1/edge/sync/batches", body)
    assert out.status_code == 200 and out.json()["outcomes"][0]["status"] == "accepted"
    assert out.json()["highest_contiguous_seq"] == 1 and out.json()["policy_cursor"] == {
        "latest_seq": 1
    }


def test_the_other_societys_gateway_gets_its_own_policy_only(seeded: World) -> None:
    ka_device = seeded.admin_rows(
        "SELECT id, society_id FROM devices WHERE name = 'Tower gate edge gateway'"
    )[0]
    mh_society = _one(seeded, "SELECT id FROM societies WHERE state = 'Maharashtra'")
    key = localkeys.device_private_key("ka:Tower gate edge gateway")
    headers = sign_request_headers(key, ka_device[0], "GET", "/v1/edge/policy")
    snap = seeded.client.get("/v1/edge/policy", headers=headers).json()
    assert snap["society_id"] == str(ka_device[1]) != str(mh_society)
    text = json.dumps(snap)
    assert "Main Gate" not in text
    mh_units = {
        str(r[0])
        for r in seeded.admin_rows("SELECT id FROM units WHERE society_id = %s", (mh_society,))
    }
    assert not mh_units & {r["unit_id"] for r in snap["manifest"]["residents"]}


def test_rerunning_the_seed_changes_nothing(seeded: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DWAAR_SEED_EDGE", "1")
    before = {
        t: _one(seeded, f"SELECT count(*) FROM {t}")
        for t in ("devices", "policy_snapshots", "standing_rules", "edge_credential_refs")
    }  # noqa: S608
    result = seed.run(seed_environment(seeded.db), say=lambda _line: None)
    after = {t: _one(seeded, f"SELECT count(*) FROM {t}") for t in before}  # noqa: S608
    assert before == after
    assert not any(
        result.counts.get(k)
        for k in ("devices_enrolled", "standing_rules_created", "policy_snapshots_created")
    )


def test_the_seeded_data_has_audit_and_outbox_rows(seeded: World) -> None:
    assert (
        _one(
            seeded,
            "SELECT count(*) FROM audit_log WHERE operation IN ('edge.policy_publish', 'standing_rule.create')",
        )
        >= 4
    )
    assert _one(seeded, "SELECT count(*) FROM outbox WHERE event_type = 'PolicyPublished'") == 2
