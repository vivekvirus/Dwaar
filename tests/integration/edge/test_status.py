"""Device lifecycle hooks (``/v1/edge/me``, ``/v1/edge/keys``) and the metrics exposed for the observability slice.

REQ: EDGE-09, EDGE-04, OBS-02 (sync age, policy age, outbox backlog), OBS-03 (edge silent), SOC-05.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from tests.integration.edge._support import EdgeWorld

pytestmark = [pytest.mark.req("OBS-02", "EDGE-09")]


def test_me_reports_the_device_society_key_and_cursors(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    me = dev.me().json()
    assert me["device"]["id"] == str(dev.device_id) and me["device"]["society_id"] == str(ew.soc.id)
    assert (
        me["device"]["state"] == "active"
        and me["device"]["simulation"] is True
        and me["device"]["kind"] == "gateway"
    )
    assert me["device"]["gate_id"] == str(ew.gate_id) and me["device"]["key_id"].startswith("ed-")
    assert me["policy"] == {"latest_seq": 0, "applied_seq": 0, "latest_issued_at": None}
    assert me["sync"] == {"highest_contiguous_seq": 0, "last_sync_at": None}
    assert me["server_time"].endswith("Z")
    assert set(me["device"]) == {
        "id",
        "society_id",
        "kind",
        "name",
        "gate_id",
        "state",
        "key_id",
        "simulation",
        "last_seen_at",
    }
    dev.policy()
    dev.sync([dev.event("DeviceHealth", uuid.uuid4())])
    me = dev.me().json()
    assert (
        me["policy"]["latest_seq"] == 1
        and me["policy"]["applied_seq"] == 0
        and me["policy"]["latest_issued_at"]
    )
    assert me["sync"]["highest_contiguous_seq"] == 1 and me["sync"]["last_sync_at"]
    dev.policy(after=1)
    assert dev.me().json()["policy"]["applied_seq"] == 1


def test_last_seen_is_maintained_but_not_on_every_request(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    assert ew.rows("SELECT last_seen_at FROM devices WHERE id = %s", (dev.device_id,))[0][0] is None
    dev.me()
    first = ew.rows("SELECT last_seen_at FROM devices WHERE id = %s", (dev.device_id,))[0][0]
    assert first is not None
    dev.me()
    assert (
        ew.rows("SELECT last_seen_at FROM devices WHERE id = %s", (dev.device_id,))[0][0] == first
    )  # throttled
    assert (
        ew.rows("SELECT version FROM devices WHERE id = %s", (dev.device_id,))[0][0] == 2
    )  # touching it is not a domain change


def test_device_can_read_only_its_own_society_through_me(ew: EdgeWorld) -> None:
    rival = ew.idh.society("Rival Heights", units=("Z-1",))
    dev = ew.edge_device()
    assert dev.me().json()["device"]["society_id"] == str(ew.soc.id) != str(rival.id)


def test_status_gauges_sync_age_policy_age_backlog_and_outbox(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    status = ew.call(ew.guard_sup, "GET", ew.s("edge/status")).json()
    row = status["devices"][0]
    assert (
        status["latest_policy_seq"] is None
        and row["sync_age_s"] is None
        and row["policy_age_s"] is None
    )
    dev.policy()
    dev.policy(after=1)
    dev.sync(
        [
            dev.event("DeviceHealth", uuid.uuid4(), seq=1),
            dev.event("DeviceHealth", uuid.uuid4(), seq=4),
        ]
    )
    status = ew.call(ew.guard_sup, "GET", ew.s("edge/status")).json()
    row = next(d for d in status["devices"] if d["device_id"] == str(dev.device_id))
    assert status["latest_policy_seq"] == 1 and 0 <= status["latest_policy_age_s"] < 60
    assert status["latest_policy_expires_in_s"] > 71 * 3600
    assert (
        0 <= row["sync_age_s"] < 60
        and 0 <= row["policy_age_s"] < 60
        and row["policy_seq_applied"] == 1
    )
    assert (
        row["highest_contiguous_seq"] == 1 and row["edge_backlog_estimate"] == 3
    )  # seq 2..4 are unacknowledged
    assert status["outbox_backlog"] >= 2  # the relay has not run: events wait in the outbox
    ew.sql("UPDATE outbox SET published_at = now()")
    assert ew.call(ew.guard_sup, "GET", ew.s("edge/status")).json()["outbox_backlog"] == 0


def test_status_is_for_society_roles_not_residents_and_not_other_societies(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    assert ew.call(h.owner, "GET", ew.s("edge/status")).status_code == 403
    assert ew.call(ew.guard, "GET", ew.s("edge/status")).status_code == 403
    assert ew.call(ew.secretary, "GET", ew.s("edge/status")).status_code == 200
    assert ew.call(ew.person(), "GET", ew.s("edge/status")).status_code == 404


def test_counters_render_as_text_without_personal_data(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    dev.policy()
    dev.sync([dev.event("DeviceHealth", uuid.uuid4())])
    text = ew.app.state.edge_metrics.render_text()
    assert 'dwaar_edge_policy_polls_total{device="' in text and "# TYPE" in text
    assert ew.app.state.edge_metrics.snapshot()["batches_total"][0]["value"] == 1


def test_a_device_silent_for_minutes_is_visible_as_an_age(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    dev.sync([dev.event("DeviceHealth", uuid.uuid4())])
    ew.sql(
        "UPDATE edge_device_state SET last_sync_at = now() - %s::interval", (timedelta(minutes=7),)
    )
    row = ew.call(ew.guard_sup, "GET", ew.s("edge/status")).json()["devices"][0]
    assert (
        420 <= row["sync_age_s"] < 480
    )  # OBS-03: "edge silent over 5 minutes" can be alerted on this number
