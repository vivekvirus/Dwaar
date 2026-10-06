"""AT-40 (M1): no device acknowledges an approval for 10 seconds -> alternate adult at t=10 s, IVR at t=20 s, link at t=35 s, expiry and guard-assisted
options at t=90 s, no auto-allow.

PRD 16: "No device acknowledges an approval for 10 seconds. Required outcome: Alternate adult notified at t=10 s, IVR at t=20 s, link at t=35 s, expiry and
guard-assisted options at t=90 s; no auto-allow."  PRD 9.4 NOTIF-03, Appendix C, D-15.

Dataset: the real seed (Pawar household of A-203: Ganesh is the primary approver, Rekha the configured alternate adult, fallback a masked call; both with a
SIMULATED registered phone), the real API and the real worker tick over the real database. SIMULATION: the providers are the labelled simulators, time is an
injected clock (the worker tick is told what "now" is), expiry is the database's own (the request is aged in the database, as AT-04 does).

What is proven here and what is not: the ORDER, the TIMES (on the injected clock, read from the rows), the roles reached and the absence of any allow. Nothing
here says a real phone would have been reached; no real provider exists in this build.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.acceptance._notify_world import Scene, scene
from tests.acceptance._world import DATASET, World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-40", dataset=DATASET),
    pytest.mark.req("NOTIF-03", "D-15", "INV-03", "INV-07", "CALL-02"),
]


def _secs(n: float) -> dt.timedelta:
    return dt.timedelta(seconds=n)


def _prepare(sc: Scene) -> str:
    """Rekha opts in to SMS links; the secretary registers the society's DLT header and template id on the seeded placeholder."""
    w = sc.world
    r = w.call(sc.rekha, "PUT", sc.s("notification-preferences/me"), json={
        "show_identity_on_lockscreen": False, "whatsapp_opt_in": False, "sms_opt_in": True, "language": "en"})  # fmt: skip
    assert r.status_code == 200, r.text
    listed = w.call(
        sc.secretary, "GET", sc.s("notification-templates"), params={"channel": "sms", "limit": 100}
    ).json()["items"]
    sms = next(t for t in listed if t["language"] == "en" and t["template_key"] == "approval.link")
    assert (
        sms["dlt_placeholder"] is True and sms["sendable"] is False
    )  # the seed invented no registration
    done = w.call(
        sc.secretary,
        "PUT",
        sc.s(f"notification-templates/{sms['id']}/dlt"),
        json={"dlt_header": "DWAARX", "dlt_template_id": "1107160000000000001"},
    )
    assert done.status_code == 200 and done.json()["sendable"] is True, done.text
    sc.phone("ganesh").force_stopped = True  # nobody's phone acknowledges
    sc.phone("rekha").force_stopped = True
    return str(sms["id"])


def test_at40_the_cascade_runs_on_the_pack_timings_and_never_allows(fresh_world: World) -> None:
    sc = scene(fresh_world)
    w = sc.world
    _prepare(sc)
    request = sc.raise_request("AT-40 courier")
    rid, t0 = request["id"], sc.created_at(request["id"])

    sc.tick(t0)  # t = 0: high-priority push to the selected household approver
    assert [(r["channel"], r["recipient_role"], r["cascade_step"]) for r in sc.rows(rid)] == [
        ("push", "primary", 1)
    ]
    sc.tick(t0 + _secs(9.9))
    assert len(sc.rows(rid)) == 1  # ten seconds have not passed: nobody else is bothered yet
    sc.tick(t0 + _secs(10))  # t = 10 s, no app acknowledgement: the configured alternate adult
    assert [(r["channel"], r["recipient_role"]) for r in sc.rows(rid)][-1] == ("push", "alternate")
    sc.tick(t0 + _secs(19.9))
    assert len(sc.rows(rid)) == 2
    sc.tick(t0 + _secs(20))  # t = 20 s, still pending: the masked IVR call to the primary
    assert [(r["channel"], r["recipient_role"]) for r in sc.rows(rid)][-1] == (
        "ivr_call",
        "primary",
    )
    sc.tick(t0 + _secs(34.9))
    assert len(sc.rows(rid)) == 3
    sc.tick(t0 + _secs(35))  # t = 35 s, still pending: the SMS link to the opted-in recipient
    rows = sc.rows(rid)
    assert [(r["channel"], r["recipient_role"]) for r in rows][-1] == ("sms", "opted_in")
    offsets = [round((r["created_at"] - t0).total_seconds(), 3) for r in rows]
    assert offsets == [0.0, 10.0, 20.0, 35.0]  # AT-40 timings, read from the rows (injected clock)
    assert sc.sims.sms.sent[-1].link.startswith("https://links.dwaar.example/r/")  # type: ignore[union-attr]  # a whitelisted URL only (CALL-02)
    assert sc.sims.sms.sent[-1].dlt_template_id == "1107160000000000001"

    # nothing was acknowledged, nothing was allowed, nothing is claimed as reached
    board = sc.board(sc.guard, rid)
    assert board["request_status"] == "pending" and board["summary"]["person_reached"] is False
    assert all(n["person_reached"] is False for n in board["notifications"])
    assert [s["issued"] for s in board["cascade"]["steps"]] == [True, True, True, True, False]
    assert w.admin_rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (rid,)
    ) == [(0,)]

    # t = 90 s: expiry (the database clock) and the guard-assisted options; NEVER an auto-allow
    sc.age(rid, 91)
    sc.tick(t0 + _secs(90))
    assert w.admin_rows(
        "SELECT state, permission_expires_at FROM approval_requests WHERE id = %s", (rid,)
    ) == [("expired", None)]
    assert w.admin_rows(
        "SELECT state, authorised_at, authorised_until FROM visits WHERE id = %s",
        (request["visit_id"],),
    ) == [("expired", None, None)]
    assert w.admin_rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (rid,)
    ) == [(0,)]
    after = sc.board(sc.guard, rid)
    assert after["request_status"] == "expired" and after["auto_allow_on_timeout"] is False
    assert set(after["guard_options"]) == {
        "hold",
        "leave_at_gate",
        "lobby_only",
        "intercom",
        "deny",
    }
    assert after["cascade"]["state"] == "expired" and {
        n["state"] for n in after["notifications"]
    } == {"expired"}
    sent = sc.sims.total_sent()
    for later in (95, 120, 600):
        sc.tick(t0 + _secs(later))
    assert sc.sims.total_sent() == sent  # nothing is sent after the end

    # the resident who comes back late sees the expiry; no permission can be created from it
    nid = w.admin_rows(
        "SELECT id FROM notifications WHERE request_id = %s AND recipient_role = 'primary' AND channel = 'push'",
        (rid,),
    )[0][0]
    late = w.call(
        sc.ganesh,
        "POST",
        sc.s(f"notifications/{nid}/action"),
        json={"action": "approve", "client_action_id": "00000000-0000-4000-8000-0000000000a4"},
    )
    assert late.status_code == 409 and late.json()["code"] == "request_expired"
    assert w.admin_rows(
        "SELECT count(*) FROM approval_decisions WHERE request_id = %s", (rid,)
    ) == [(0,)]


def test_at40_an_acknowledging_app_changes_the_path_but_never_the_outcome_by_itself(
    fresh_world: World,
) -> None:
    """If the primary's app DOES acknowledge, the alternate adult is not bothered at t=10 s; the cascade still goes on until somebody decides."""
    sc = scene(fresh_world)
    request = sc.raise_request("AT-40 control")
    rid, t0 = request["id"], sc.created_at(request["id"])
    sc.tick(t0)
    sc.tick(t0 + _secs(2))  # the simulated phone reports receipt and display
    sc.tick(t0 + _secs(10))
    assert [r["recipient_role"] for r in sc.rows(rid)] == ["primary"]
    assert sc.rows(rid)[0]["state"] == "displayed"
    assert fresh_world.admin_rows("SELECT state FROM approval_requests WHERE id = %s", (rid,)) == [
        ("pending",)
    ]  # acknowledged is not decided
