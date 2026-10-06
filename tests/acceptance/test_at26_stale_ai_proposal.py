"""AT-26 (M1): an AI proposal is confirmed after the user's role or the target changed -> revalidation fails; a new proposal is required.

PRD 16: "AI proposal confirmed after role or target change. Required outcome: Revalidation fails; new proposal required."
PRD 10.1 / AI-SYS-04 (confirmation binds to the payload hash; execution re-checks role, target version, budget and idempotency), INV-06.

Dataset: the real seed (Sahyadri Residency = A), real API, real OTP/TOTP sign-in through the labelled local simulator. ``ganesh`` is the
owner-occupier of A-203; ``mh.secretary`` is the secretary of A. The ticket module does not exist yet: the executor is a FAKE behind the narrow
``ticket_create`` port, which makes 'nothing was executed' observable. The proposals come from the deterministic SIMULATOR (``simulation=true``).

Scenarios: (1) the unit changed after the draft (the secretary edits it through the real organisation API); (2) the role changed (Ganesh no
longer lives in the unit, so he is now a non-resident owner); (3) the standing ended; (4) the payload hash does not match; (5) in every case a
NEW proposal made under the current state confirms.
"""

from __future__ import annotations

import pytest

from tests.acceptance._world import DATASET, World
from tests.integration.ai._support import FakePort, install_runtime

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-26", dataset=DATASET),
    pytest.mark.req("AI-SYS-04", "INV-06", "IAM-08"),
]

COMPLAINT = {"transcript": "Water is leaking in flat A-203 kitchen pipe"}


def _setup(world: World):  # type: ignore[no-untyped-def]
    mh = world.society_ref("mh")
    sec = world.login("mh.secretary")
    r = world.call(
        sec,
        "PUT",
        f"/v1/societies/{mh.id}/quotas",
        json={"ai_requests_per_day": 50},
        headers={"X-Society-Id": str(mh.id)},
    )
    assert r.status_code == 200, r.text
    rt = install_runtime(world.app)
    port = FakePort("ticket_create")
    rt.ports["ticket_create"] = port  # type: ignore[assignment]
    return mh, sec, port


def _propose(world: World, who, society) -> dict:  # type: ignore[no-untyped-def,type-arg]
    r = world.call(
        who,
        "POST",
        "/v1/ai/proposals",
        json={"feature_id": "AI-R02", "inputs": COMPLAINT},
        headers={"X-Society-Id": str(society.id)},
    )
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    p: dict = r.json()["proposal"]  # type: ignore[type-arg]
    assert p["state"] == "proposed" and p["target_ids"] == [str(society.unit("A", "203"))]
    return p


def _confirm(world: World, who, society, p, **body):  # type: ignore[no-untyped-def]
    return world.call(
        who,
        "POST",
        f"/v1/ai/proposals/{p['id']}/confirm",
        json={"payload_hash": p["payload_hash"], **body},
        headers={"X-Society-Id": str(society.id)},
    )


def test_a_proposal_confirmed_after_the_target_changed_fails_revalidation_and_needs_a_new_one(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh, sec, port = _setup(world)
    ganesh = world.login("ganesh")
    p = _propose(world, ganesh, mh)
    unit = mh.unit("A", "203")
    got = world.call(sec, "GET", f"/v1/societies/{mh.id}/units/{unit}")
    moved = world.call(
        sec,
        "PATCH",
        f"/v1/societies/{mh.id}/units/{unit}",
        json={"floor": 9, "expected_version": got.json()["version"]},
    )
    assert moved.status_code == 200 and moved.json()["version"] == p["target_versions"][0] + 1
    late = _confirm(world, ganesh, mh, p)
    assert late.status_code == 409 and late.json()["code"] == "stale_version"
    assert late.json()["details"] == {"reason": "target_changed", "new_proposal_required": True}
    assert port.calls == []  # nothing executed
    assert world.admin_rows("SELECT state FROM action_proposals") == [("proposed",)]
    fresh = _propose(world, ganesh, mh)  # the NEW proposal is bound to the new version and confirms
    assert fresh["target_versions"] == [moved.json()["version"]] and fresh["id"] != p["id"]
    ok = _confirm(world, ganesh, mh, fresh)
    assert ok.status_code == 200 and ok.json()["state"] == "confirmed" and len(port.calls) == 1
    assert world.admin_rows("SELECT outcome FROM ai_runs ORDER BY id") == [
        (None,),
        ("accepted",),
    ]  # the stale run stays undecided: it never executed


def test_a_proposal_confirmed_after_the_role_changed_fails_revalidation_and_needs_a_new_one(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh, _sec, port = _setup(world)
    ganesh = world.login("ganesh")
    p = _propose(world, ganesh, mh)
    assert world.admin_rows("SELECT actor_role FROM action_proposals") == [("owner_occ",)]
    with (
        world.db.owner_conn() as conn
    ):  # Ganesh moves out of A-203 but stays its owner: occupancy and ownership are independent (INV-04)
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(mh.id),))
        conn.execute(
            "UPDATE memberships SET lives_in_unit = false WHERE person_id = %s AND unit_id = %s AND kind = 'owner'",
            (ganesh.person_id, mh.unit("A", "203")),
        )
    late = _confirm(world, ganesh, mh, p)
    assert (
        late.status_code == 409
        and late.json()["code"] == "stale_version"
        and late.json()["details"]["reason"] == "role_changed"
    )
    assert late.json()["details"]["new_proposal_required"] is True and port.calls == []
    assert world.admin_rows("SELECT state, confirmed_by FROM action_proposals") == [
        ("proposed", None)
    ]
    # ... as a non-resident owner the complaint feature is still his to use: a NEW proposal under the new role confirms
    r = world.call(
        ganesh,
        "POST",
        "/v1/ai/proposals",
        json={"feature_id": "AI-R02", "inputs": COMPLAINT},
        headers={"X-Society-Id": str(mh.id)},
    )
    fresh = r.json()["proposal"]
    assert world.admin_rows("SELECT actor_role FROM action_proposals ORDER BY id DESC LIMIT 1") == [
        ("owner_nr",)
    ]
    assert _confirm(world, ganesh, mh, fresh).status_code == 200 and len(port.calls) == 1


def test_a_proposal_whose_owner_lost_all_standing_cannot_be_confirmed(fresh_world: World) -> None:
    world = fresh_world
    mh, _sec, port = _setup(world)
    ganesh = world.login("ganesh")
    p = _propose(world, ganesh, mh)
    with world.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(mh.id),))
        conn.execute(
            "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s AND kind = 'owner'",
            (ganesh.person_id,),
        )
    late = _confirm(world, ganesh, mh, p)
    assert (
        late.status_code in {403, 404} and port.calls == []
    )  # no standing: indistinguishable from an unknown proposal
    assert world.admin_rows("SELECT state FROM action_proposals") == [("proposed",)]


def test_a_changed_or_forged_payload_hash_never_confirms_and_nobody_else_can_confirm(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh, _sec, port = _setup(world)
    ganesh, rekha = world.login("ganesh"), world.login("rekha")
    p = _propose(world, ganesh, mh)
    forged = world.call(
        ganesh,
        "POST",
        f"/v1/ai/proposals/{p['id']}/confirm",
        json={"payload_hash": "sha256:" + "0" * 64},
        headers={"X-Society-Id": str(mh.id)},
    )
    assert (
        forged.status_code == 422 and forged.json()["details"]["reason"] == "payload_hash_mismatch"
    )
    assert (
        _confirm(world, rekha, mh, p).status_code == 404
    )  # a family member of the same household cannot confirm Ganesh's draft
    assert port.calls == [] and world.admin_rows("SELECT state FROM action_proposals") == [
        ("proposed",)
    ]
    assert _confirm(world, ganesh, mh, p).status_code == 200 and len(port.calls) == 1
    again = _confirm(world, ganesh, mh, p)
    assert (
        again.status_code == 409
        and again.json()["code"] == "already_decided"
        and len(port.calls) == 1
    )
