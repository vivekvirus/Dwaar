"""AT-12 (M1): a worker loses one of three employers -> the other engagements are preserved.

PRD 16: "Worker loses one of three employers. Required outcome: Other engagements preserved."  PRD 9.6 STAFF-03: ending one engagement does not
revoke other employers' engagements; STAFF-01: one staff person, separate engagements per household, valid hours, guards see only currently
authorised destinations.

Dataset: the real seed (``s480_staff``): Sunita Kamble, a cook, works for the Pawar household of A-203 (07:00-10:00), the Patil household of A-101
(10:30-12:30, Monday to Saturday) and the Menon household of B-205 (17:00-19:00, weekdays). Real API, real tokens (simulation=true), real Postgres.

What is proven: after the Pawars end THEIR engagement (with a reason, through their own API call) the other two engagements are untouched in the
database, in what each household reads, in what the guard sees at their hours, and in the INPUT the edge policy publisher consumes
(``authorisation.edge_staff_input``: the ended one is listed as ended, the other two stay in ``entries``) AND in the next SIGNED SNAPSHOT that
``publish_policy`` produces (last two tests; the gateway's own parser accepts the new ``staff`` and ``overrides`` sections). Not proven here: that a real
gateway applied the new snapshot, and the gateway's decision engine does not yet read the staff section (it parses and stores it): see the slice 4 report.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from dwaar_api.core.db import RequestContext
from dwaar_api.modules.staff import authorisation
from tests.acceptance._world import DATASET, World

IST = ZoneInfo("Asia/Kolkata")
pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-12", dataset=DATASET),
    pytest.mark.req("STAFF-01", "STAFF-03", "INV-01"),
]
_TODAY = dt.datetime.now(IST).date()
MONDAY = _TODAY + dt.timedelta(
    days=(7 - _TODAY.weekday()) % 7 or 7
)  # the next Monday: after the seeded engagements took effect


def _at(hour: int, minute: int = 0) -> dt.datetime:
    return dt.datetime.combine(MONDAY, dt.time(hour, minute), tzinfo=IST)


def _engagements(world: World) -> dict[str, tuple[Any, ...]]:
    rows = world.admin_rows(
        "SELECT b.name || ' ' || u.label, e.id, e.ended_at, e.version, e.schedule::text FROM staff_engagements e"
        " JOIN staff s ON s.id = e.staff_id JOIN units u ON u.id = e.unit_id JOIN blocks b ON b.id = u.block_id"
        " WHERE s.display_name = 'Sunita Kamble' ORDER BY 1"
    )
    return {r[0]: r for r in rows}


def _edge_input(world: World, society: Any) -> dict[str, Any]:
    with world.database.app_tx(RequestContext(society, None, "system", None)) as conn:
        return authorisation.edge_staff_input(conn)


def _cook(world: World) -> Any:
    return world.admin_rows("SELECT id FROM staff WHERE display_name = 'Sunita Kamble'")[0][0]


def _authorised_units(world: World, society: Any, at: dt.datetime) -> list[str]:
    with world.database.app_tx(RequestContext(society, None, "system", None)) as conn:
        found = authorisation.authorised_engagements(conn, at, staff_ids=[_cook(world)])
        return sorted(f"{a['block_name']} {a['unit_label']}" for a in found)


def test_ending_one_of_three_engagements_preserves_the_other_two(fresh_world: World) -> None:
    world = fresh_world
    mh = world.society_ref("mh").id
    before = _engagements(world)
    assert sorted(before) == ["A 101", "A 203", "B 205"], "the seeded cook has three employers"
    assert all(r[2] is None for r in before.values())
    edge_before = _edge_input(world, mh)
    staff_refs = {
        e["staff_ref"]
        for e in edge_before["entries"]
        if e["engagement_id"] in {str(r[1]) for r in before.values()}
    }
    assert len(staff_refs) == 1, "one staff person behind three engagements"
    assert _authorised_units(world, mh, _at(8)) == ["A 203"] and _authorised_units(
        world, mh, _at(11)
    ) == ["A 101"]
    assert _authorised_units(world, mh, _at(18)) == ["B 205"], "separate hours per household"

    ganesh = world.login("ganesh")
    ended = world.call(
        ganesh, "POST", f"/v1/staff-engagements/{before['A 203'][1]}/end",
        json={"expected_version": before["A 203"][3], "reason": "Moved the cook to the new house in Pune"},
        headers={"X-Society-Id": str(mh)},
    )  # fmt: skip
    assert ended.status_code == 200, ended.text
    assert ended.json()["ended_at"] is not None and ended.json()["authorised_now"] is False

    after = _engagements(world)
    assert after["A 203"][2] is not None
    for unit in ("A 101", "B 205"):
        assert after[unit][2] is None, f"{unit} was not touched"
        assert after[unit][3] == before[unit][3] and after[unit][4] == before[unit][4], (
            "same version, same hours"
        )
    # what each remaining household reads
    for person, unit in (("neha", "A 101"), ("priya", "B 205")):
        mine = world.call(
            world.login(person), "GET", "/v1/staff-engagements", headers={"X-Society-Id": str(mh)}
        ).json()["items"]
        assert [e["id"] for e in mine] == [str(after[unit][1])] and mine[0]["ended_at"] is None
    gone = world.call(
        ganesh,
        "GET",
        "/v1/staff-engagements",
        params={"state": "live"},
        headers={"X-Society-Id": str(mh)},
    ).json()["items"]
    assert gone == [], "the Pawars no longer employ her"
    # what the guard may see at each hour
    assert _authorised_units(world, mh, _at(8)) == [], (
        "the ended household's hours no longer authorise anyone"
    )
    assert _authorised_units(world, mh, _at(11)) == ["A 101"] and _authorised_units(
        world, mh, _at(18)
    ) == ["B 205"]
    # the edge policy input reflects it (the function the edge publisher consumes)
    edge_after = _edge_input(world, mh)
    live = {e["engagement_id"] for e in edge_after["entries"]}
    assert (
        str(after["A 203"][1]) not in live
        and {str(after["A 101"][1]), str(after["B 205"][1])} <= live
    )
    assert [e["engagement_id"] for e in edge_after["ended"]] == [str(after["A 203"][1])]
    assert edge_after["digest"] != edge_before["digest"]
    # audited and evented, naming the engagement and how many remain
    event = world.admin_rows(
        "SELECT payload FROM outbox WHERE event_type = 'StaffEngagementEnded' AND aggregate_id = %s",
        (after["A 203"][1],),
    )[0][0]
    assert event["remaining_live_engagements"] == 2
    audit = world.admin_rows(
        "SELECT actor_id, reason FROM audit_log WHERE operation = 'staff.engagement_end' AND object_id = %s",
        (after["A 203"][1],),
    )
    assert len(audit) == 1 and audit[0][1] == "Moved the cook to the new house in Pune"


def test_the_ended_employer_cannot_touch_the_other_employers_engagements(
    fresh_world: World,
) -> None:
    world = fresh_world
    mh = world.society_ref("mh").id
    eng = _engagements(world)
    ganesh = world.login("ganesh")
    for unit in ("A 101", "B 205"):
        r = world.call(
            ganesh,
            "POST",
            f"/v1/staff-engagements/{eng[unit][1]}/end",
            json={
                "expected_version": eng[unit][3],
                "reason": "Trying to end another household's cook",
            },
            headers={"X-Society-Id": str(mh)},
        )
        assert r.status_code == 404, "not his engagement: indistinguishable from an unknown one"
    assert all(r[2] is None for r in _engagements(world).values())


# ------------------------------------------------------------------------------------------------------------ through the publisher (slice 4 integration)
def _publish(world: World, society: Any, *, now: dt.datetime | None = None) -> Any:
    from dwaar_api.modules.edge.snapshot import latest_snapshot, publish_policy

    cfg = world.app.state.edge_config
    ctx = RequestContext(society, None, "system", None)
    with world.database.app_tx(ctx) as conn:
        result = publish_policy(conn, ctx, cfg, now=now)
    with world.database.app_tx(ctx) as conn:
        snap = latest_snapshot(conn)
    assert snap is not None and snap["seq"] == result.seq
    return result, snap


def test_the_next_signed_snapshot_keeps_the_other_two_engagements_when_one_employer_ends(
    fresh_world: World,
) -> None:
    """AT-12 end to end through ``publish_policy``: the manifest the gateway receives lists one entry per ENGAGEMENT; ending the Pawars' engagement
    changes the next snapshot (the ended one moves to ``ended``) and leaves the other two entries byte-identical."""
    world = fresh_world
    mh = world.society_ref("mh").id
    eng = _engagements(world)
    _first_result, first = _publish(world, mh)
    entries = {e["engagement_id"]: e for e in first["manifest"]["staff"]["entries"]}
    assert {str(r[1]) for r in eng.values()} <= set(entries), (
        "all three employers are in the first snapshot"
    )
    cook_refs = {entries[str(r[1])]["staff_ref"] for r in eng.values()}
    assert len(cook_refs) == 1, "one person, three engagements"
    assert first["manifest"]["staff"]["ended"] == []

    ended = world.call(
        world.login("ganesh"), "POST", f"/v1/staff-engagements/{eng['A 203'][1]}/end",
        json={"expected_version": eng["A 203"][3], "reason": "Moved the cook to the new house in Pune"},
        headers={"X-Society-Id": str(mh)},
    )  # fmt: skip
    assert ended.status_code == 200, ended.text
    result, second = _publish(world, mh)
    assert result.changed and result.reason == "changed" and second["seq"] == first["seq"] + 1
    now_entries = {e["engagement_id"]: e for e in second["manifest"]["staff"]["entries"]}
    gone = str(eng["A 203"][1])
    assert gone not in now_entries, "the ended engagement no longer authorises anything at the gate"
    for unit in ("A 101", "B 205"):
        key = str(eng[unit][1])
        assert now_entries[key] == entries[key], (
            f"{unit}: the other employers' entries are untouched"
        )
    assert [e["engagement_id"] for e in second["manifest"]["staff"]["ended"]] == [gone]
    # nothing personal travels: opaque ids and local valid hours only
    blob = repr(second["manifest"]["staff"])
    assert "Sunita" not in blob and "Kamble" not in blob and "+91" not in blob
    # the snapshot is signed, and the GATEWAY's own parser (extra=forbid everywhere) accepts the new sections
    from dwaar_api.modules.edge.snapshot import snapshot_document
    from dwaar_edge.policy_model import Snapshot

    parsed = Snapshot.model_validate(snapshot_document(second))
    assert {str(e.engagement_id) for e in parsed.manifest.staff.entries} == set(now_entries)
    assert parsed.manifest.staff.ended[0].engagement_id.hex == uuid_hex(gone)
    # idempotent: publishing again with nothing changed writes nothing
    again, _ = _publish(world, mh)
    assert not again.changed and again.reason == "unchanged"


def uuid_hex(value: str) -> str:
    return value.replace("-", "")


def test_a_supervisor_override_in_force_travels_in_the_snapshot_with_its_own_expiry(
    fresh_world: World,
) -> None:
    """Appendix C through the publisher: an override granted at a gate by the supervisor of the ACTIVE shift appears in the next snapshot with a
    ``valid_until`` that never outlives the shift, the gateway's parser accepts it, and ending the shift removes it from the following snapshot."""
    world = fresh_world
    mh = world.society_ref("mh").id
    _, before = _publish(world, mh)
    assert before["manifest"]["overrides"] == []
    shift = world.admin_rows(
        "SELECT id, gate_id, planned_end FROM shifts WHERE society_id = %s AND state = 'active' ORDER BY id LIMIT 1",
        (mh,),
    )[0]
    sup = world.login("mh.guard_sup")
    granted = world.call(
        sup, "POST", f"/v1/shifts/{shift[0]}/overrides",
        json={"reason": "Barrier sensor fault: verified by the supervisor", "minutes": 30},
        headers={"X-Society-Id": str(mh)},
    )  # fmt: skip
    assert granted.status_code == 201, granted.text
    result, after = _publish(world, mh)
    assert result.changed and result.reason == "changed"
    [published] = after["manifest"]["overrides"]
    assert published["gate_id"] == str(shift[1])
    valid_until = dt.datetime.fromisoformat(published["valid_until"].replace("Z", "+00:00"))
    assert dt.datetime.now(dt.UTC) < valid_until <= shift[2], "an override never outlives its shift"
    from dwaar_api.modules.edge.snapshot import snapshot_document
    from dwaar_edge.policy_model import Snapshot

    parsed = Snapshot.model_validate(snapshot_document(after))
    assert [str(o.gate_id) for o in parsed.manifest.overrides] == [str(shift[1])]
    ended = world.call(
        world.login("mh.guard1"), "POST", f"/v1/shifts/{shift[0]}/end",
        json={"checklist": {"parcels_counted": 0, "inside_records_reviewed": True}},
        headers={"X-Society-Id": str(mh)},
    )  # fmt: skip
    # whichever guard holds the shift ends it; if the seeded guard is not the holder the supervisor does (the route allows both)
    if ended.status_code != 200:
        ended = world.call(
            sup, "POST", f"/v1/shifts/{shift[0]}/end",
            json={"checklist": {"parcels_counted": 0, "inside_records_reviewed": True}},
            headers={"X-Society-Id": str(mh)},
        )  # fmt: skip
    assert ended.status_code == 200, ended.text
    _, last = _publish(world, mh)
    assert last["manifest"]["overrides"] == [], (
        "the shift ended: the override is gone from the next snapshot"
    )
