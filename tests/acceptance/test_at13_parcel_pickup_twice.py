"""AT-13 (M1): a parcel pickup is attempted twice -> the second attempt is denied and the custody history is intact.

PRD 16: "Parcel pickup attempted twice. Required outcome: Second attempt denied; custody history intact."  PRD 9.5 PAR-03 (single-use pickup
token), PAR-02 (exactly one current custodian), INV-07.

Dataset: the real seed (``s470_parcels``): a Bluecart parcel stored in bin B-01 for the Patil household of A-101 (owner Neha Patil). Real API, real
tokens (simulation=true), real Postgres, and, for the race, real threads.

What is proven: the resident issues the single-use token, the guard hands the parcel over, the SAME token is presented again (once, then eight
times at once, then through a different idempotency key): every later attempt is denied with ``409 already_decided``, each denial is recorded in
``parcel_pickup_attempts``, and ``custody_transfers`` is byte-for-byte what it was after the first hand-over (one current custodian, a complete
chain). Not proven: that a person at a real gate presents a QR on a real tablet (no client exists yet).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from tests.acceptance._world import DATASET, World

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-13", dataset=DATASET),
    pytest.mark.req("PAR-02", "PAR-03", "INV-07", "INV-01"),
]


def _parcel(world: World) -> tuple[Any, Any, Any]:
    row = world.admin_rows(
        "SELECT id, version, society_id FROM parcels WHERE carrier_ref = 'SEED-P2' AND state = 'stored'"
    )[0]
    return row


def _chain(world: World, parcel_id: Any) -> list[tuple[Any, ...]]:
    return world.admin_rows(
        "SELECT seq, prev_seq, from_party, to_party, at, reason FROM custody_transfers WHERE parcel_id = %s ORDER BY seq",
        (parcel_id,),
    )


def test_the_second_pickup_attempt_is_denied_and_the_custody_history_is_intact(
    fresh_world: World,
) -> None:
    world = fresh_world
    parcel_id, version, society = _parcel(world)
    headers = {"X-Society-Id": str(society)}
    neha, guard = world.login("neha"), world.login("mh.guard1")
    issued = world.call(
        neha,
        "POST",
        f"/v1/parcels/{parcel_id}/pickup-token",
        json={"expected_version": version},
        headers=headers,
    )
    assert issued.status_code == 200 and issued.json()["state"] == "pickup_pending", issued.text
    token = issued.json()["pickup_token"]
    body = {"method": "token", "token": token, "collector": {"kind": "recipient"}}
    first = world.call(
        guard, "POST", f"/v1/parcels/{parcel_id}/collect", json=body, headers=headers
    )
    assert (
        first.status_code == 200
        and first.json()["state"] == "collected"
        and first.json()["in_society_custody"] is False
    )
    chain = _chain(world, parcel_id)
    assert [c[5] for c in chain] == ["received", "stored", "collected"] and [
        c[0] for c in chain
    ] == [1, 2, 3]

    second = world.call(
        guard, "POST", f"/v1/parcels/{parcel_id}/collect", json=body, headers=headers
    )
    assert second.status_code == 409 and second.json()["code"] == "already_decided"
    assert second.json()["details"]["reason"] == "already_collected"
    assert _chain(world, parcel_id) == chain, (
        "custody history intact: nothing added, nothing changed"
    )
    assert (
        world.admin_rows("SELECT state, custodian FROM parcels WHERE id = %s", (parcel_id,))[0][0]
        == "collected"
    )
    attempts = world.admin_rows(
        "SELECT outcome, reason FROM parcel_pickup_attempts WHERE parcel_id = %s ORDER BY at, id",
        (parcel_id,),
    )
    assert attempts == [("granted", "collected"), ("denied", "already_collected")], (
        "the denial itself is part of the history"
    )
    # a replay with a fresh Idempotency-Key is another attempt, and is denied too
    third = world.call(
        guard, "POST", f"/v1/parcels/{parcel_id}/collect", json=body, headers=headers
    )
    assert third.status_code == 409
    # the resident cannot mint a new token for a collected parcel
    again = world.call(
        neha,
        "POST",
        f"/v1/parcels/{parcel_id}/pickup-token",
        json={"expected_version": first.json()["version"]},
        headers=headers,
    )
    assert again.status_code == 422 and again.json()["details"]["reason"] == "not_ready_for_pickup"
    assert _chain(world, parcel_id) == chain
    view = world.call(neha, "GET", f"/v1/parcels/{parcel_id}", headers=headers).json()
    assert [a["outcome"] for a in view["pickup_attempts"]] == ["granted", "denied", "denied"]
    assert [c["reason"] for c in view["custody"]] == ["received", "stored", "collected"]


def test_two_people_at_two_desks_presenting_the_token_at_once_have_exactly_one_winner(
    fresh_world: World,
) -> None:
    world = fresh_world
    parcel_id, version, society = _parcel(world)
    headers = {"X-Society-Id": str(society)}
    token = world.call(
        world.login("neha"),
        "POST",
        f"/v1/parcels/{parcel_id}/pickup-token",
        json={"expected_version": version},
        headers=headers,
    ).json()["pickup_token"]
    guard = world.login("mh.guard1")
    body = {"method": "token", "token": token, "collector": {"kind": "recipient"}}
    barrier = threading.Barrier(8)

    def attempt(_: int) -> int:
        barrier.wait()
        return int(
            world.call(
                guard, "POST", f"/v1/parcels/{parcel_id}/collect", json=body, headers=headers
            ).status_code
        )

    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(attempt, range(8)))
    assert sorted(codes) == [200] + [409] * 7, codes
    chain = _chain(world, parcel_id)
    assert [c[5] for c in chain] == ["received", "stored", "collected"]
    assert (
        world.admin_rows(
            "SELECT count(*) FROM parcel_pickup_attempts WHERE parcel_id = %s AND outcome = 'denied'",
            (parcel_id,),
        )[0][0]
        == 7
    )


def test_a_stranger_household_cannot_collect_or_see_the_parcel(fresh_world: World) -> None:
    world = fresh_world
    parcel_id, _version, society = _parcel(world)
    headers = {"X-Society-Id": str(society)}
    ganesh = world.login("ganesh")  # another household
    assert world.call(ganesh, "GET", f"/v1/parcels/{parcel_id}", headers=headers).status_code == 404
    assert (
        world.call(
            ganesh,
            "POST",
            f"/v1/parcels/{parcel_id}/collect",
            json={"method": "token", "token": "x" * 30, "collector": {"kind": "recipient"}},
            headers=headers,
        ).status_code
        == 403
    )
    assert (
        world.admin_rows("SELECT state FROM parcels WHERE id = %s", (parcel_id,))[0][0] == "stored"
    )
