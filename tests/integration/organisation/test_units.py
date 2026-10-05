"""SOC-02 blocks and units, idempotent creation, permission matrix, pagination."""

from __future__ import annotations

import uuid

import pytest

from tests.integration.organisation._support import (
    AUDITOR,
    COMMITTEE,
    ESTATE_MGR,
    FAMILY,
    GUARD,
    OUTSIDER,
    OWNER_NR,
    OWNER_OCC,
    SECRETARY,
    TENANT,
    TREASURER,
    OrgHarness,
)


@pytest.fixture
def soc(org: OrgHarness) -> uuid.UUID:
    sid = uuid.UUID(org.create_society()["id"])
    org.seed_staff(sid)
    return sid


@pytest.mark.req("SOC-02")
def test_block_and_unit_crud_with_exact_decimals(org: OrgHarness, soc: uuid.UUID) -> None:
    block = org.create_block(soc, "Tower A", floors=12)
    assert block["floors"] == 12 and block["has_lift"] is True and block["version"] == 1
    unit = org.create_unit(soc, block["id"], "A-101", floor=1)
    assert unit["carpet_area_sqft"] == "650.50"
    assert unit["builtup_area_sqft"] == "780.25"
    assert unit["undivided_interest_pct"] == "0.125000"
    assert unit["construction_cost_paise"] == 450000000
    got = org.call("GET", f"/v1/societies/{soc}/units/{unit['id']}", SECRETARY).json()
    assert got["block_name"] == "Tower A" and got["carpet_area_sqft"] == "650.50"
    patched = org.call(
        "PATCH",
        f"/v1/societies/{soc}/units/{unit['id']}",
        SECRETARY,
        json={"expected_version": 1, "carpet_area_sqft": "700.00", "construction_cost_paise": None},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["carpet_area_sqft"] == "700.00"
    assert patched.json()["construction_cost_paise"] is None
    assert patched.json()["version"] == 2
    stale = org.call(
        "PATCH",
        f"/v1/societies/{soc}/units/{unit['id']}",
        SECRETARY,
        json={"expected_version": 1, "floor": 2},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    null_label = org.call(
        "PATCH",
        f"/v1/societies/{soc}/units/{unit['id']}",
        SECRETARY,
        json={"expected_version": 2, "label": None},
    )
    assert null_label.status_code == 400
    floats = org.call(
        "PATCH",
        f"/v1/societies/{soc}/units/{unit['id']}",
        SECRETARY,
        json={"expected_version": 2, "carpet_area_sqft": "1.234"},
    )
    assert floats.status_code == 400  # three decimals: refused, never rounded silently
    # audit: one row per mutation, with the changed fields only
    ops = org.rows(
        soc, "SELECT operation FROM audit_log WHERE object_type = 'unit' ORDER BY at, id"
    )
    assert ops == [("unit.create",), ("unit.update",)]
    events = org.rows(
        soc,
        "SELECT event_type, aggregate_version FROM outbox WHERE aggregate_type = 'unit' ORDER BY aggregate_version",
    )
    assert events == [("UnitCreated", 1), ("UnitUpdated", 2)]


@pytest.mark.req("SOC-02", "ARCH-01")
def test_duplicate_labels_across_blocks_work_but_not_within_a_block(
    org: OrgHarness, soc: uuid.UUID
) -> None:
    a = org.create_block(soc, "A")
    b = org.create_block(soc, "B")
    org.create_unit(soc, a["id"], "101")
    org.create_unit(
        soc, b["id"], "101"
    )  # same label, other block: fine (PRD 8.1: unique within block)
    dup = org.call(
        "POST",
        f"/v1/societies/{soc}/units",
        SECRETARY,
        json={"block_id": a["id"], "label": "101", "floor": 1},
        key="dup-label-0001",
    )
    assert dup.status_code == 422
    assert (
        dup.json()["code"] == "policy_violation"
        and dup.json()["details"]["reason"] == "duplicate_unit_label"
    )
    ci = org.call(
        "POST",
        f"/v1/societies/{soc}/units",
        SECRETARY,
        json={"block_id": a["id"], "label": " 101 ", "floor": 1},
        key="dup-label-0002",
    )
    assert ci.status_code == 422
    assert org.rows(soc, "SELECT count(*) FROM units") == [(2,)]
    dup_block = org.call(
        "POST",
        f"/v1/societies/{soc}/blocks",
        SECRETARY,
        json={"name": "a", "floors": 3},
        key="dup-block-0001",
    )
    assert (
        dup_block.status_code == 422
        and dup_block.json()["details"]["reason"] == "duplicate_block_name"
    )


@pytest.mark.req("SOC-02")
def test_unit_validation(org: OrgHarness, soc: uuid.UUID) -> None:
    block = org.create_block(soc, "A", floors=5)
    base = {"block_id": block["id"], "label": "X", "floor": 1}
    bad_bodies = [
        {**base, "carpet_area_sqft": "0"},
        {**base, "carpet_area_sqft": "-5"},
        {**base, "undivided_interest_pct": "100.5"},
        {**base, "undivided_interest_pct": "-1"},
        {**base, "construction_cost_paise": -1},
        {**base, "construction_cost_paise": 1.5},
        {**base, "carpet_area_sqft": "900", "builtup_area_sqft": "800"},
        {**base, "label": ""},
        {**base, "label": "x\u0000y"},
        {**base, "floor": 400},
        {**base, "society_id": str(soc)},
        {**base, "surprise": 1},
    ]
    for i, body in enumerate(bad_bodies):
        resp = org.call(
            "POST", f"/v1/societies/{soc}/units", SECRETARY, json=body, key=f"bad-unit-{i:04d}"
        )
        assert resp.status_code == 400, (body, resp.text)
    high = org.call(
        "POST",
        f"/v1/societies/{soc}/units",
        SECRETARY,
        json={**base, "floor": 6},
        key="high-floor-0001",
    )
    assert (
        high.status_code == 422 and high.json()["details"]["reason"] == "floor_exceeds_block_floors"
    )
    assert org.rows(soc, "SELECT count(*) FROM units") == [(0,)]


@pytest.mark.req("SOC-02")
def test_archive_unit_and_block(org: OrgHarness, soc: uuid.UUID) -> None:
    block = org.create_block(soc, "A")
    unit = org.create_unit(soc, block["id"], "101")
    blocked = org.call("DELETE", f"/v1/societies/{soc}/blocks/{block['id']}", SECRETARY)
    assert (
        blocked.status_code == 422
        and blocked.json()["details"]["reason"] == "block_has_active_units"
    )
    gone = org.call("DELETE", f"/v1/societies/{soc}/units/{unit['id']}", SECRETARY)
    assert gone.status_code == 200 and gone.json()["status"] == "archived"
    again = org.call("DELETE", f"/v1/societies/{soc}/units/{unit['id']}", SECRETARY)
    assert (
        again.status_code == 200 and again.json()["version"] == gone.json()["version"]
    )  # idempotent
    listing = org.call("GET", f"/v1/societies/{soc}/units", SECRETARY).json()
    assert listing["items"] == []
    archived = org.call(
        "GET", f"/v1/societies/{soc}/units", SECRETARY, params={"status": "archived"}
    ).json()
    assert [u["id"] for u in archived["items"]] == [unit["id"]]
    ok = org.call("DELETE", f"/v1/societies/{soc}/blocks/{block['id']}", SECRETARY)
    assert ok.status_code == 200 and ok.json()["status"] == "archived"
    new_unit = org.call(
        "POST",
        f"/v1/societies/{soc}/units",
        SECRETARY,
        json={"block_id": block["id"], "label": "102", "floor": 1},
        key="archived-block-1",
    )
    assert new_unit.status_code == 400  # an archived block takes no new units
    stale = org.call("DELETE", f"/v1/societies/{soc}/units/{uuid.uuid4()}", SECRETARY)
    assert stale.status_code == 404


@pytest.mark.req("SOC-02", "IAM-08")
def test_write_permissions_follow_matrix(org: OrgHarness, soc: uuid.UUID) -> None:
    block = org.create_block(soc, "A")
    unit = org.create_unit(soc, block["id"], "101")
    org.seed_residents(soc, uuid.UUID(unit["id"]))
    for person in (
        TREASURER,
        COMMITTEE,
        ESTATE_MGR,
        GUARD,
        AUDITOR,
        OWNER_OCC,
        OWNER_NR,
        TENANT,
        FAMILY,
    ):
        n = uuid.uuid4().hex[:8]
        assert (
            org.call(
                "POST",
                f"/v1/societies/{soc}/blocks",
                person,
                json={"name": f"B{n}", "floors": 1},
                key=f"perm-b-{n}",
            ).status_code
            == 403
        ), person
        assert (
            org.call(
                "POST",
                f"/v1/societies/{soc}/units",
                person,
                json={"block_id": block["id"], "label": f"L{n}", "floor": 1},
                key=f"perm-u-{n}",
            ).status_code
            == 403
        ), person
        assert (
            org.call(
                "PATCH",
                f"/v1/societies/{soc}/units/{unit['id']}",
                person,
                json={"expected_version": 1, "floor": 2},
            ).status_code
            == 403
        ), person
        assert (
            org.call("DELETE", f"/v1/societies/{soc}/units/{unit['id']}", person).status_code == 403
        ), person
        assert (
            org.call("DELETE", f"/v1/societies/{soc}/blocks/{block['id']}", person).status_code
            == 403
        ), person
    assert (
        org.call(
            "POST",
            f"/v1/societies/{soc}/units",
            OUTSIDER,
            json={"block_id": block["id"], "label": "Z", "floor": 1},
            key="perm-outsider",
        ).status_code
        == 404
    )
    assert org.rows(soc, "SELECT count(*) FROM units") == [(1,)]


@pytest.mark.req("SOC-02", "INV-01")
def test_read_permissions_masking_and_own_unit_scope(org: OrgHarness, soc: uuid.UUID) -> None:
    block = org.create_block(soc, "A")
    mine = org.create_unit(soc, block["id"], "101")
    other = org.create_unit(soc, block["id"], "102")
    org.seed_residents(soc, uuid.UUID(mine["id"]))
    for person in (SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, AUDITOR):
        resp = org.call("GET", f"/v1/societies/{soc}/units", person)
        assert resp.status_code == 200 and len(resp.json()["items"]) == 2, person
        assert resp.json()["items"][0]["carpet_area_sqft"] is not None
    guard = org.call("GET", f"/v1/societies/{soc}/units/{mine['id']}", GUARD)
    assert guard.status_code == 200
    assert "carpet_area_sqft" not in guard.json() and "construction_cost_paise" not in guard.json()
    assert guard.json()["label"] == "101"
    assert all(
        "carpet_area_sqft" not in u
        for u in org.call("GET", f"/v1/societies/{soc}/units", GUARD).json()["items"]
    )
    for person in (OWNER_OCC, OWNER_NR, TENANT, FAMILY):
        assert (
            org.call("GET", f"/v1/societies/{soc}/units/{mine['id']}", person).status_code == 200
        ), person
        assert (
            org.call("GET", f"/v1/societies/{soc}/units/{other['id']}", person).status_code == 404
        ), person
        listing = org.call("GET", f"/v1/societies/{soc}/units", person).json()
        assert [u["id"] for u in listing["items"]] == [mine["id"]], person
    assert org.call("GET", f"/v1/societies/{soc}/units", OUTSIDER).status_code == 404


@pytest.mark.req("SOC-02", "INV-02")
def test_idempotent_creation_replays_and_detects_payload_mismatch(
    org: OrgHarness, soc: uuid.UUID
) -> None:
    block = org.create_block(soc, "A")
    body = {"block_id": block["id"], "label": "101", "floor": 1, "carpet_area_sqft": "500.00"}
    first = org.call(
        "POST", f"/v1/societies/{soc}/units", SECRETARY, json=body, key="idem-unit-0001"
    )
    again = org.call(
        "POST", f"/v1/societies/{soc}/units", SECRETARY, json=body, key="idem-unit-0001"
    )
    assert first.status_code == again.status_code == 201
    assert again.headers["Idempotent-Replayed"] == "true"
    assert first.json()["id"] == again.json()["id"]
    assert org.rows(soc, "SELECT count(*) FROM units") == [(1,)]
    assert org.rows(soc, "SELECT count(*) FROM audit_log WHERE operation = 'unit.create'") == [(1,)]
    assert org.rows(soc, "SELECT count(*) FROM outbox WHERE event_type = 'UnitCreated'") == [(1,)]
    mismatch = org.call(
        "POST",
        f"/v1/societies/{soc}/units",
        SECRETARY,
        json={**body, "label": "102"},
        key="idem-unit-0001",
    )
    assert mismatch.status_code == 409 and mismatch.json()["code"] == "duplicate_payload_mismatch"
    missing = org.call(
        "POST", f"/v1/societies/{soc}/units", SECRETARY, json={**body, "label": "103"}
    )
    assert missing.status_code == 400 and missing.json()["code"] == "invalid_schema"
    # a failed request stores nothing: the same key can be retried after the cause is fixed
    failing = {**body, "label": "101"}
    assert (
        org.call(
            "POST", f"/v1/societies/{soc}/units", SECRETARY, json=failing, key="idem-unit-0002"
        ).status_code
        == 422
    )
    fixed = {**body, "label": "104"}
    assert (
        org.call(
            "POST", f"/v1/societies/{soc}/units", SECRETARY, json=fixed, key="idem-unit-0002"
        ).status_code
        == 201
    )


@pytest.mark.req("SOC-02")
def test_pagination_and_allow_listed_filters(org: OrgHarness, soc: uuid.UUID) -> None:
    a = org.create_block(soc, "A")
    b = org.create_block(soc, "B")
    for i in range(5):
        org.create_unit(soc, a["id"], f"A{i}", floor=i % 3)
    org.create_unit(soc, b["id"], "B0", floor=0)
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, object] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = org.call("GET", f"/v1/societies/{soc}/units", SECRETARY, params=params).json()
        seen += [u["id"] for u in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 6
    by_block = org.call(
        "GET", f"/v1/societies/{soc}/units", SECRETARY, params={"block_id": b["id"]}
    ).json()
    assert [u["label"] for u in by_block["items"]] == ["B0"]
    by_floor = org.call("GET", f"/v1/societies/{soc}/units", SECRETARY, params={"floor": 0}).json()
    assert {u["label"] for u in by_floor["items"]} == {"A0", "A3", "B0"}
    assert (
        org.call(
            "GET", f"/v1/societies/{soc}/units", SECRETARY, params={"owner_name": "x"}
        ).status_code
        == 400
    )
    assert (
        org.call("GET", f"/v1/societies/{soc}/units", SECRETARY, params={"limit": 101}).status_code
        == 400
    )
    assert (
        org.call("GET", f"/v1/societies/{soc}/units", SECRETARY, params={"limit": 0}).status_code
        == 400
    )
    blocks = org.call("GET", f"/v1/societies/{soc}/blocks", COMMITTEE, params={"limit": 1}).json()
    assert len(blocks["items"]) == 1 and blocks["next_cursor"]
    # a cursor is bound to its filters: it cannot be replayed with another filter
    other = org.call(
        "GET",
        f"/v1/societies/{soc}/units",
        SECRETARY,
        params={"limit": 1, "cursor": cursor or blocks["next_cursor"], "block_id": b["id"]},
    )
    assert other.status_code == 400


@pytest.mark.req("SOC-02")
def test_block_update_rules(org: OrgHarness, soc: uuid.UUID) -> None:
    block = org.create_block(soc, "A", floors=10)
    org.create_unit(soc, block["id"], "1001", floor=10)
    shrink = org.call(
        "PATCH",
        f"/v1/societies/{soc}/blocks/{block['id']}",
        SECRETARY,
        json={"expected_version": 1, "floors": 5},
    )
    assert (
        shrink.status_code == 422
        and shrink.json()["details"]["reason"] == "units_above_block_floors"
    )
    ok = org.call(
        "PATCH",
        f"/v1/societies/{soc}/blocks/{block['id']}",
        SECRETARY,
        json={"expected_version": 1, "has_lift": False},
    )
    assert ok.status_code == 200 and ok.json()["has_lift"] is False and ok.json()["version"] == 2
