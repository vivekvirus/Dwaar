"""ARCH-01 / ARCH-03 / INV-01: society A's context can never read or write society B's organisation rows."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg import errors

from tests.integration.organisation._support import SECRETARY, SECRETARY_B, OrgHarness


@pytest.fixture
def two(org: OrgHarness) -> dict[str, uuid.UUID]:
    a = uuid.UUID(org.create_society("Alpha")["id"])
    b = uuid.UUID(org.create_society("Beta")["id"])
    org.seeder.grant(SECRETARY, "secretary", a)
    org.seeder.grant(SECRETARY_B, "secretary", b)
    block_a = org.create_block(a, "A")
    block_b = uuid.UUID(
        org.call(
            "POST",
            f"/v1/societies/{b}/blocks",
            SECRETARY_B,
            json={"name": "A", "floors": 5},
            key="k-blockb-0001",
        ).json()["id"]
    )
    unit_a = org.create_unit(a, block_a["id"], "101")
    unit_b = uuid.UUID(
        org.call(
            "POST",
            f"/v1/societies/{b}/units",
            SECRETARY_B,
            json={"block_id": str(block_b), "label": "101", "floor": 1},
            key="k-unitb-0001",
        ).json()["id"]
    )
    return {
        "a": a,
        "b": b,
        "block_a": uuid.UUID(block_a["id"]),
        "block_b": block_b,
        "unit_a": uuid.UUID(unit_a["id"]),
        "unit_b": unit_b,
    }


TABLES = [
    "societies",
    "legal_entities",
    "blocks",
    "units",
    "society_feature_flags",
    "society_quotas",
]


@pytest.mark.req("ARCH-01", "INV-01")
@pytest.mark.parametrize("table", TABLES)
def test_society_context_sees_only_its_own_rows(
    org: OrgHarness, two: dict[str, uuid.UUID], table: str
) -> None:
    for mine, theirs in ((two["a"], two["b"]), (two["b"], two["a"])):
        rows = org.rows(mine, f"SELECT society_id FROM {table}")  # noqa: S608
        assert rows and {r[0] for r in rows} == {mine}
        assert theirs not in {r[0] for r in rows}
    with org.db.app_conn() as conn:  # no context at all: zero rows, never all rows
        assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # type: ignore[call-overload]  # noqa: S608
    with org.db.app_conn(society_id="") as conn:  # empty context behaves the same
        assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # type: ignore[call-overload]  # noqa: S608


@pytest.mark.req("ARCH-01", "INV-01")
def test_society_row_is_protected_by_its_own_id(org: OrgHarness, two: dict[str, uuid.UUID]) -> None:
    """``societies`` has no society column in the PRD: its generated society_id (= id) carries the policy."""
    with org.db.app_conn(two["a"]) as conn:
        assert (
            conn.execute("SELECT id FROM societies WHERE id = %s", (two["b"],)).fetchall() == []
        )  # guessed id
        assert conn.execute("SELECT count(*) FROM societies").fetchone() == (1,)
        assert (
            conn.execute("UPDATE societies SET name = 'hacked' WHERE id = %s", (two["b"],)).rowcount
            == 0
        )
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("DELETE FROM societies WHERE id = %s", (two["a"],))
    with (
        org.db.app_conn(two["a"]) as conn,
        pytest.raises((errors.InsufficientPrivilege, errors.GeneratedAlways)),
    ):
        conn.execute("UPDATE societies SET society_id = %s WHERE id = %s", (two["b"], two["a"]))
    assert org.rows(two["b"], "SELECT name FROM societies") == [("Beta",)]


@pytest.mark.req("ARCH-01", "INV-01")
def test_cannot_write_rows_for_another_society(org: OrgHarness, two: dict[str, uuid.UUID]) -> None:
    with org.db.app_conn(two["a"]) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO blocks (society_id, name, floors) VALUES (%s, 'Z', 1)", (two["b"],)
        )
    with org.db.app_conn(two["a"]) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO societies (id, name, legal_entity_id, legal_pack_id, city, state)"
            " VALUES (%s, 'X', %s, %s, 'c', 's')",
            (uuid.uuid4(), uuid.uuid4(), org.legal_pack_id),
        )


@pytest.mark.req("ARCH-01")
def test_cross_society_references_are_impossible(
    org: OrgHarness, two: dict[str, uuid.UUID]
) -> None:
    # a unit of society A pointing at society B's block: the composite FK (society_id, block_id) refuses it
    with org.db.app_conn(two["a"]) as conn, pytest.raises(errors.ForeignKeyViolation):
        conn.execute(
            "INSERT INTO units (society_id, block_id, label, floor) VALUES (%s, %s, 'X1', 1)",
            (two["a"], two["block_b"]),
        )
    # even the owner cannot (FKs hold for every role)
    with pytest.raises(errors.ForeignKeyViolation), org.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(two["a"]),))
        conn.execute(
            "INSERT INTO units (society_id, block_id, label, floor) VALUES (%s, %s, 'X2', 1)",
            (two["a"], two["block_b"]),
        )
    # a society cannot adopt another society's legal entity (deferred composite FK, fails at commit)
    with org.db.admin_conn() as admin:
        entity_b = admin.execute(
            "SELECT legal_entity_id FROM societies WHERE id = %s", (two["b"],)
        ).fetchone()[0]  # type: ignore[index]
    with pytest.raises(errors.ForeignKeyViolation), org.db.owner_conn() as conn:
        new_id = uuid.uuid4()
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(new_id),))
        conn.execute(
            "INSERT INTO societies (id, name, legal_entity_id, legal_pack_id, city, state)"
            " VALUES (%s, 'Thief', %s, %s, 'c', 's')",
            (new_id, entity_b, org.legal_pack_id),
        )


@pytest.mark.req("ARCH-01")
def test_global_reference_tables_are_not_readable_by_runtime_roles(org: OrgHarness) -> None:
    for table in ("orgs", "legal_packs", "tax_packs"):
        with org.db.app_conn(uuid.uuid4()) as conn, pytest.raises(errors.InsufficientPrivilege):
            conn.execute(f"SELECT count(*) FROM {table}")  # type: ignore[call-overload]  # noqa: S608
        with org.db.worker_conn(uuid.uuid4()) as conn, pytest.raises(errors.InsufficientPrivilege):
            conn.execute(f"SELECT count(*) FROM {table}")  # type: ignore[call-overload]  # noqa: S608
    with org.db.app_conn() as conn:  # the narrow catalog view is the only door
        row = conn.execute(
            "SELECT pack_status, approved FROM legal_pack_catalog WHERE id = %s",
            (org.legal_pack_id,),
        ).fetchone()
        assert row == ("unapproved", False)


@pytest.mark.req("ARCH-01", "INV-01")
def test_api_guessed_ids_across_societies_are_404(
    org: OrgHarness, two: dict[str, uuid.UUID]
) -> None:
    a, b = two["a"], two["b"]
    # A's secretary names B's society, B's unit under A's path, or B's block under A's path
    for method, path in [
        ("GET", f"/v1/societies/{b}"),
        ("GET", f"/v1/societies/{b}/units"),
        ("GET", f"/v1/societies/{b}/units/{two['unit_b']}"),
        ("GET", f"/v1/societies/{a}/units/{two['unit_b']}"),
        ("GET", f"/v1/societies/{a}/blocks/{two['block_b']}"),
        ("GET", f"/v1/societies/{b}/configuration"),
    ]:
        resp = org.call(method, path, SECRETARY)
        assert resp.status_code == 404, (path, resp.text)
    for path, body in [
        (f"/v1/societies/{a}/units/{two['unit_b']}", {"expected_version": 1, "floor": 2}),
        (f"/v1/societies/{a}/blocks/{two['block_b']}", {"expected_version": 1, "floors": 9}),
    ]:
        assert org.call("PATCH", path, SECRETARY, json=body).status_code == 404
    assert (
        org.call("DELETE", f"/v1/societies/{a}/units/{two['unit_b']}", SECRETARY).status_code == 404
    )
    smuggled = org.call(
        "POST",
        f"/v1/societies/{a}/units",
        SECRETARY,
        json={"block_id": str(two["block_b"]), "label": "Q1", "floor": 1},
        key="k-smuggle-001",
    )
    assert smuggled.status_code == 400  # B's block does not exist in A's world
    assert org.rows(b, "SELECT count(*) FROM units") == [(1,)]


@pytest.mark.req("ARCH-01", "INV-01")
def test_worker_role_is_read_only(org: OrgHarness, two: dict[str, uuid.UUID]) -> None:
    with org.db.worker_conn(two["a"]) as conn:
        assert conn.execute("SELECT count(*) FROM units").fetchone() == (1,)
        for sql in (
            "DELETE FROM units",
            "UPDATE units SET label = 'x'",
            "INSERT INTO blocks (society_id, name, floors) VALUES (%s, 'W', 1)",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql, (two["a"],) if "%s" in sql else None)  # type: ignore[call-overload]
            conn.rollback()
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(two["a"]),))
