"""Database-level guarantees of the edge migrations (0300-0312): RLS in the same migration, append-only history, composite foreign keys,
least-privilege grants and the reviewed device-lookup function.

REQ: EDGE-04, EDGE-03, EDGE-07, DB-02, INV-01, ARCH-01, ARCH-03.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest

from tests.integration.edge._support import EdgeWorld

pytestmark = [pytest.mark.req("EDGE-03", "EDGE-04", "INV-01")]

TABLES = (
    "policy_snapshots", "edge_credential_refs", "standing_rules", "edge_device_state", "edge_events", "edge_quarantine",
)  # fmt: skip
APPEND_ONLY = ("policy_snapshots", "edge_events", "edge_quarantine")


def test_every_edge_table_has_forced_row_level_security_and_a_society_policy(ew: EdgeWorld) -> None:
    for table in TABLES:
        flags = ew.rows(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s", (table,)
        )[0]
        assert flags == (True, True), table
        policies = ew.rows("SELECT count(*) FROM pg_policies WHERE tablename = %s", (table,))[0][0]
        assert policies >= 1, table
        cols = ew.rows(
            "SELECT is_nullable FROM information_schema.columns WHERE table_name = %s AND column_name = 'society_id'",
            (table,),
        )
        assert cols == [("NO",)], (
            table
        )  # society_id NOT NULL on every society-owned table (ARCH-01)


def test_no_context_means_zero_rows_never_all_rows(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    visit = ew.authorised_visit()
    dev.sync([dev.entry(visit), dev.entry(uuid.uuid4(), sign=False)])
    dev.policy()
    for table in TABLES:
        assert ew.count(table) >= 0
        with ew.idh.db.app_conn() as conn:
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # type: ignore[call-overload]  # noqa: S608
        with ew.idh.db.app_conn(uuid.uuid4()) as conn:
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # type: ignore[call-overload]  # noqa: S608


def test_history_tables_reject_update_delete_truncate_even_for_the_owner_role(
    ew: EdgeWorld,
) -> None:
    dev = ew.edge_device()
    dev.sync([dev.entry(ew.authorised_visit()), dev.entry(uuid.uuid4(), sign=False)])
    dev.policy()
    for table in APPEND_ONLY:
        assert ew.count(table) >= 1, table
        for statement in (
            f"UPDATE {table} SET society_id = society_id",
            f"DELETE FROM {table}",
            f"TRUNCATE {table}",
        ):
            with ew.idh.db.app_conn(ew.soc.id) as conn, pytest.raises(psycopg.errors.Error):
                conn.execute(statement)  # type: ignore[call-overload]
            with ew.idh.db.owner_conn() as conn, pytest.raises(psycopg.errors.Error):
                conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ew.soc.id),))
                conn.execute(statement)  # type: ignore[call-overload]


def test_least_privilege_grants(ew: EdgeWorld) -> None:
    def priv(role: str, table: str, kind: str) -> bool:
        return bool(ew.rows("SELECT has_table_privilege(%s, %s, %s)", (role, table, kind))[0][0])

    # Slice 3 integration (migration 0314, ADR-0019): the worker's policy publisher may INSERT exactly these two tables (and nothing else of
    # the edge tables); every other edge table stays read-only for the worker. The worker never UPDATEs at table level and never DELETEs.
    worker_inserts = {"policy_snapshots", "edge_credential_refs"}
    for table in TABLES:
        assert priv("dwaar_app", table, "SELECT") and priv("dwaar_app", table, "INSERT"), table
        assert not priv("dwaar_app", table, "DELETE") and not priv(
            "dwaar_app", table, "TRUNCATE"
        ), table
        assert priv("dwaar_worker", table, "SELECT"), table
        assert priv("dwaar_worker", table, "INSERT") == (table in worker_inserts), table
        assert not priv("dwaar_worker", table, "UPDATE") and not priv(
            "dwaar_worker", table, "DELETE"
        ), table
        assert not priv("dwaar_worker", table, "TRUNCATE"), table
    for table in APPEND_ONLY:
        assert not priv("dwaar_app", table, "UPDATE"), table

    def col(role: str, table: str, column: str) -> bool:
        return bool(
            ew.rows("SELECT has_column_privilege(%s, %s, %s, 'UPDATE')", (role, table, column))[0][
                0
            ]
        )

    assert col("dwaar_app", "edge_credential_refs", "state") and not col(
        "dwaar_app", "edge_credential_refs", "credential_ref"
    )
    assert col("dwaar_app", "edge_device_state", "highest_contiguous_seq") and not col(
        "dwaar_app", "edge_device_state", "device_id"
    )
    assert col("dwaar_app", "standing_rules", "state") and not col(
        "dwaar_app", "standing_rules", "params"
    )
    assert not col("dwaar_app", "standing_rules", "unit_id")
    # the worker publisher: the revocation columns of a credential reference and nothing more; the policy history stays append-only
    assert col("dwaar_worker", "edge_credential_refs", "revoked_at") and not col(
        "dwaar_worker", "edge_credential_refs", "credential_ref"
    )
    assert not col("dwaar_worker", "policy_snapshots", "signature") and not col(
        "dwaar_worker", "standing_rules", "state"
    )


def test_composite_foreign_keys_make_a_cross_society_reference_impossible(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    other = ew.idh.society("Rival Heights", units=("Z-1",))
    with ew.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(other.id),))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute(
                "INSERT INTO edge_events (society_id, device_id, seq, event_id, event_type, entity_id, entity_version, policy_version,"
                " status, occurred_at, clock_uncertainty_ms, payload_hash) VALUES (%s, %s, 1, %s, 'X', %s, 0, 0, 'accepted', now(), 0, %s)",
                (other.id, dev.device_id, uuid.uuid4(), uuid.uuid4(), "sha256:" + "0" * 64),
            )
    with ew.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(other.id),))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute("INSERT INTO standing_rules (society_id, unit_id, rule_kind, params, created_by) VALUES (%s, %s, 'allow_window', '{}', %s)",
                         (other.id, ew.soc.units["A-101"], ew.guard.id))  # fmt: skip


def test_uniqueness_of_the_ledger(ew: EdgeWorld) -> None:
    dev = ew.edge_device()
    ev = dev.event("DeviceHealth", uuid.uuid4())
    dev.sync([ev])
    row = ew.rows("SELECT society_id, device_id, seq, event_id FROM edge_events")[0]
    base = (
        "INSERT INTO edge_events (society_id, device_id, seq, event_id, event_type, entity_id, entity_version, policy_version, status,"
        " occurred_at, clock_uncertainty_ms, payload_hash) VALUES (%s, %s, %s, %s, 'X', %s, 0, 0, 'accepted', now(), 0, %s)"
    )
    for seq, event_id in ((row[2], uuid.uuid4()), (row[2] + 1, row[3])):
        with ew.idh.db.owner_conn() as conn, pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(row[0]),))
            conn.execute(base, (row[0], row[1], seq, event_id, uuid.uuid4(), "sha256:" + "0" * 64))


def test_the_slice_2_exception_kinds_survive_and_the_two_new_ones_exist(ew: EdgeWorld) -> None:
    with ew.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ew.soc.id),))
        for kind in ("overstay", "unauthorised_entry", "exit_unknown", "exit_without_entry", "emergency_entry", "manual_entry", "other",
                     "clock_implausible", "edge_quarantine"):  # fmt: skip
            conn.execute(
                "INSERT INTO exceptions (society_id, kind, reason, raised_by_system) VALUES (%s, %s, 'seeded for the test', true)",
                (ew.soc.id, kind),
            )
    with ew.idh.db.owner_conn() as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ew.soc.id),))
        conn.execute(
            "INSERT INTO exceptions (society_id, kind, reason, raised_by_system) VALUES (%s, 'made_up', 'seeded for the test', true)",
            (ew.soc.id,),
        )


def test_device_lookup_function_is_reviewed_narrow_and_not_a_backdoor(ew: EdgeWorld) -> None:
    dev = ew.edge_device()

    def can_execute(role: str) -> bool:
        return bool(
            ew.rows(
                "SELECT has_function_privilege(%s, 'edge.device_for_auth(uuid)', 'EXECUTE')",
                (role,),
            )[0][0]
        )

    assert (
        can_execute("dwaar_app") and not can_execute("dwaar_worker") and not can_execute("public")
    )
    meta = ew.rows("SELECT prosecdef, proconfig FROM pg_proc WHERE proname = 'device_for_auth'")[0]
    assert meta[0] is True and any("search_path" in c for c in meta[1])
    with ew.idh.db.app_conn() as conn:  # no society context at all
        row = conn.execute(
            "SELECT society_id, state, key_id FROM edge.device_for_auth(%s)", (dev.device_id,)
        ).fetchone()
        assert row is not None and row[0] == ew.soc.id and row[1] == "active"
        assert conn.execute(
            "SELECT count(*) FROM edge.device_for_auth(%s)", (uuid.uuid4(),)
        ).fetchone() == (0,)
        cols = [
            d.name
            for d in conn.execute(
                "SELECT * FROM edge.device_for_auth(%s)", (dev.device_id,)
            ).description
            or []
        ]
        assert conn.execute("SELECT count(*) FROM devices").fetchone() == (
            0,
        )  # the function is the only door, and it is a narrow one
    assert (
        "requested_by" not in cols and "capabilities" not in cols
    )  # nothing beyond what authentication needs


def test_the_directory_has_no_table_privilege_for_runtime_roles_and_follows_every_device_change(
    ew: EdgeWorld,
) -> None:
    dev = ew.edge_device(approve=False)

    def priv(role: str, kind: str) -> bool:
        return bool(
            ew.rows("SELECT has_table_privilege(%s, 'edge.device_directory', %s)", (role, kind))[0][
                0
            ]
        )

    assert not any(
        priv(r, k)
        for r in ("dwaar_app", "dwaar_worker", "public")
        for k in ("SELECT", "INSERT", "UPDATE", "DELETE")
    )
    with ew.idh.db.app_conn() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SELECT * FROM edge.device_directory")

    def state() -> str:
        return str(
            ew.rows(
                "SELECT state FROM edge.device_directory WHERE device_id = %s", (dev.device_id,)
            )[0][0]
        )

    assert state() == "pending_approval"
    version = ew.device_version(dev.device_id)
    ew.call(
        ew.guard_sup,
        "POST",
        ew.s(f"devices/{dev.device_id}/decision"),
        json={"decision": "approve", "expected_version": version},
    )
    assert state() == "active"
    ew.revoke_device(dev)
    assert (
        state() == "revoked"
    )  # the same transaction that revoked the device changed what authentication sees
    # a row for every device, with the same key as the device record
    mismatches = ew.rows(
        "SELECT count(*) FROM devices d LEFT JOIN edge.device_directory x ON x.device_id = d.id"
        " WHERE x.device_id IS NULL OR x.public_key <> d.public_key OR x.state <> d.state OR x.society_ref <> d.society_id"
    )[0][0]
    assert mismatches == 0


def test_the_application_role_cannot_forge_a_snapshot_for_another_society(ew: EdgeWorld) -> None:
    other = ew.idh.society("Rival Heights", units=("Z-1",))
    with ew.idh.db.app_conn(ew.soc.id) as conn, pytest.raises(psycopg.errors.Error):
        conn.execute(
            "INSERT INTO policy_snapshots (society_id, seq, issued_at, valid_until, issuer_key_id, content_hash, reason, manifest, signature)"
            " VALUES (%s, 1, now(), now() + interval '1 day', 'k', %s, 'initial', '{}', %s)",
            (other.id, "sha256:" + "0" * 64, "ed25519:" + "A" * 86),
        )


def test_a_purged_device_can_never_authenticate_again_and_nothing_is_deleted_from_the_directory(
    ew: EdgeWorld,
) -> None:
    dev = ew.edge_device(approve=False)
    with ew.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ew.soc.id),))
        conn.execute(
            "DELETE FROM devices WHERE id = %s", (dev.device_id,)
        )  # the privacy purge path runs as the owner
    assert ew.rows(
        "SELECT state FROM edge.device_directory WHERE device_id = %s", (dev.device_id,)
    ) == [("deleted",)]
    r = dev.me()
    assert r.status_code == 403 and r.json()["code"] == "not_authorised"
