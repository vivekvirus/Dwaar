"""Database-level guarantees of migration 0500: RLS in the same migration, append-only history, composite foreign keys, least-privilege grants,
the NOTIF-02 state list, CALL-01 no-recording, one call per role and attempt, and the processed-event ledger.

REQ: NOTIF-02, NOTIF-03, CALL-01, DB-02, ARCH-01, ARCH-03, INV-01, NOTIF-01.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest

from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("INV-01", "ARCH-01", "DB-02", "NOTIF-02")]

TABLES = (
    "notification_templates", "notification_preferences", "unit_notification_settings", "device_push_tokens", "notification_cascades",
    "notifications", "notification_attempts", "proxy_call_sessions", "notification_budgets", "notification_counters",
    "device_health_reports", "notification_processed_events",
)  # fmt: skip
APPEND_ONLY = ("notification_attempts", "device_health_reports", "notification_processed_events")


def test_every_table_has_forced_row_level_security_and_a_society_policy(nw: NW) -> None:
    for table in TABLES:
        assert nw.rows(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s", (table,)
        )[0] == (True, True), table
        assert (
            nw.rows("SELECT count(*) FROM pg_policies WHERE tablename = %s", (table,))[0][0] >= 1
        ), table
        assert nw.rows(
            "SELECT is_nullable FROM information_schema.columns WHERE table_name = %s AND column_name = 'society_id'", (table,)
        ) == [("NO",)], table  # fmt: skip


def test_no_context_means_zero_rows_never_all_rows(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    nw.register_device(owner, "p")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    for table in TABLES:
        with nw.idh.db.app_conn() as conn:
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # type: ignore[call-overload]  # noqa: S608
        with nw.idh.db.app_conn(uuid.uuid4()) as conn:
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # type: ignore[call-overload]  # noqa: S608
    assert nw.count("notifications") >= 1 and nw.count("notification_cascades") == 1


def test_history_tables_reject_update_delete_truncate(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    nw.register_device(owner, "p")
    nw.call(
        owner,
        "POST",
        nw.s("device-diagnostics"),
        json={"manufacturer": "Oppo", "notification_permission": "granted"},
    )
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    for table in APPEND_ONLY:
        assert nw.count(table) >= 1, table
        for statement in (
            f"UPDATE {table} SET society_id = society_id",
            f"DELETE FROM {table}",
            f"TRUNCATE {table}",
        ):
            with nw.idh.db.app_conn(nw.soc.id) as conn, pytest.raises(psycopg.errors.Error):
                conn.execute(statement)  # type: ignore[call-overload]
            with nw.idh.db.owner_conn() as conn, pytest.raises(psycopg.errors.Error):
                conn.execute("SELECT set_config('app.society_id', %s, true)", (str(nw.soc.id),))
                conn.execute(statement)  # type: ignore[call-overload]


def test_least_privilege_grants(nw: NW) -> None:
    def priv(role: str, table: str, kind: str) -> bool:
        return bool(nw.rows("SELECT has_table_privilege(%s, %s, %s)", (role, table, kind))[0][0])

    for table in TABLES:
        for role in ("dwaar_app", "dwaar_worker"):
            assert not priv(role, table, "DELETE") and not priv(role, table, "TRUNCATE"), (
                role,
                table,
            )
            assert not priv(role, table, "UPDATE"), (
                role,
                table,
            )  # UPDATE only ever column-scoped, never table-wide
    # what the worker may write: the cascade, its notifications, the delivery log, call sessions, counters, the ledger; nothing else
    worker_inserts = {
        "notification_cascades",
        "notifications",
        "notification_attempts",
        "proxy_call_sessions",
        "notification_counters",
        "notification_processed_events",
    }
    for table in TABLES:
        assert priv("dwaar_worker", table, "INSERT") == (table in worker_inserts), table
        assert priv("dwaar_worker", table, "SELECT"), table
    # the worker can not forge a template, a preference, a household setting, a budget or a health report
    for table in (
        "notification_templates",
        "notification_preferences",
        "unit_notification_settings",
        "notification_budgets",
        "device_health_reports",
    ):
        assert not priv("dwaar_worker", table, "INSERT")
    # the API role never writes the ledger and cannot hand-write a processed event
    assert not priv("dwaar_app", "notification_processed_events", "INSERT")


def test_the_worker_cannot_update_columns_it_has_no_business_with(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    nw.register_device(owner, "p")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    from dwaar_api.core.db import RequestContext

    assert nw.database is not None
    for sql in (
        "UPDATE notifications SET recipient_person_id = recipient_person_id",
        "UPDATE notifications SET category = 'emergency'",
        "UPDATE notification_cascades SET started_at = started_at",
        "UPDATE device_push_tokens SET person_id = person_id",
        "UPDATE device_push_tokens SET notification_permission = 'granted'",
    ):
        with (
            pytest.raises(Exception, match="permission denied"),
            nw.database.worker_tx(RequestContext(nw.soc.id, None, "system", None)) as conn,
        ):
            from sqlalchemy import text

            conn.execute(text(sql))


def test_only_the_six_notif_02_states_exist_and_a_state_needs_its_evidence(nw: NW) -> None:
    states = nw.rows(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'notifications'::regclass AND contype = 'c'"
    )
    text = " ".join(s[0] for s in states)
    for state in (
        "created",
        "provider_accepted",
        "app_received",
        "displayed",
        "actioned",
        "expired",
    ):
        assert f"'{state}'" in text
    for forbidden in ("delivered", "sent'", "read'", "failed'"):
        assert f"'{forbidden}" not in text.replace("failure_reason", "")
    owner, _ = nw.household2("A-101")
    nw.register_device(owner, "p")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    nid = nw.nrows(request["id"])[0]["id"]
    for bad in (
        "UPDATE notifications SET state = 'app_received', app_received_at = NULL",
        "UPDATE notifications SET state = 'displayed', displayed_at = now(), app_received_at = NULL",
        "UPDATE notifications SET state = 'actioned', actioned_at = NULL",
        "UPDATE notifications SET state = 'expired', expired_at = NULL",
        "UPDATE notifications SET state = 'delivered'",
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            nw.sql(bad + " WHERE id = %s", (nid,))


def test_the_database_enforces_one_primary_and_one_alternate_call_per_attempt_and_no_recording(
    nw: NW,
) -> None:
    idx = nw.rows(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'notifications_one_call_per_role_uq'"
    )[0][0]
    assert "ivr_call" in idx and "primary" in idx and "alternate" in idx and "attempt_no" in idx
    check = nw.rows(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname LIKE 'proxy_call_sessions_recording%%' OR (conrelid = 'proxy_call_sessions'::regclass AND pg_get_constraintdef(oid) LIKE '%%recording_enabled%%')"
    )
    assert check and "recording_enabled = false" in check[0][0]


def test_cross_society_references_are_refused_by_composite_foreign_keys(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    other = nw.idh.society("Other Heights", units=("Z-1",))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        nw.sql(
            "INSERT INTO notification_cascades (society_id, request_id, unit_id, attempt_no, started_at, expires_at, plan)"
            " VALUES (%s, %s, %s, 1, now(), now() + interval '90 seconds', '{}')",
            (other.id, request["id"], other.units["Z-1"]),
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        nw.sql(
            "INSERT INTO unit_notification_settings (society_id, unit_id) VALUES (%s, %s)",
            (other.id, nw.unit("A-101")),
        )


def test_the_processed_event_ledger_is_unique_per_society_and_event(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]))
    row = nw.rows("SELECT society_id, event_id FROM notification_processed_events LIMIT 1")[0]
    with pytest.raises(psycopg.errors.UniqueViolation):
        nw.sql(
            "INSERT INTO notification_processed_events (society_id, event_id, event_type) VALUES (%s, %s, 'ApprovalRequested')",
            row,
        )


def test_the_cascade_time_helpers_stay_in_the_request_lifetime(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    request = nw.raise_request(nw.unit("A-101"))
    nw.tick(nw.created_at(request["id"]) + secs(1))
    assert nw.rows(
        "SELECT attempt_no, state, started_at = (SELECT created_at FROM approval_requests WHERE id = %s) FROM notification_cascades",
        (request["id"],),
    ) == [(1, "active", True)]
