"""The notifications part of the synthetic seed (steps/s590_notifications.py): shape, honesty, determinism, idempotency.

REQ: NOTIF-01, NOTIF-03, CALL-02 (SMS templates are DLT placeholders), D-21 (simulated devices), BUILD_BRIEF 7.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api import seed
from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment

pytestmark = [pytest.mark.req("NOTIF-01", "NOTIF-03", "CALL-02")]


@pytest.fixture(scope="module")
def seeded(pg_server: PgServer, template_db: str) -> Iterator[World]:
    for handle in _clone(pg_server, template_db):
        w = build_world(handle)
        try:
            yield w
        finally:
            w.database.dispose()


def _one(w: World, sql: str, *params: Any) -> Any:
    return w.admin_rows(sql, params)[0][0]


def test_every_society_gets_the_default_templates_and_the_sms_ones_are_placeholders(seeded: World) -> None:
    w = seeded
    per_society = w.admin_rows("SELECT society_id, count(*) FROM notification_templates GROUP BY 1")
    assert len(per_society) == 2 and {n for _s, n in per_society} == {24}  # eight templates in three languages
    cats = {r[0] for r in w.admin_rows("SELECT DISTINCT category FROM notification_templates")}
    assert cats == {"security_approval", "emergency", "finance", "service_ticket", "community_digest"}
    sms = w.admin_rows("SELECT dlt_header, dlt_template_id, whitelisted_url FROM notification_templates WHERE channel = 'sms'")
    assert sms and all(h is None and t is None and u.startswith("https://") for h, t, u in sms)  # no invented DLT registration
    assert _one(w, "SELECT count(*) FROM notification_templates WHERE category IN ('security_approval','emergency') AND content_class <> 'transactional'") == 0


def test_the_a203_household_is_configured_with_an_alternate_adult(seeded: World) -> None:
    w = seeded
    row = w.admin_rows(
        "SELECT p.display_name, a.display_name, s.fallback_mode, s.approver_person_ids = ARRAY[s.primary_person_id]"
        " FROM unit_notification_settings s JOIN iam.persons p ON p.id = s.primary_person_id"
        " JOIN iam.persons a ON a.id = s.alternate_person_id"
    )
    assert row == [("Ganesh Pawar", "Rekha Pawar", "call", True)]


def test_the_seeded_devices_are_simulated_and_hold_no_raw_token(seeded: World) -> None:
    w = seeded
    rows = w.admin_rows("SELECT simulation, notification_permission, platform, token_hash, token_ref FROM device_push_tokens ORDER BY registered_at")
    assert len(rows) == 2 and all(r[0] is True and r[1] == "granted" and r[2] == "fcm" and len(r[3]) == 64 for r in rows)
    assert "simulated-seed-token" not in " ".join("".join(r[3:]) for r in rows)


def test_budgets_exist_and_nothing_was_sent(seeded: World) -> None:
    w = seeded
    assert _one(w, "SELECT count(*) FROM notification_budgets") == 2
    assert _one(w, "SELECT count(*) FROM notifications") == 0 and _one(w, "SELECT count(*) FROM proxy_call_sessions") == 0  # no provider was ever called


def test_every_seeded_row_has_its_audit_and_outbox_record(seeded: World) -> None:
    w = seeded
    ops = {r[0] for r in w.admin_rows("SELECT DISTINCT operation FROM audit_log WHERE operation LIKE 'notification.%%'")}
    assert {"notification.template.create", "notification.budget.set", "notification.token.register", "notification.unit_settings.put"} <= ops
    events = {r[0] for r in w.admin_rows("SELECT DISTINCT event_type FROM outbox WHERE event_type LIKE 'notification.%%'")}
    assert {"notification.template_created", "notification.budget_changed", "notification.token_registered", "notification.unit_settings_changed"} <= events


def test_second_run_changes_nothing(seeded: World) -> None:
    w = seeded
    tables = ("notification_templates", "notification_budgets", "unit_notification_settings", "device_push_tokens", "audit_log", "outbox")
    sql = "SELECT " + ", ".join(f"(SELECT count(*) FROM {t})" for t in tables)  # noqa: S608
    before = w.admin_rows(sql)
    again = seed.run(seed_environment(w.db), say=lambda _l: None)
    assert w.admin_rows(sql) == before
    assert not {k: v for k, v in again.counts.items() if v and k.startswith("notification_")}


def test_ids_are_deterministic_across_databases(pg_server: PgServer, template_db: str, seeded: World) -> None:
    def snapshot(w: World) -> list[tuple[Any, ...]]:
        return w.admin_rows("SELECT id, template_key, channel, language FROM notification_templates ORDER BY template_key, channel, language, society_id")

    first = snapshot(seeded)
    for handle in _clone(pg_server, template_db):
        other = build_world(handle)
        try:
            assert snapshot(other) == first
        finally:
            other.database.dispose()
