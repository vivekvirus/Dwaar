"""Notifications: the default template catalog, a budget row, the A-203 household's approvers and two SIMULATED push devices.

REQ: NOTIF-01 (templates per category; SMS templates carry NO DLT ids: placeholders until the society registers them, CALL-02), NOTIF-03 (A-203: Ganesh is
the primary approver, Rekha the configured alternate adult, fallback a masked call), PRD 9.4 budget metrics (a budget row with the default caps),
D-21 (devices are simulated; nothing here reaches a provider), BUILD_BRIEF 6 / 7 (every simulated thing is labelled ``simulation = true``).

Everything goes through the module's SERVICE functions as ``dwaar_app`` with the RLS context of the real actor, so each row has its audit and outbox
record; a second run changes nothing (every object is looked up by its natural key first).
"""

from __future__ import annotations

from sqlalchemy import text

from ...modules.notifications import devices, households, service, templates
from ...modules.notifications.config import NotificationsConfig
from ..runtime import SeedContext
from . import s400_visits

NAME = "notifications"
ORDER = 590

_SIM_DEVICES = (
    ("ganesh", "Redmi Note 12", "Xiaomi", "HyperOS", "1.0"),
    ("rekha", "Galaxy A54", "Samsung", "Android", "14"),
)


def _token(person_key: str) -> str:
    return f"simulated-seed-token-{person_key}-0000000000000000"


def run(ctx: SeedContext) -> None:
    cfg = NotificationsConfig.from_environment(ctx.settings, simulation_allowed=True)
    for plan in s400_visits.PLANS:
        soc = ctx.society(plan.society)
        with ctx.tx(f"notifications:templates:{plan.society}", society=soc.id, role="system") as (
            conn,
            rctx,
        ):
            made = templates.ensure_defaults(conn, rctx, cfg.link_hosts)
        ctx.count("notification_templates_created", made)
        secretary = ctx.person(plan.secretary)
        with ctx.tx(f"notifications:budget-read:{plan.society}", society=soc.id, role="seed") as (
            conn,
            _c,
        ):
            has_budget = (
                conn.execute(text("SELECT 1 FROM notification_budgets")).first() is not None
            )
        if not has_budget:
            with ctx.tx(
                f"notifications:budget:{plan.society}",
                society=soc.id,
                person=secretary,
                role="secretary",
            ) as (conn, rctx):
                service.set_budget(
                    conn, rctx, monthly_notification_cap=30_000, monthly_call_cap=3_000, monthly_sms_cap=3_000, expected_version=None
                )  # fmt: skip
            ctx.count("notification_budgets_created")
        if plan.society != "mh":
            continue
        unit = soc.unit("A", "203")
        ganesh, rekha = ctx.person("ganesh"), ctx.person("rekha")
        for key, model, maker, os_name, os_version in _SIM_DEVICES:
            person = ctx.person(key)
            with ctx.tx(f"notifications:device-read:{key}", society=soc.id, role="seed") as (
                conn,
                _c,
            ):
                have = conn.execute(
                    text(
                        "SELECT 1 FROM device_push_tokens WHERE person_id = :p AND revoked_at IS NULL AND device_label = :l"
                    ),
                    {"p": person, "l": "Seeded simulated phone"},
                ).first()
            if have is not None:
                continue
            with ctx.tx(
                f"notifications:device:{key}",
                society=soc.id,
                person=person,
                role="owner_occ" if key == "ganesh" else "family",
            ) as (conn, rctx):
                devices.register_token(
                    conn, rctx, person, platform="fcm", token=_token(key), device_label="Seeded simulated phone", device_model=model,
                    manufacturer=maker, os_name=os_name, os_version=os_version, app_version="1.0.0",
                    notification_permission="granted", simulation=True,
                )  # fmt: skip
            ctx.count("notification_devices_registered")
        with ctx.tx("notifications:settings-read:A-203", society=soc.id, role="seed") as (conn, _c):
            settings = households.get_unit_settings(conn, unit)
        if settings is None:
            with ctx.tx(
                "notifications:settings:A-203", society=soc.id, person=ganesh, role="owner_occ"
            ) as (conn, rctx):
                households.put_unit_settings(
                    conn, rctx, unit, primary_person_id=ganesh, approver_person_ids=[ganesh], alternate_person_id=rekha,
                    fallback_mode="call", expected_version=None,
                )  # fmt: skip
            ctx.count("notification_household_settings_created")
    ctx.say(
        "  notifications: default templates (SMS DLT ids are placeholders), budgets, the A-203 approvers and two SIMULATED devices"
        f" ({ctx.counts.get('notification_templates_created', 0)} templates this run)"
    )


__all__ = ["NAME", "ORDER", "run"]
