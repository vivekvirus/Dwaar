"""Budget metrics and delivery telemetry (PRD 9.4 "Budget metrics", NOTIF-07, PRD 18.1, OBS-02).

REQ: PRD 9.4 (notifications and calls per 1,000 arrivals, failed calls, fallback share; "a high fallback rate is an operations problem to fix, not
a cost passed to the society"), PRD 18.1 (approval acknowledgement rate = requests with app acknowledgement before the configured fallback /
requests eligible for app delivery, reported by permission and network cohort), NOTIF-07 (delivery telemetry by phone model and OS version;
acknowledgement rate and fallback share), INV-12 (claims only from measurements: every number here is counted from rows, and the network cohort,
which the platform cannot observe, is reported as ``not_observed`` rather than guessed).

Definitions are returned WITH the numbers so a dashboard cannot present them differently.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Final

from sqlalchemy import Connection, text

from . import budget
from .config import NotificationsConfig
from .planner import Timings

DEFINITIONS: Final = {
    "acknowledgement_rate": "requests whose push was acknowledged by the app (app_received) before the configured fallback step / requests eligible for "
    "app delivery (an approver with a registered device whose notification permission was not denied); PRD 18.1",
    "fallback_share": "requests in which a fallback step (alternate push, masked call or link) was issued / all requests with a cascade",
    "notifications_per_1000_arrivals": "provider submissions of push, WhatsApp and SMS / arrivals (visits created) x 1000",
    "calls_per_1000_arrivals": "proxy and IVR calls placed / arrivals (visits created) x 1000",
    "failed_calls": "calls the provider refused or reported as failed (an unanswered call is not a failed call)",
    "network_cohort": "not_observed: the platform has no measurement of the resident's network; no figure is invented",
}
_ELIGIBLE_SQL: Final = (
    "EXISTS (SELECT 1 FROM notifications n WHERE n.cascade_id = c.id AND n.channel = 'push' AND n.token_id IS NOT NULL"
    " AND COALESCE(n.failure_reason, '') NOT IN ('notification_permission_denied', 'no_active_device', 'recipient_not_authorised'))"
)


def _rate(num: int, den: int) -> float | None:
    return None if den == 0 else round(num / den, 4)


def _per_1000(num: int, arrivals: int) -> float | None:
    return None if arrivals == 0 else round(num * 1000 / arrivals, 2)


def collect_metrics(
    conn: Connection,
    society_id: uuid.UUID,
    *,
    since: dt.datetime,
    until: dt.datetime,
    now: dt.datetime,
    cfg: NotificationsConfig | None = None,
) -> dict[str, Any]:
    """The budget and acknowledgement numbers of one society over ``[since, until)``."""
    cfg = cfg or NotificationsConfig()
    window = {"a": since, "b": until}
    arrivals = int(
        conn.execute(
            text("SELECT count(*) FROM visits WHERE created_at >= :a AND created_at < :b"), window
        ).scalar_one()
    )
    by_channel = {
        str(ch): int(n)
        for ch, n in conn.execute(
            text(
                "SELECT channel, count(*) FROM notifications WHERE sent_at >= :a AND sent_at < :b AND provider_ref IS NOT NULL"
                " GROUP BY channel"
            ),
            window,
        ).all()
    }
    calls = by_channel.get("ivr_call", 0)
    notifications = sum(n for ch, n in by_channel.items() if ch != "ivr_call")
    failed_calls = int(
        conn.execute(
            text(
                "SELECT count(*) FROM notifications n LEFT JOIN proxy_call_sessions s ON s.society_id = n.society_id AND s.notification_id = n.id"
                " WHERE n.channel = 'ivr_call' AND n.created_at >= :a AND n.created_at < :b"
                " AND (n.failure_reason IS NOT NULL OR s.state = 'failed' OR s.dial_outcome = 'failed')"
            ),
            window,
        ).scalar_one()
    )
    unanswered = int(
        conn.execute(
            text(
                "SELECT count(*) FROM proxy_call_sessions WHERE created_at >= :a AND created_at < :b"
                " AND dial_outcome IN ('no_answer', 'busy', 'rejected')"
            ),
            window,
        ).scalar_one()
    )
    cascades = (
        conn.execute(
            text(
                "SELECT c.id, c.started_at, c.plan, c.state, "  # noqa: S608
                + _ELIGIBLE_SQL
                + " AS eligible,"
                " (SELECT min(n.app_received_at) FROM notifications n WHERE n.cascade_id = c.id AND n.channel = 'push' AND n.cascade_step = 1) AS first_ack,"
                " EXISTS (SELECT 1 FROM notifications n WHERE n.cascade_id = c.id AND n.cascade_step >= 2) AS fallback_used,"
                " (SELECT n.token_id IS NOT NULL FROM notifications n WHERE n.cascade_id = c.id AND n.channel = 'push' AND n.cascade_step = 1 LIMIT 1) AS had_token,"
                " (SELECT t.notification_permission FROM notifications n JOIN device_push_tokens t ON t.society_id = n.society_id AND t.id = n.token_id"
                "   WHERE n.cascade_id = c.id AND n.channel = 'push' AND n.cascade_step = 1 ORDER BY n.created_at LIMIT 1) AS permission"
                " FROM notification_cascades c WHERE c.attempt_no = 1 AND c.started_at >= :a AND c.started_at < :b"
            ),
            window,
        )
        .mappings()
        .all()
    )
    total = len(cascades)
    eligible = acked = fallback = 0
    cohorts: dict[str, list[int]] = {}
    for c in cascades:
        timings = Timings.from_plan(c["plan"])
        if c["fallback_used"]:
            fallback += 1
        if not c["eligible"]:
            continue
        eligible += 1
        hit = (
            c["first_ack"] is not None
            and (c["first_ack"] - c["started_at"]).total_seconds() <= timings.alternate_at
        )
        acked += 1 if hit else 0
        cohort = str(c["permission"] or "unknown")
        bucket = cohorts.setdefault(cohort, [0, 0])
        bucket[0] += 1 if hit else 0
        bucket[1] += 1
    share = _rate(fallback, total)
    attention = bool(share is not None and total >= 5 and share > cfg.fallback_alert_share)
    return {
        "window": {"since": since, "until": until},
        "arrivals": arrivals,
        "notifications": {"total": notifications, "by_channel": by_channel},
        "calls": {"total": calls, "failed": failed_calls, "unanswered": unanswered},
        "notifications_per_1000_arrivals": _per_1000(notifications, arrivals),
        "calls_per_1000_arrivals": _per_1000(calls, arrivals),
        "requests_with_cascade": total,
        "approval_acknowledgement": {
            "eligible_requests": eligible,
            "acknowledged_before_fallback": acked,
            "rate": _rate(acked, eligible),
            "by_permission_cohort": {
                k: {"acknowledged": v[0], "eligible": v[1], "rate": _rate(v[0], v[1])}
                for k, v in sorted(cohorts.items())
            },
            "by_network_cohort": "not_observed",
        },
        "fallback": {
            "requests_using_fallback": fallback,
            "share": share,
            "ops_attention": attention,
            "cost_passed_to_society": False,
            "note": "A high fallback share is an operations problem to fix (device onboarding, OEM guidance, provider health), not a cost passed to the society.",
        },
        "budget": budget.view(conn, now),
        "definitions": dict(DEFINITIONS),
        "simulation": cfg.simulation,
    }


def device_health(
    conn: Connection, *, since: dt.datetime, until: dt.datetime, limit: int = 100
) -> dict[str, Any]:
    """Delivery telemetry by phone model and OS version (NOTIF-07): how many pushes, how many the app acknowledged before the fallback, how many
    cascades fell back. Telemetry comes from what devices reported (``simulation`` marks simulated reports); a model is never a person."""
    rows = (
        conn.execute(
            text(
                "SELECT COALESCE(n.phone_model, 'unknown') AS model, COALESCE(n.manufacturer, 'unknown') AS manufacturer,"
                " COALESCE(n.os_name, 'unknown') AS os_name, COALESCE(n.os_version, 'unknown') AS os_version,"
                " count(*) AS sent,"
                " count(*) FILTER (WHERE n.provider_accepted_at IS NOT NULL) AS provider_accepted,"
                " count(*) FILTER (WHERE n.app_received_at IS NOT NULL) AS app_received,"
                " count(*) FILTER (WHERE n.displayed_at IS NOT NULL) AS displayed,"
                " count(*) FILTER (WHERE n.app_received_at IS NOT NULL AND n.app_received_at <= n.created_at"
                "   + make_interval(secs => COALESCE((c.plan -> 'steps' -> 1 ->> 'at_seconds')::int, 10))) AS acknowledged_before_fallback,"
                " count(DISTINCT n.cascade_id) AS cascades,"
                " count(DISTINCT n.cascade_id) FILTER (WHERE EXISTS (SELECT 1 FROM notifications f WHERE f.cascade_id = n.cascade_id"
                "   AND f.cascade_step >= 2)) AS cascades_with_fallback,"
                " bool_or(n.simulation) AS simulation"
                " FROM notifications n JOIN notification_cascades c ON c.society_id = n.society_id AND c.id = n.cascade_id"
                " WHERE n.channel = 'push' AND n.token_id IS NOT NULL AND n.provider_accepted_at IS NOT NULL"
                " AND n.created_at >= :a AND n.created_at < :b"
                " GROUP BY 1, 2, 3, 4 ORDER BY count(*) DESC, 1, 3, 4 LIMIT :n"
            ),
            {"a": since, "b": until, "n": limit},
        )
        .mappings()
        .all()
    )
    groups = [
        {
            "phone_model": r["model"],
            "manufacturer": r["manufacturer"],
            "os_name": r["os_name"],
            "os_version": r["os_version"],
            "pushes_accepted_by_provider": int(r["provider_accepted"]),
            "app_received": int(r["app_received"]),
            "displayed": int(r["displayed"]),
            "acknowledgement_rate": _rate(
                int(r["acknowledged_before_fallback"]), int(r["provider_accepted"])
            ),
            "fallback_share": _rate(int(r["cascades_with_fallback"]), int(r["cascades"])),
            "simulation": bool(r["simulation"]),
        }
        for r in rows
    ]
    blocked = {
        str(reason): int(n)
        for reason, n in conn.execute(
            text(
                "SELECT failure_reason, count(*) FROM notifications WHERE channel = 'push' AND created_at >= :a AND created_at < :b"
                " AND failure_reason IN ('notification_permission_denied', 'no_active_device', 'provider_unavailable') GROUP BY 1"
            ),
            {"a": since, "b": until},
        ).all()
    }
    return {
        "window": {"since": since, "until": until},
        "groups": groups,
        "not_sent": blocked,
        "definitions": {
            "acknowledgement_rate": "pushes the provider accepted that the app acknowledged before the fallback step / pushes the provider accepted",
            "fallback_share": "cascades of that model and OS in which a fallback step was issued / cascades",
        },
    }
