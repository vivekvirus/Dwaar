"""Per-society notification and call budgets and counters (PRD 9.4 budget metrics).

REQ: PRD 9.4 "Budget metrics" (notifications and calls per 1,000 arrivals, failed calls, fallback share; "a high fallback rate is an operations problem
to fix, not a cost passed to the society"), NOTIF-01 / INV-03 (a cost cap must never make an entry decision slower or less safe), OBS-02.

Policy, stated once:

* The caps bound the SPEND of the non-safety categories (finance, service ticket, community digest): when a cap is reached those sends are
  REFUSED with ``failure_reason = budget_exhausted`` and counted (``budget_blocked``).
* Security approval and emergency sends are NEVER blocked by a cap. They are counted, and past the cap they are also counted as ``over_budget``:
  an operations signal (raise the cap, find out why the fallback rate is high), not a cost passed to the society and not a reason to leave a
  resident unreached.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Final
from zoneinfo import ZoneInfo

from sqlalchemy import Connection, text

from dwaar_common.ids import uuid7

from . import categories as cat

IST: Final = ZoneInfo("Asia/Kolkata")
DEFAULT_CAPS: Final = {"notification": 30_000, "call": 3_000, "sms": 3_000}
KIND_OF_CHANNEL: Final = {
    "push": "notification",
    "whatsapp": "notification",
    "ivr_call": "call",
    "sms": "sms",
}


def period_of(moment: dt.datetime) -> str:
    """The IST calendar month a moment belongs to (``2026-10``)."""
    return moment.astimezone(IST).strftime("%Y-%m")


@dataclass(frozen=True)
class Caps:
    notification: int
    call: int
    sms: int

    def cap_for(self, kind: str) -> int:
        return {"notification": self.notification, "call": self.call, "sms": self.sms}[kind]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    kind: str
    used: int
    cap: int
    over_budget: bool = False


def load_caps(conn: Connection) -> Caps:
    row = conn.execute(
        text(
            "SELECT monthly_notification_cap, monthly_call_cap, monthly_sms_cap FROM notification_budgets"
        )
    ).first()
    if row is None:
        return Caps(**DEFAULT_CAPS)
    return Caps(int(row[0]), int(row[1]), int(row[2]))


def used(conn: Connection, period: str) -> dict[str, int]:
    rows = conn.execute(
        text("SELECT kind, n FROM notification_counters WHERE period = :p"), {"p": period}
    ).all()
    return {str(k): int(n) for k, n in rows}


def bump(conn: Connection, society_id: uuid.UUID, period: str, kind: str, by: int = 1) -> None:
    conn.execute(
        text(
            "INSERT INTO notification_counters (id, society_id, period, kind, n) VALUES (:id, :s, :p, :k, :n)"
            " ON CONFLICT (society_id, period, kind) DO UPDATE SET n = notification_counters.n + :n"
        ),
        {"id": uuid7(), "s": society_id, "p": period, "k": kind, "n": by},
    )


def authorise_send(
    conn: Connection, society_id: uuid.UUID, *, category: str, channel: str, now: dt.datetime
) -> Decision:
    """Decide whether a send may go to a provider, and count it. Safety categories always may (see the module docstring)."""
    kind = KIND_OF_CHANNEL[channel]
    period = period_of(now)
    caps = load_caps(conn)
    counts = used(conn, period)
    n, cap = counts.get(kind, 0), caps.cap_for(kind)
    exhausted = n >= cap
    if exhausted and category not in cat.CLEAN_CATEGORIES:
        bump(conn, society_id, period, "budget_blocked")
        return Decision(False, kind, n, cap)
    bump(conn, society_id, period, kind)
    if exhausted:
        bump(conn, society_id, period, "over_budget")
    return Decision(True, kind, n + 1, cap, over_budget=exhausted)


def view(conn: Connection, now: dt.datetime) -> dict[str, object]:
    caps = load_caps(conn)
    period = period_of(now)
    counts = used(conn, period)
    return {
        "period": period,
        "caps": {"notification": caps.notification, "call": caps.call, "sms": caps.sms},
        "used": {k: counts.get(k, 0) for k in ("notification", "call", "sms")},
        "over_budget": counts.get("over_budget", 0),
        "blocked": counts.get("budget_blocked", 0),
        "policy": {
            "security_and_emergency_never_blocked": True,
            "cost_passed_to_society": False,
        },
    }
