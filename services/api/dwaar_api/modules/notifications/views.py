"""What the API shows about notifications: truthful states, the guard's status board, the fallback the guard is offered.

REQ: NOTIF-02 (provider acceptance is NEVER presented as delivery to a person: ``person_reached`` needs the app's own receipt), NOTIF-03 (guard
options after expiry), AT-11 (no false delivery claim; the configured call or the intercom is offered), CALL-01 (provider outage exposes the intercom
or office process; no number, no name), GATE-13, INV-03, INV-07.

No view carries a phone number or a resident's name. A guard sees roles ("primary", "alternate"), never persons.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from . import households
from .planner import STEP_EXPIRE, Timings, due_steps

#: provider-side failure reasons: the notification service itself is not working (CALL-01)
OUTAGE_REASONS: Final = frozenset(
    {"provider_unavailable", "provider_error", "provider_not_configured"}
)
#: reasons the PHONE cannot show the alert, whatever the provider did
UNREACHABLE_REASONS: Final = frozenset({"no_active_device", "notification_permission_denied"})

COLUMN_NAMES: Final = (
    "id", "request_id", "cascade_id", "attempt_no", "category", "channel", "cascade_step", "recipient_role",
    "recipient_person_id", "state", "failure_reason", "closed_reason", "provider", "simulation", "lockscreen_identity",
    "action", "created_at", "sent_at", "provider_accepted_at", "app_received_at", "displayed_at", "actioned_at",
    "expired_at", "invalidated_at", "phone_model", "os_name", "os_version",
)  # fmt: skip
_COLUMNS: Final = ", ".join(COLUMN_NAMES)
N_COLUMNS: Final = ", ".join(f"n.{c}" for c in COLUMN_NAMES)


def notification_view(row: Mapping[str, Any], *, audience: str) -> dict[str, Any]:
    """One notification. ``person_reached`` is true only when the person's own app reported receipt (or the person answered): a provider's
    acceptance is ``provider_accepted`` and nothing more (NOTIF-02)."""
    reached = row["app_received_at"] is not None or row["actioned_at"] is not None
    out: dict[str, Any] = {
        "id": row["id"],
        "request_id": row["request_id"],
        "category": row["category"],
        "channel": row["channel"],
        "state": row["state"],
        "state_text_key": f"status.{row['state']}",
        "provider_accepted": row["provider_accepted_at"] is not None,
        "person_reached": reached,
        "failure_reason": row["failure_reason"],
        "closed_reason": row["closed_reason"],
        "created_at": row["created_at"],
        "provider_accepted_at": row["provider_accepted_at"],
        "app_received_at": row["app_received_at"],
        "displayed_at": row["displayed_at"],
        "actioned_at": row["actioned_at"],
        "expired_at": row["expired_at"],
        "action": row["action"],
        "simulation": row["simulation"],
    }
    if audience == "guard":
        out["cascade_step"] = row["cascade_step"]
        out["recipient_role"] = row["recipient_role"]
        out["attempt_no"] = row["attempt_no"]
    else:
        out["lockscreen_identity"] = row["lockscreen_identity"]
    return out


def fetch_notifications(
    conn: Connection, request_id: uuid.UUID, attempt_no: int | None = None
) -> list[dict[str, Any]]:
    sql = f"SELECT {_COLUMNS} FROM notifications WHERE request_id = :r"  # noqa: S608
    params: dict[str, Any] = {"r": request_id}
    if attempt_no is not None:
        sql += " AND attempt_no = :n"
        params["n"] = attempt_no
    rows = conn.execute(text(sql + " ORDER BY created_at, id"), params).mappings()
    return [dict(r) for r in rows]


def fallback_view(
    rows: Sequence[Mapping[str, Any]],
    *,
    mode: str,
    started_at: dt.datetime | None,
    now: dt.datetime,
    timings: Timings,
    request_state: str,
) -> dict[str, Any]:
    """What the guard may do when the app has not answered. Never claims a person was reached unless the app says so (AT-11)."""
    pushes = [r for r in rows if r["channel"] == "push"]
    reached = any(r["app_received_at"] is not None or r["actioned_at"] is not None for r in rows)
    outage = any(r["failure_reason"] in OUTAGE_REASONS for r in rows) and not reached
    unreachable = bool(pushes) and all(
        r["failure_reason"] in UNREACHABLE_REASONS or r["failure_reason"] in OUTAGE_REASONS
        for r in pushes
    )
    elapsed = (now - started_at).total_seconds() if started_at else 0.0
    silent = (
        not reached
        and bool(pushes)
        and any(r["provider_accepted_at"] is not None for r in pushes)
        and elapsed >= timings.alternate_at
    )
    offered: list[str] = []
    reason: str | None = None
    text_key: str | None = None
    if request_state == "pending" and not reached:
        if outage:
            offered, reason, text_key = (
                ["intercom", "office"],
                "provider_outage",
                "fallback.provider_outage",
            )
        elif unreachable or silent:
            reason = "app_unreachable" if unreachable else "no_app_acknowledgement"
            offered = ["masked_call", "intercom"] if mode == "call" else ["intercom"]
            text_key = "fallback.call" if mode == "call" else "fallback.intercom"
    return {
        "mode": mode,
        "offered": offered,
        "reason": reason,
        "text_key": text_key,
        "provider_outage": outage,
        "person_reached": reached,
    }


def status_view(
    conn: Connection,
    request: Mapping[str, Any],
    *,
    now: dt.datetime,
) -> dict[str, Any]:
    """The guard / supervisor board of one request: the cascade by step, every notification with its honest state, calls, the fallback and, after
    expiry, the guard-assisted options. No person ids, names or numbers."""
    cascades = (
        conn.execute(
            text(
                "SELECT id, attempt_no, started_at, expires_at, plan, state, guard_options, ended_reason"
                " FROM notification_cascades WHERE request_id = :r ORDER BY attempt_no"
            ),
            {"r": request["id"]},
        )
        .mappings()
        .all()
    )
    live = next((c for c in reversed(cascades) if c["state"] == "active"), None)
    current = live or (cascades[-1] if cascades else None)
    timings = Timings.from_plan(current["plan"] if current else request.get("cascade"))
    rows = fetch_notifications(conn, request["id"])
    household = households.resolve_household(conn, request["unit_id"])
    issued = {(r["attempt_no"], r["cascade_step"]) for r in rows}
    steps: list[dict[str, Any]] = []
    for step, secs in due_steps(timings):
        issued_now = current is not None and (current["attempt_no"], step) in issued
        steps.append(
            {
                "step": step,
                "at_seconds": secs,
                "due_at": None
                if current is None
                else current["started_at"] + dt.timedelta(seconds=secs),
                "issued": bool(issued_now)
                if step != STEP_EXPIRE
                else request["state"] == "expired",
            }
        )
    calls = conn.execute(
        text(
            "SELECT id, purpose, state, dial_outcome, duration_seconds, ttl_expires_at, masked_label, created_at, recording_enabled, simulation"
            " FROM proxy_call_sessions WHERE request_id = :r ORDER BY created_at, id"
        ),
        {"r": request["id"]},
    ).mappings()
    guard_rows = [notification_view(r, audience="guard") for r in rows]
    fallback = fallback_view(
        rows,
        mode=household.fallback_mode,
        started_at=None if current is None else current["started_at"],
        now=now,
        timings=timings,
        request_state=str(request["state"]),
    )
    options = (
        list(current["guard_options"])
        if current and request["state"] == "expired" and current["guard_options"]
        else []
    )
    if request["state"] == "expired" and not options:
        options = list(timings.guard_options)
    handoff = any(r["action"] == "talk_to_guard" for r in rows)
    return {
        "request_id": request["id"],
        "request_status": request["state"],
        "auto_allow_on_timeout": False,
        "cascade": None
        if current is None
        else {
            "attempt_no": current["attempt_no"],
            "state": current["state"],
            "started_at": current["started_at"],
            "expires_at": current["expires_at"],
            "ended_reason": current["ended_reason"],
            "steps": steps,
            "attempts": len(cascades),
        },
        "notifications": guard_rows,
        "summary": {
            "person_reached": fallback["person_reached"],
            "provider_accepted_only": sum(
                1
                for r in guard_rows
                if r["provider_accepted"] and not r["person_reached"] and r["state"] != "expired"
            ),
            "failed": sum(1 for r in guard_rows if r["failure_reason"]),
        },
        "calls": [
            {
                "id": c["id"],
                "purpose": c["purpose"],
                "state": c["state"],
                "dial_outcome": c["dial_outcome"],
                "duration_seconds": c["duration_seconds"],
                "ttl_expires_at": c["ttl_expires_at"],
                "who": c["masked_label"],
                "audio_recorded": bool(c["recording_enabled"]),
                "simulation": c["simulation"],
            }
            for c in calls
        ],
        "fallback": fallback,
        "guard_options": options,
        "talk_to_guard_requested": handoff,
        "server_time": now,
    }
