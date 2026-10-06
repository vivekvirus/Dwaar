"""Which engagements are authorised NOW, and what the edge publisher consumes.

REQ: STAFF-01 (separate engagements per household with valid hours; guards see only currently authorised destinations), STAFF-03 (ending one
engagement never touches another's), AT-12 (the edge policy input reflects the remaining engagements), INV-08 (staff entry is never restricted
for debt: nothing here looks at dues), INV-01.

Pure functions plus two reads. The schedule is evaluated in Asia/Kolkata. Nothing here grants entry: authorisation is a fact about the
household's engagement; an attendance event is an observation (STAFF-02).

``edge_staff_input`` is the function the edge publisher consumes (the edge module is not edited here): the same data-minimised shape the
policy manifest uses (opaque ids, no names, no phones), deterministic and sorted, with a digest so a publisher can see "changed".
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.timeutil import format_iso_utc, ist_date, to_ist, utc_now

DAY_CODES: Final = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _minutes(hhmm: str) -> int:
    hours, minutes = hhmm.split(":")
    return int(hours) * 60 + int(minutes)


def schedule_allows(schedule: Mapping[Any, Any], at: dt.datetime) -> bool:
    """Is ``at`` inside the valid hours (Asia/Kolkata) of the schedule ``{"days": [...], "from": "07:00", "to": "11:00"}``?"""
    local = to_ist(at)
    if DAY_CODES[local.weekday()] not in schedule.get("days", ()):
        return False
    minute = local.hour * 60 + local.minute
    return _minutes(str(schedule["from"])) <= minute < _minutes(str(schedule["to"]))


def effective_on(row: Mapping[Any, Any], day: dt.date) -> bool:
    if row["ended_at"] is not None:
        return False
    if row["effective_from"] > day:
        return False
    return row["effective_to"] is None or row["effective_to"] >= day


def authorised_now(row: Mapping[Any, Any], at: dt.datetime) -> bool:
    """Live, inside its dates and inside its valid hours. An engagement ended at or before ``at`` is never authorised."""
    if row["ended_at"] is not None and row["ended_at"] <= at:
        return False
    live = dict(row, ended_at=None)
    return effective_on(live, ist_date(at)) and schedule_allows(row["schedule"], at)


_ENGAGEMENT_COLS: Final = (
    "e.id, e.staff_id, e.unit_id, e.duty, e.schedule, e.effective_from, e.effective_to, e.ended_at, e.end_reason, e.version,"
    " e.created_at, u.label AS unit_label, b.name AS block_name"
)
_ENGAGEMENT_FROM: Final = (
    " FROM staff_engagements e JOIN units u ON u.society_id = e.society_id AND u.id = e.unit_id"
    " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
)


def authorised_engagements(
    conn: Connection,
    at: dt.datetime | None = None,
    *,
    staff_ids: Sequence[uuid.UUID] | None = None,
    unit_ids: Sequence[uuid.UUID] | None = None,
) -> list[dict[str, Any]]:
    """Engagements authorised at ``at`` (default now) for the given staff and/or units (RLS context decides the society)."""
    moment = at or utc_now()
    rows = (
        conn.execute(
            text(
                f"SELECT {_ENGAGEMENT_COLS}{_ENGAGEMENT_FROM} WHERE e.ended_at IS NULL"  # noqa: S608
                " AND e.effective_from <= :day AND (e.effective_to IS NULL OR e.effective_to >= :day)"
                " AND (CAST(:staff AS uuid[]) IS NULL OR e.staff_id = ANY(CAST(:staff AS uuid[])))"
                " AND (CAST(:units AS uuid[]) IS NULL OR e.unit_id = ANY(CAST(:units AS uuid[])))"
                " ORDER BY e.staff_id, e.unit_id, e.id"
            ),
            {
                "day": ist_date(moment),
                "staff": None if staff_ids is None else list(staff_ids),
                "units": None if unit_ids is None else list(unit_ids),
            },
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows if schedule_allows(r["schedule"], moment)]


def destination_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    """What a GUARD may see of an authorised engagement: the destination and the window, nothing about the household's arrangement."""
    return {
        "engagement_id": row["id"],
        "unit_id": row["unit_id"],
        "block_name": row["block_name"],
        "unit_label": row["unit_label"],
        "days": row["schedule"]["days"],
        "from": row["schedule"]["from"],
        "to": row["schedule"]["to"],
    }


def edge_staff_input(
    conn: Connection, now: dt.datetime | None = None, *, revoked_retention_days: int = 30
) -> dict[str, Any]:
    """The staff part of the edge policy input (AT-12): currently effective engagements (valid hours included) and recently ended ones.

    Opaque identifiers only. ``entries`` are what the gate may allow (inside the schedule); ``ended`` lets the edge drop a cached entry
    for exactly that engagement. Another employer's engagement of the same person appears in ``entries`` unchanged (STAFF-03).
    """
    moment = now or utc_now()
    day = ist_date(moment)
    live = conn.execute(
        text(
            "SELECT e.id, e.unit_id, e.schedule, e.effective_from, e.effective_to, s.staff_ref FROM staff_engagements e"
            " JOIN staff s ON s.society_id = e.society_id AND s.id = e.staff_id"
            " WHERE e.ended_at IS NULL AND s.status = 'active' AND e.effective_from <= :d"
            " AND (e.effective_to IS NULL OR e.effective_to >= :d) ORDER BY e.id"
        ),
        {"d": day},
    ).mappings()
    entries = [
        {
            "engagement_id": str(r["id"]),
            "staff_ref": r["staff_ref"],
            "unit_id": str(r["unit_id"]),
            "days": list(r["schedule"]["days"]),
            "from": r["schedule"]["from"],
            "to": r["schedule"]["to"],
            "effective_from": r["effective_from"].isoformat(),
            "effective_to": r["effective_to"].isoformat() if r["effective_to"] else None,
        }
        for r in live
    ]
    ended = [
        {"engagement_id": str(r[0]), "ended_at": format_iso_utc(r[1])}
        for r in conn.execute(
            text(
                "SELECT id, ended_at FROM staff_engagements WHERE ended_at IS NOT NULL AND ended_at > :h ORDER BY id"
            ),
            {"h": moment - dt.timedelta(days=revoked_retention_days)},
        )
    ]
    body = {"entries": entries, "ended": ended}
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {"generated_at": format_iso_utc(moment), "digest": f"sha256:{digest}", **body}
