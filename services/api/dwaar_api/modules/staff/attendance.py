"""Attendance: check-in / check-out observations, appended corrections, and the read model (STAFF-02, STAFF-05).

REQ: STAFF-02 (attendance is an OBSERVATION: it never creates or removes permission; a correction is a NEW row with who, why and when; the
original is never edited), STAFF-05 (identified by CODE or CARD only; nothing here reads, stores or compares a face), STAFF-01 (a guard learns a
destination only if it is authorised right now), INV-08 (a person outside their hours is still recorded; nothing is withheld for debt), INV-07.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound, PolicyViolation
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ...core.pagination import DateRange, PageParams, Paginator, SortColumn
from ..identity.config import IdentityConfig
from . import authorisation
from .schemas import AttendanceCorrection, AttendanceCreate
from .service import credential_hash

_COLS: Final = (
    "a.id, a.staff_id, a.engagement_id, a.direction, a.credential_kind, a.device_id, a.seq, a.client_event_id, a.occurred_at,"
    " a.recorded_at, a.recorded_by, a.authorised_now, e.unit_id AS unit_id, s.display_name AS staff_name"
)
_LOOKUP_BASE: Final = (
    "SELECT s.id, s.display_name, s.staff_type, s.photo_ref, c.withdrawn_at, c.purposes FROM staff s"
    " JOIN staff_consents c ON c.society_id = s.society_id AND c.id = s.consent_id WHERE "
)
_LOOKUP_CODE: Final = _LOOKUP_BASE + "s.credential_code_hash = :h AND s.status = 'active'"
_LOOKUP_CARD: Final = _LOOKUP_BASE + "s.credential_card_hash = :h AND s.status = 'active'"
_FROM: Final = (
    " FROM attendance_events a JOIN staff s ON s.society_id = a.society_id AND s.id = a.staff_id"
    " LEFT JOIN staff_engagements e ON e.society_id = a.society_id AND e.id = a.engagement_id"
)


def _corrections_of(
    conn: Connection, ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT attendance_id, id, kind, new_occurred_at, new_direction, reason, corrected_by, corrector_role, at"
            " FROM attendance_corrections WHERE attendance_id = ANY(:ids) ORDER BY attendance_id, at, id"
        ),
        {"ids": list(ids)},
    ).mappings()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["attendance_id"], []).append(
            {k: v for k, v in r.items() if k != "attendance_id"}
        )
    return out


def attendance_view(
    row: Mapping[Any, Any], corrections: Sequence[Mapping[Any, Any]]
) -> dict[str, Any]:
    """The observation exactly as recorded PLUS the corrections appended to it, and the effective values they imply."""
    direction, occurred, voided = row["direction"], row["occurred_at"], False
    for c in corrections:
        if c["kind"] == "void":
            voided = True
        elif c["kind"] == "amend_time":
            occurred = c["new_occurred_at"]
        elif c["kind"] == "amend_direction":
            direction = c["new_direction"]
    return {
        "id": row["id"],
        "staff_id": row["staff_id"],
        "staff_name": row["staff_name"],
        "engagement_id": row["engagement_id"],
        "unit_id": row["unit_id"],
        "direction": row["direction"],
        "occurred_at": row["occurred_at"],
        "credential_kind": row["credential_kind"],
        "recorded_at": row["recorded_at"],
        "recorded_by": row["recorded_by"],
        "authorised_when_observed": row["authorised_now"],
        "corrections": [dict(c) for c in corrections],
        "effective": {"direction": direction, "occurred_at": occurred, "voided": voided},
    }


def _fetch(conn: Connection, attendance_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLS}{_FROM} WHERE a.id = :id"),  # noqa: S608
            {"id": attendance_id},
        )
        .mappings()
        .first()
    )
    return None if row is None else dict(row)


def record(
    conn: Connection,
    ctx: RequestContext,
    cfg: IdentityConfig,
    body: AttendanceCreate,
    *,
    now: dt.datetime,
) -> dict[str, Any]:
    """A check-in or out by code or card. A credential that matches nobody is the same 404 as any unknown thing."""
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    digest = credential_hash(cfg, ctx.society_id, body.credential.kind, body.credential.value)
    lookup = _LOOKUP_CODE if body.credential.kind == "code" else _LOOKUP_CARD
    staff = conn.execute(text(lookup), {"h": digest}).mappings().first()
    if staff is None:
        raise NotFound()
    if staff["withdrawn_at"] is not None or "attendance" not in staff["purposes"]:
        raise PolicyViolation(details={"reason": "consent_withdrawn"})
    prior = conn.execute(
        text("SELECT id FROM attendance_events WHERE client_event_id = :c"),
        {"c": body.client_event_id},
    ).first()
    if prior is not None:
        existing = _fetch(conn, prior[0])
        assert existing is not None  # noqa: S101
        if existing["staff_id"] != staff["id"]:
            raise PolicyViolation(details={"reason": "client_event_id_in_use"})
        return _guard_result(conn, staff, existing, now=existing["occurred_at"], replayed=True)
    at = body.occurred_at or now
    live = authorisation.authorised_engagements(conn, at, staff_ids=[staff["id"]])
    chosen: dict[str, Any] | None = None
    ambiguous = False
    if body.unit_id is not None:
        chosen = next((a for a in live if a["unit_id"] == body.unit_id), None)
    elif len(live) == 1:
        chosen = live[0]
    elif len(live) > 1:
        ambiguous = True
    attendance_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO attendance_events (id, society_id, staff_id, engagement_id, direction, credential_kind, device_id, seq,"
                " client_event_id, occurred_at, recorded_by, authorised_now) VALUES (:id, :s, :staff, :eng, :dir, :kind, :dev, :seq,"
                " :cid, :at, :by, :auth)"
            ),
            {
                "id": attendance_id, "s": ctx.society_id, "staff": staff["id"], "eng": chosen["id"] if chosen else None,
                "dir": body.direction, "kind": body.credential.kind, "dev": body.device_id, "seq": body.seq,
                "cid": body.client_event_id, "at": at, "by": ctx.person_id, "auth": chosen is not None,
            },
        )  # fmt: skip
        return MutationResult(
            attendance_id, 1,
            after={"direction": body.direction, "authorised_now": chosen is not None, "credential_kind": body.credential.kind},
            event_payload={
                "attendance_id": attendance_id, "staff_id": staff["id"], "engagement_id": chosen["id"] if chosen else None,
                "direction": body.direction, "authorised_now": chosen is not None,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.attendance_record", object_type="attendance_event",
        event_type="StaffAttendanceObserved", apply=apply,
    )  # fmt: skip
    fresh = _fetch(conn, attendance_id)
    assert fresh is not None  # noqa: S101
    return _guard_result(conn, staff, fresh, now=at, replayed=False, ambiguous=ambiguous)


def _guard_result(
    conn: Connection, staff: Mapping[Any, Any], event: Mapping[Any, Any], *, now: dt.datetime, replayed: bool,
    ambiguous: bool = False,
) -> dict[str, Any]:  # fmt: skip
    """What the guard gets back: the observation, and (only when authorised right now) who it is and where they may go."""
    out: dict[str, Any] = {
        "id": event["id"],
        "recorded": True,
        "replayed": replayed,
        "direction": event["direction"],
        "occurred_at": event["occurred_at"],
        "authorised_now": bool(event["authorised_now"]),
        "ambiguous_destination": ambiguous,
        "note": "an attendance record is an observation; it does not grant or remove entry",
    }
    if event["authorised_now"] or ambiguous:
        destinations = authorisation.authorised_engagements(conn, now, staff_ids=[staff["id"]])
        out["staff"] = {
            "id": staff["id"], "display_name": staff["display_name"], "staff_type": staff["staff_type"],
            "photo_ref": staff["photo_ref"],
        }  # fmt: skip
        out["authorised_destinations"] = [authorisation.destination_view(d) for d in destinations]
    return out


def list_attendance(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    scope: Scope,
    window: DateRange,
    staff_id: uuid.UUID | None,
    unit_id: uuid.UUID | None,
) -> dict[str, Any]:
    where = ["a.occurred_at >= :from_", "a.occurred_at < :to_"]
    params: dict[str, Any] = {"from_": window.start, "to_": window.end}
    filters: dict[str, Any] = {"from": window.start, "to": window.end, "wide": scope.society_wide}
    if unit_id is not None:
        if not scope.covers_unit(unit_id):
            raise NotFound()
        where.append("e.unit_id = :unit")
        params["unit"] = unit_id
        filters["unit_id"] = unit_id
    elif not scope.society_wide:
        units = sorted(scope.unit_ids, key=lambda u: u.int)
        where.append("e.unit_id = ANY(:units)")
        params["units"] = units
        filters["units"] = ",".join(str(u) for u in units)
    if staff_id is not None:
        where.append("a.staff_id = :staff")
        params["staff"] = staff_id
        filters["staff_id"] = staff_id
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_COLS}{_FROM}",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("a.occurred_at", "timestamptz", nullable=False),
            SortColumn("a.id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    corrections = _corrections_of(conn, [r["id"] for r in result.items])
    return {
        "items": [attendance_view(r, corrections.get(r["id"], ())) for r in result.items],
        "next_cursor": result.next_cursor,
    }


def correct(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    attendance_id: uuid.UUID,
    body: AttendanceCorrection,
) -> dict[str, Any]:
    """APPEND a correction (who, why, when). The observation is never edited; a voided event takes no further correction."""
    row = _fetch(conn, attendance_id)
    if row is None:
        raise NotFound()
    unit = row["unit_id"]
    if not (scope.society_wide or (unit is not None and scope.covers_unit(unit))):
        raise NotFound()
    existing = _corrections_of(conn, [attendance_id]).get(attendance_id, [])
    if any(c["kind"] == "void" for c in existing):
        raise PolicyViolation(details={"reason": "already_voided"})
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    correction_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO attendance_corrections (id, society_id, attendance_id, kind, new_occurred_at, new_direction, reason,"
                " corrected_by, corrector_role) VALUES (:id, :s, :a, :kind, :t, :d, :why, :by, :role)"
            ),
            {
                "id": correction_id, "s": ctx.society_id, "a": attendance_id, "kind": body.kind, "t": body.new_occurred_at,
                "d": body.new_direction, "why": body.reason, "by": ctx.person_id, "role": ctx.actor_role or "unknown",
            },
        )  # fmt: skip
        return MutationResult(
            correction_id, 1,
            before={"direction": row["direction"], "occurred_at": row["occurred_at"]},
            after={"kind": body.kind, "new_direction": body.new_direction, "new_occurred_at": body.new_occurred_at},
            event_payload={"correction_id": correction_id, "attendance_id": attendance_id, "kind": body.kind},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.attendance_correct", object_type="attendance_correction",
        event_type="StaffAttendanceCorrected", apply=apply, reason=body.reason,
    )  # fmt: skip
    return attendance_view(row, _corrections_of(conn, [attendance_id]).get(attendance_id, []))
