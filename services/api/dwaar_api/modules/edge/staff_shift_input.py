"""What the policy publisher takes from the staff and shifts modules (the only place the edge module reads either).

REQ: STAFF-01 / STAFF-03 / AT-12 (a domestic worker with three employers keeps the other two engagements in the next snapshot when one ends: the
manifest carries one entry per ENGAGEMENT, never one per person), STAFF-02 (an attendance record is an observation: nothing here reads attendance),
Appendix C (a supervisor override expires at the end of its shift: the manifest carries its ``valid_until`` so the gateway never has to trust the
publish cadence), EDGE-04 (data minimisation: opaque ids and local valid hours only: no name, no phone, no ID number, no photo), INV-08 (nothing in
this file can lock a gate: an override only ADDS a way in for a supervisor, a missing staff entry sends the person to guard-assisted verification),
INV-01 (everything runs under the society's RLS context).

``staff.authorisation.edge_staff_input`` and ``shifts.service.active_override`` are the two functions the slice 4 modules published for this purpose; the
publisher calls them as they are and only reshapes the result into the signed manifest contract (``generated_at`` and ``digest`` are dropped: the
manifest is hashed as a whole and must not depend on the clock).

FAILURE ISOLATION: an error while reading STAFF propagates (the publish fails, the previous snapshot keeps serving, the worker records the society as
failed): publishing a snapshot with the wrong staff list would silently grant or deny entry. An error while reading OVERRIDES is isolated by a savepoint
and logged: the snapshot is published without overrides, which is the stricter reading, and a shift module fault can never stop policy publication.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Connection

from dwaar_common.timeutil import format_iso_utc

from ..shifts import service as shift_service
from ..staff import authorisation as staff_authorisation

log = logging.getLogger("dwaar_api.edge.staff_shift_input")


def staff_section(
    conn: Connection, now: dt.datetime, retention_days: int
) -> dict[str, list[dict[str, Any]]]:
    """``{"entries": [...], "ended": [...]}``: live engagements with their valid hours, and engagements ended within the retention window.

    Entries are sorted by engagement id (the input is), so the manifest is deterministic."""
    raw = staff_authorisation.edge_staff_input(conn, now, revoked_retention_days=retention_days)
    entries = [
        {
            "engagement_id": e["engagement_id"],
            "staff_ref": e["staff_ref"],
            "unit_id": e["unit_id"],
            "days": list(e["days"]),
            "from_local": e["from"],
            "to_local": e["to"],
            "effective_from": e["effective_from"],
            "effective_to": e["effective_to"],
        }
        for e in raw["entries"]
    ]
    ended = [{"engagement_id": e["engagement_id"], "ended_at": e["ended_at"]} for e in raw["ended"]]
    return {"entries": entries, "ended": ended}


def override_section(
    conn: Connection, gate_ids: Sequence[uuid.UUID | str], now: dt.datetime
) -> list[dict[str, Any]]:
    """The supervisor override in force at each active gate right now (at most one per gate), sorted by gate id."""
    found: list[dict[str, Any]] = []
    try:
        with conn.begin_nested():
            for gate_id in sorted(str(g) for g in gate_ids):
                row = shift_service.active_override(conn, uuid.UUID(gate_id), now)
                if row is not None:
                    found.append(
                        {
                            "override_id": str(row["id"]),
                            "gate_id": gate_id,
                            "valid_until": format_iso_utc(row["valid_until"]),
                        }
                    )
    except Exception as exc:  # a shift module fault must never stop policy publication (INV-08); the stricter reading is published
        log.warning("override section skipped", extra={"exc_type": type(exc).__name__})
        return []
    return found
