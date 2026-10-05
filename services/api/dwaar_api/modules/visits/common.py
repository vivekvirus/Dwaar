"""Shared helpers: units, the household of a unit (who may decide), masking (GATE-13), visit views.

REQ: GATE-02 (destination: masked surname confirmation), GATE-13 (guards never see raw resident numbers, nor resident
identities beyond a masked surname hint), PRD 5.1/5.2 (the household that lives in a unit approves for it; FAMILY only when
delegated), INV-04 (a non-resident owner is not part of the household), INV-01.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound

from ..identity import store as identity_store

#: effective today (IST calendar day, like the identity access index): verified or disputed (a dispute never removes
#: occupancy, IAM-05), not ended, inside its dates.
_EFFECTIVE: Final = (
    "m.verification IN ('verified', 'disputed') AND m.ended_at IS NULL"
    " AND m.effective_from <= (now() AT TIME ZONE 'Asia/Kolkata')::date"
    " AND (m.effective_to IS NULL OR m.effective_to >= (now() AT TIME ZONE 'Asia/Kolkata')::date)"
)

VISIT_COLUMNS: Final = (
    "v.id, v.kind, v.state, v.visitor_alias, v.invitation_id, v.gate_id, v.people_count, v.vehicle_plate,"
    " v.expected_minutes, v.authorisation_source, v.authorised_at, v.authorised_until, v.entered_at, v.exited_at,"
    " v.exit_basis, v.exit_reconciled_at, v.confidence_inside, v.closed_reason, v.consent_recorded, v.created_at,"
    " v.version, EXISTS (SELECT 1 FROM access_events ae WHERE ae.society_id = v.society_id AND ae.visit_id = v.id"
    " AND ae.event_type = 'EntryObserved') AS entry_observed"
)

#: states in which a visit is "active" at the gate (what a guard may see)
ACTIVE_VISIT_STATES: Final = ("requested", "authorised", "inside")


# ------------------------------------------------------------------------------------------ units
def fetch_unit(conn: Connection, unit_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT u.id, u.label, u.status, u.block_id, b.name AS block_name FROM units u"
                " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id WHERE u.id = :id"
            ),
            {"id": unit_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def require_unit(conn: Connection, unit_id: uuid.UUID) -> dict[str, Any]:
    """The unit inside the caller's society (RLS), or 404: another society's unit is simply absent."""
    unit = fetch_unit(conn, unit_id)
    if unit is None or unit["status"] != "active":
        raise NotFound()
    return unit


# ------------------------------------------------------------------------------------------ household
@dataclass(frozen=True)
class Member:
    person_id: uuid.UUID
    kind: str
    role: str
    can_decide: bool


def _role_of(kind: str, lives: bool) -> str:
    if kind in ("owner", "joint_owner"):
        return "owner_occ" if lives else "owner_nr"
    return {"tenant": "tenant", "family": "family"}.get(kind, "staff")


def household(conn: Connection, unit_id: uuid.UUID) -> list[Member]:
    """Effective members of the unit and whether each may decide an approval request for it.

    The household that LIVES there decides: occupying owners and tenants always; a family member only when delegated
    (``is_primary_approver``). A non-resident owner and staff never decide (PRD 5.1/5.2, INV-04).
    """
    rows = conn.execute(
        text(
            "SELECT m.person_id, m.kind, m.lives_in_unit, m.is_primary_approver FROM memberships m"  # noqa: S608
            f" WHERE m.unit_id = :u AND {_EFFECTIVE} ORDER BY m.effective_from, m.created_at, m.id"
        ),
        {"u": unit_id},
    ).all()
    members: list[Member] = []
    for person_id, kind, lives, primary in rows:
        role = _role_of(str(kind), bool(lives))
        decides = (
            role in ("owner_occ", "tenant") or (role == "family" and bool(primary))
        ) and bool(lives)
        members.append(Member(person_id, str(kind), role, decides))
    return members


def deciders(conn: Connection, unit_id: uuid.UUID) -> list[Member]:
    return [m for m in household(conn, unit_id) if m.can_decide]


def member_standing(conn: Connection, person_id: uuid.UUID, unit_id: uuid.UUID) -> Member | None:
    """The caller's strongest standing in the household: a deciding membership if any, else any membership, else None."""
    mine = [m for m in household(conn, unit_id) if m.person_id == person_id]
    if not mine:
        return None
    deciding = [m for m in mine if m.can_decide]
    return deciding[0] if deciding else mine[0]


# ------------------------------------------------------------------------------------------ masking (GATE-13)
def mask_surname(display_name: str | None) -> str:
    """``Rekha Pawar`` -> ``P****``: the first letter of the family name and a fixed-length mask. A guard compares it
    with what the visitor says; it is a hint to confirm, not a way to read a name."""
    parts = (display_name or "").split()
    if not parts:
        return "?"
    surname = parts[-1]
    return surname[0].upper() + "*" * 4


def surname_hint(conn: Connection, unit_id: uuid.UUID) -> str | None:
    """Masked surname of the longest-standing deciding occupant of the unit, or None when nobody can decide."""
    people = deciders(conn, unit_id)
    if not people:
        return None
    names = identity_store.society_people(conn, [people[0].person_id])
    entry = names.get(people[0].person_id)
    return mask_surname(entry[0] if entry else None)


# ------------------------------------------------------------------------------------------ views
def fetch_stops(
    conn: Connection, visit_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not visit_ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT s.visit_id, s.id, s.unit_id, s.seq, s.authorised, s.state, s.approval_request_id,"
            " u.label AS unit_label, b.name AS block_name FROM visit_stops s"
            " JOIN units u ON u.society_id = s.society_id AND u.id = s.unit_id"
            " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
            " WHERE s.visit_id = ANY(:ids) ORDER BY s.visit_id, s.seq"
        ),
        {"ids": list(visit_ids)},
    ).mappings()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["visit_id"], []).append(
            {
                "id": r["id"],
                "unit_id": r["unit_id"],
                "block_name": r["block_name"],
                "unit_label": r["unit_label"],
                "seq": r["seq"],
                "authorised": r["authorised"],
                "state": r["state"],
                "approval_request_id": r["approval_request_id"],
            }
        )
    return out


def visit_view(
    row: Mapping[Any, Any],
    stops: Iterable[Mapping[Any, Any]],
    *,
    view: str,
    own_units: frozenset[uuid.UUID] | None = None,
) -> dict[str, Any]:
    """One visit for one audience.

    ``view`` is ``full`` (society roles, purpose logged), ``guard`` (masked: no invitation link, no consent detail) or
    ``household`` (the unit's own residents: only the stops of THEIR unit, never the other destinations of the visitor).
    The visitor contact token is never part of a view in any audience.
    """
    shown = [dict(s) for s in stops]
    if view == "household":
        shown = [s for s in shown if own_units is not None and s["unit_id"] in own_units]
    base: dict[str, Any] = {
        "id": row["id"],
        "kind": row["kind"],
        "state": row["state"],
        "visitor_alias": row["visitor_alias"],
        "gate_id": row["gate_id"],
        "people_count": row["people_count"],
        "vehicle_plate": row["vehicle_plate"],
        "expected_minutes": row["expected_minutes"],
        "authorisation_source": row["authorisation_source"],
        "authorised_at": row["authorised_at"],
        "authorised_until": row["authorised_until"],
        "entry_observed": bool(row["entry_observed"]),
        "entered_at": row["entered_at"],
        "exited_at": row["exited_at"],
        "exit_basis": row["exit_basis"],
        "exit_reconciled_at": row["exit_reconciled_at"],
        "inside_confidence": row["confidence_inside"],
        "closed_reason": row["closed_reason"],
        "stops": shown,
        "version": row["version"],
        "created_at": row["created_at"],
    }
    if view == "full":
        base["invitation_id"] = row["invitation_id"]
        base["consent_recorded"] = row["consent_recorded"]
    return base


def visit_views(
    conn: Connection,
    rows: Sequence[Mapping[Any, Any]],
    *,
    view: str,
    own_units: frozenset[uuid.UUID] | None = None,
) -> list[dict[str, Any]]:
    stops = fetch_stops(conn, [r["id"] for r in rows])
    return [visit_view(r, stops.get(r["id"], []), view=view, own_units=own_units) for r in rows]
