"""Helpdesk configuration: SLA targets, business calendar, windows, emergency procedures (OPS-01, OPS-04, OPS-09, INV-10).

REQ: OPS-01, OPS-04 (feedback window 48 h and reopen window 7 days are DEFAULTS of configuration), OPS-09 (the society's own
emergency-procedure record per hazard), INV-10 (configuration, not code), PRD 9.7 pilot defaults, ARCH-01.

The settings row is created lazily with the PILOT DEFAULTS (``sla_source = 'pilot_default'``) through an audited mutation.
A change affects tickets submitted AFTER it: a ticket's due instants are computed once, at submission or at an approved
priority change, and are never silently rewritten by a configuration change.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from dwaar_common.errors import NotFound, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from .schemas import EmergencyProcedureIn, SettingsIn
from .sla import PILOT_SLA, BusinessCalendar, validate_sla

_COLS: Final = (
    "id, timezone, working_days, opens_at, closes_at, holidays, sla, sla_source, feedback_window_hours,"
    " reopen_window_days, duplicate_similarity, version, updated_at"
)


@dataclass(frozen=True)
class Settings:
    id: uuid.UUID
    calendar: BusinessCalendar
    timezone: str
    sla: dict[str, Any]
    sla_source: str
    feedback_window_hours: int
    reopen_window_days: int
    duplicate_similarity: float
    version: int
    updated_at: dt.datetime

    @classmethod
    def from_row(cls, row: Any) -> Settings:
        cal = BusinessCalendar.build(
            row["timezone"], row["working_days"], row["opens_at"], row["closes_at"], row["holidays"]
        )
        return cls(
            row["id"], cal, row["timezone"], dict(row["sla"]), row["sla_source"],
            int(row["feedback_window_hours"]), int(row["reopen_window_days"]),
            float(row["duplicate_similarity"]), int(row["version"]), row["updated_at"],
        )  # fmt: skip

    def view(self) -> dict[str, Any]:
        return {
            "timezone": self.timezone,
            "working_days": sorted(self.calendar.working_days),
            "opens_at": self.calendar.opens.isoformat(timespec="minutes"),
            "closes_at": self.calendar.closes.isoformat(timespec="minutes"),
            "holidays": sorted(d.isoformat() for d in self.calendar.holidays),
            "sla": self.sla,
            "sla_source": self.sla_source,
            "feedback_window_hours": self.feedback_window_hours,
            "reopen_window_days": self.reopen_window_days,
            "duplicate_similarity": f"{self.duplicate_similarity:.2f}",
            "version": self.version,
            "updated_at": self.updated_at,
        }


def _select(conn: Connection) -> Any:
    return conn.execute(text(f"SELECT {_COLS} FROM helpdesk_settings")).mappings().first()  # noqa: S608


def ensure_settings(conn: Connection, ctx: RequestContext) -> Settings:
    """The society's settings; the first call creates them from the pilot defaults (audited)."""
    row = _select(conn)
    if row is None:
        assert ctx.society_id is not None  # noqa: S101
        new_id = uuid7()

        def apply(c: Connection) -> MutationResult:
            c.execute(
                text(
                    "INSERT INTO helpdesk_settings (id, society_id, sla, updated_by)"
                    " VALUES (:id, :s, CAST(:sla AS jsonb), :by)"
                ),
                {
                    "id": new_id,
                    "s": ctx.society_id,
                    "sla": json.dumps(PILOT_SLA),
                    "by": ctx.person_id,
                },
            )
            return MutationResult(
                new_id, 1, after={"sla_source": "pilot_default"},
                event_payload={"settings_id": new_id, "sla_source": "pilot_default"},
            )  # fmt: skip

        with contextlib.suppress(IntegrityError):  # a concurrent request created it first
            mutation(
                conn, ctx, operation="helpdesk.settings.initialise", object_type="helpdesk_settings",
                event_type="HelpdeskSettingsInitialised", apply=apply,
            )  # fmt: skip
        row = _select(conn)
    assert row is not None  # noqa: S101
    return Settings.from_row(row)


def update_settings(conn: Connection, ctx: RequestContext, body: SettingsIn) -> dict[str, Any]:
    current = ensure_settings(conn, ctx)
    if body.expected_version is not None and body.expected_version != current.version:
        raise StaleVersion()
    sla = validate_sla(body.sla)
    BusinessCalendar.build(  # validates the timezone and the window
        body.timezone, body.working_days, body.opens_at, body.closes_at, body.holidays
    )
    now = utc_now()

    def apply(c: Connection) -> MutationResult:
        n = c.execute(
            text(
                "UPDATE helpdesk_settings SET timezone = :tz, working_days = :wd, opens_at = :o, closes_at = :c,"
                " holidays = :h, sla = CAST(:sla AS jsonb), sla_source = 'society_configured',"
                " feedback_window_hours = :f, reopen_window_days = :r, duplicate_similarity = :d,"
                " version = version + 1, updated_by = :by, updated_at = :now WHERE id = :id AND version = :v"
            ),
            {
                "tz": body.timezone, "wd": sorted(set(body.working_days)), "o": body.opens_at, "c": body.closes_at,
                "h": sorted(set(body.holidays)), "sla": json.dumps(sla), "f": body.feedback_window_hours,
                "r": body.reopen_window_days, "d": round(body.duplicate_similarity, 2), "by": ctx.person_id,
                "now": now, "id": current.id, "v": current.version,
            },
        )  # fmt: skip
        if n.rowcount != 1:
            raise StaleVersion()
        return MutationResult(
            current.id, current.version + 1,
            before={"feedback_window_hours": current.feedback_window_hours, "reopen_window_days": current.reopen_window_days,
                    "sla_source": current.sla_source},
            after={"feedback_window_hours": body.feedback_window_hours, "reopen_window_days": body.reopen_window_days,
                   "sla_source": "society_configured"},
            event_payload={"settings_id": current.id, "sla_source": "society_configured"},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="helpdesk.settings.update", object_type="helpdesk_settings",
        event_type="HelpdeskSettingsChanged", apply=apply,
    )  # fmt: skip
    return ensure_settings(conn, ctx).view()


# ------------------------------------------------------------------------------------------ emergency procedures
def _procedure_view(row: Any) -> dict[str, Any]:
    return {
        "hazard": row["hazard"],
        "headline": row["headline"],
        "steps": row["steps"],
        "contacts": row["contacts"],
        "qualified_contractor": row["qualified_contractor"],
        "version": row["version"],
        "updated_at": row["updated_at"],
        "configured": True,
    }


def list_procedures(conn: Connection) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT hazard, headline, steps, contacts, qualified_contractor, version, updated_at"
            " FROM emergency_procedures ORDER BY hazard"
        )
    ).mappings()
    return {r["hazard"]: _procedure_view(r) for r in rows}


def procedure_for(
    conn: Connection, hazard: str, procedures: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    """What OPS-09 shows IMMEDIATELY: the hazard's procedure, else the society's general one, else an explicit "not configured".

    Never repair instructions: the platform authors no steps; the society's own text is shown as written."""
    found = procedures if procedures is not None else list_procedures(conn)
    chosen = found.get(hazard) or found.get("general")
    base: dict[str, Any]
    if chosen is None:
        base = {
            "hazard": hazard, "configured": False, "headline": None, "steps": None, "contacts": [],
            "qualified_contractor": None, "version": None,
        }  # fmt: skip
    else:
        base = dict(chosen)
        base["hazard"] = hazard
    base["message_keys"] = [
        "ops.emergency.follow_site_procedure"
        if base["configured"]
        else "ops.emergency.not_configured",
        "ops.emergency.no_rescue_guarantee",
        "ops.emergency.do_not_attempt_repair",
        "ops.emergency.qualified_contractor_only",
    ]
    return base


def put_procedure(
    conn: Connection, ctx: RequestContext, hazard: str, body: EmergencyProcedureIn
) -> dict[str, Any]:
    assert ctx.society_id is not None  # noqa: S101
    existing = (
        conn.execute(
            text("SELECT id, version FROM emergency_procedures WHERE hazard = :h"), {"h": hazard}
        )
        .mappings()
        .first()
    )
    if existing is None and body.expected_version not in (None, 0):
        raise StaleVersion()
    if existing is not None and body.expected_version not in (None, existing["version"]):
        raise StaleVersion()
    contacts = json.dumps([c.model_dump() for c in body.contacts])
    now = utc_now()
    new_id = existing["id"] if existing else uuid7()

    def apply(c: Connection) -> MutationResult:
        if existing is None:
            c.execute(
                text(
                    "INSERT INTO emergency_procedures (id, society_id, hazard, headline, steps, contacts,"
                    " qualified_contractor, updated_by, updated_at) VALUES (:id, :s, :h, :hl, :st,"
                    " CAST(:ct AS jsonb), :qc, :by, :now)"
                ),
                {"id": new_id, "s": ctx.society_id, "h": hazard, "hl": body.headline, "st": body.steps,
                 "ct": contacts, "qc": body.qualified_contractor, "by": ctx.person_id, "now": now},
            )  # fmt: skip
            version = 1
        else:
            n = c.execute(
                text(
                    "UPDATE emergency_procedures SET headline = :hl, steps = :st, contacts = CAST(:ct AS jsonb),"
                    " qualified_contractor = :qc, version = version + 1, updated_by = :by, updated_at = :now"
                    " WHERE id = :id AND version = :v"
                ),
                {"hl": body.headline, "st": body.steps, "ct": contacts, "qc": body.qualified_contractor,
                 "by": ctx.person_id, "now": now, "id": new_id, "v": existing["version"]},
            )  # fmt: skip
            if n.rowcount != 1:
                raise StaleVersion()
            version = int(existing["version"]) + 1
        return MutationResult(
            new_id, version, after={"hazard": hazard, "contacts_count": len(body.contacts)},
            event_payload={"hazard": hazard, "procedure_id": new_id},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="helpdesk.emergency_procedure.put", object_type="emergency_procedure",
        event_type="EmergencyProcedureChanged", apply=apply,
    )  # fmt: skip
    found = list_procedures(conn).get(hazard)
    if found is None:
        raise NotFound()
    return found
