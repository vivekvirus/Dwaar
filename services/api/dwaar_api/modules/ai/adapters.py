"""The real ticket and shift modules behind the AI ports (AI-F01 triage, AI-G08 shift handover).

REQ: INV-06 (AI proposes, deterministic services execute: a model's suggestion changes nothing until a person confirms the proposal, and then the helpdesk
and shift services apply it under THEIR rules), AI-F01 (category, priority and team suggestions for tickets; duplicates are only ever hints), AI-G08 +
SHIFT-02 (the handover summary is an advisory draft shown ABOVE the deterministic open-items list, which is always present and never replaced),
INV-01 (every read is made as the CALLER: their society, role and scope; the gateway then re-checks each returned item), INV-03/INV-08 (nothing here can
touch a gate, a device, a visit or an entry decision).

Sources read through ``app.state.db`` in their own short read transaction with the caller's RLS context. Command ports run INSIDE the confirmation
transaction (``conn``/``ctx`` are the caller's), so the module's own audit and outbox rows commit with the proposal's confirmation.

NOT built here (a missing port answers 503 and leaves the proposal open, exactly as before): ``ticket.create`` (AI-R02) and ``notice.create_draft``
(AI-C01 keeps the author's private draft until the notices port exists).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_ai_gateway.types import Caller, SourceDoc
from dwaar_common.errors import DwaarError, PolicyViolation
from dwaar_common.ids import uuid7

from ...core.db import Database, RequestContext
from ..helpdesk import service as ticket_service
from ..helpdesk import views as ticket_views
from ..helpdesk.permissions import READERS
from ..helpdesk.schemas import TriageIn
from ..shifts import service as shift_service
from .ports import AiRuntime

log = logging.getLogger("dwaar_api.ai.adapters")

#: the gateway's triage vocabulary -> the helpdesk's (the helpdesk keeps its own, richer, category list)
CATEGORY_MAP: Final = {"housekeeping": "cleaning"}
#: the gateway's four-step priority -> the helpdesk's (PRD 9.7: emergency / urgent / normal / low)
PRIORITY_MAP: Final = {"low": "low", "normal": "normal", "high": "urgent", "emergency": "emergency"}
#: kinds of open item that stay in a handover whatever a summary says (the gateway keeps every critical unresolved item)
CRITICAL_KINDS: Final = frozenset({"incident_unresolved", "override_active"})
_MARK: Final = "[ai:{key}]"


def _context(caller: Caller) -> RequestContext:
    return RequestContext(caller.society_id, caller.person_id, caller.role, uuid7())


# ====================================================================================== AI-F01: tickets as the caller sees them
class HelpdeskTicketSource:
    """``TicketSource`` over the helpdesk: only tickets the caller's audience rules show in full (a manager of the society), never a private
    household's ticket to anyone else, never a draft of somebody else, never a support-privacy ticket unless the caller may read it."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def tickets(self, caller: Caller, ticket_ids: Sequence[str]) -> Sequence[SourceDoc]:
        wanted: list[uuid.UUID] = []
        for raw in ticket_ids:
            try:
                wanted.append(uuid.UUID(raw))
            except ValueError:
                continue  # not an id: it simply is not a ticket of this society
        if not wanted:
            return ()
        actor = ticket_views.Actor(
            caller.person_id, caller.role, caller.society_wide, caller.unit_ids
        )
        docs: list[SourceDoc] = []
        with self._db.app_tx(_context(caller)) as conn:
            blocks = ticket_views.my_blocks(conn, actor)
            for tid in wanted:
                row = ticket_service.fetch_ticket(conn, tid)
                if row is None or ticket_views.audience(row, actor, blocks) != "manager":
                    continue
                docs.append(
                    SourceDoc(
                        source_id=str(row["id"]), society_id=caller.society_id, kind="ticket",
                        text=f"{row['title']}. {row['description']}".strip(), unit_id=row["unit_id"],
                        visible_to_roles=frozenset(READERS),
                        status="archived" if row["state"] in {"closed", "cancelled"} else "published",
                        version=int(row["version"]),
                        meta={"category": row["category"], "state": row["state"], "created_at": str(row["created_at"])},
                    )
                )  # fmt: skip
        return docs


class TicketTriagePort:
    """``ticket.apply_triage``: category and priority of each CONFIRMED suggestion go through ``helpdesk.service.triage`` (the same rules, SLA clocks,
    history, audit and outbox as the staff screen). Team and duplicate hints are recorded in the triage note and applied by nobody: a merge is a
    manager's own decision (OPS-02). An emergency suggestion is NEVER applied from here (it stays flagged for separate human review); lowering an urgent
    ticket is refused by the helpdesk itself. A ticket that cannot be triaged is reported as skipped, the others are still applied."""

    def execute(
        self, conn: Connection, ctx: RequestContext, payload: Mapping[str, Any], *, proposal_id: uuid.UUID, external_key: str
    ) -> Mapping[str, Any]:  # fmt: skip
        if ctx.person_id is None or ctx.actor_role is None:
            raise PolicyViolation(details={"reason": "no_acting_person"})
        actor = ticket_views.Actor(ctx.person_id, ctx.actor_role, True, frozenset())
        marker = _MARK.format(key=external_key)
        versions = payload.get("ticket_versions", {})
        applied: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for r in payload.get("results", []):
            tid = uuid.UUID(str(r["ticket_id"]))
            done = conn.execute(
                text(
                    "SELECT 1 FROM ticket_events WHERE ticket_id = :t AND kind = 'triaged' AND note LIKE :m"
                ),
                {"t": tid, "m": f"%{marker}%"},
            ).first()
            if done is not None:  # a retry of the same confirmation: already applied
                skipped.append({"ticket_id": str(tid), "reason": "already_applied"})
                continue
            category = CATEGORY_MAP.get(str(r["category"]), str(r["category"]))
            priority = PRIORITY_MAP.get(str(r["priority"]))
            hints = [f"team suggested: {r.get('team')}"]
            if r.get("duplicate_of"):
                hints.append(f"possible duplicate of ticket {r['duplicate_of']} (not merged)")
            note = f"AI-F01 suggestion confirmed by a person; {'; '.join(hints)}. {marker}"
            holding_back = None
            if priority == "emergency":
                priority, holding_back = None, "emergency_requires_separate_human_review"
            try:
                body = TriageIn(
                    category=category, priority=priority, note=note,
                    expected_version=int(versions[str(tid)]) if str(tid) in versions else None,
                )  # fmt: skip
                with conn.begin_nested():
                    out = ticket_service.triage(conn, ctx, actor, tid, body)
            except DwaarError as exc:  # one ticket's refusal (state, version, approver rule) must not undo the others
                skipped.append({"ticket_id": str(tid), "reason": getattr(exc, "code", "refused")})
                continue
            item = {
                "ticket_id": str(tid),
                "category": category,
                "priority": priority,
                "state": out["ticket"]["state"] if "ticket" in out else None,
            }
            if holding_back:
                item["held_back"] = holding_back
            applied.append(item)
        return {"applied": applied, "skipped": skipped, "merged": 0, "team_applied": False}


# ====================================================================================== AI-G08: the shift's deterministic open items
class ShiftEventSource:
    """``ShiftSource`` over the shifts module: the handover's OPEN ITEMS (deterministic, from the database; the same list a guard reads), or the live
    list for a shift still on duty. No free text is invented: each item is a short machine statement. Critical items (unresolved incident, an
    override still in force) are marked so that the gateway keeps them in the summary whatever the model writes."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def events(self, caller: Caller, shift_id: str) -> Sequence[SourceDoc]:
        try:
            sid = uuid.UUID(shift_id)
        except ValueError:
            return ()
        with self._db.app_tx(_context(caller)) as conn:
            shift = (
                conn.execute(
                    text("SELECT id, gate_id, state FROM shifts WHERE id = :i"), {"i": sid}
                )
                .mappings()
                .first()
            )
            if shift is None:
                return ()
            handover = conn.execute(
                text("SELECT open_items FROM shift_handovers WHERE outgoing_shift_id = :i"),
                {"i": sid},
            ).first()
            items = (
                list(handover[0])
                if handover is not None
                else shift_service.open_items(conn, shift["gate_id"])["items"]
            )
        return [
            SourceDoc(
                source_id=str(it["ref_id"]), society_id=caller.society_id, kind="shift_event",
                text=f"{it['kind']}: {it['what']}" + (f" ({it['detail']})" if it.get("detail") else ""),
                version=1, meta={"kind": it["kind"], "critical": it["kind"] in CRITICAL_KINDS, "resolved": False},
            )
            for it in items
        ]  # fmt: skip


class ShiftHandoverPort:
    """``shift.save_handover``: the supervisor-confirmed narrative becomes the ADVISORY summary of the handover of that shift
    (``shifts.service.attach_summary``). It is shown above the deterministic open-items list and cannot change, hide or replace it. A shift that has
    not ended has no handover yet: the proposal stays open (409-style refusal), nothing is invented."""

    def execute(
        self, conn: Connection, ctx: RequestContext, payload: Mapping[str, Any], *, proposal_id: uuid.UUID, external_key: str
    ) -> Mapping[str, Any]:  # fmt: skip
        try:
            sid = uuid.UUID(str(payload.get("shift_id")))
        except ValueError:
            raise PolicyViolation(details={"reason": "unknown_shift"}) from None
        row = conn.execute(
            text("SELECT id, summary_text FROM shift_handovers WHERE outgoing_shift_id = :i"),
            {"i": sid},
        ).first()
        if row is None:
            raise PolicyViolation(details={"reason": "handover_not_created_yet"})
        narrative = str(payload.get("narrative", "")).strip()
        if not narrative:
            raise PolicyViolation(details={"reason": "empty_summary"})
        if row[1] != narrative[:4000]:  # the same confirmation retried writes nothing twice
            shift_service.attach_summary(conn, ctx, row[0], narrative, source="ai_gateway")
        return {
            "handover_id": str(row[0]),
            "summary_attached": True,
            "open_items_unchanged": True,
            "pending_critical_items": len(payload.get("pending_critical_items", [])),
        }


def install(runtime: AiRuntime, db: Database) -> None:
    """Register the real sources and ports on the runtime (the simulator or Anthropic provider is the gateway's own business, not decided here)."""
    runtime.sources.setdefault("AI-F01", HelpdeskTicketSource(db))
    runtime.sources.setdefault("AI-G08", ShiftEventSource(db))
    runtime.ports.setdefault("ticket_triage", TicketTriagePort())
    runtime.ports.setdefault("shift_handover", ShiftHandoverPort())
    log.info("ai ports installed: ticket triage and shift handover")


__all__ = [
    "HelpdeskTicketSource",
    "ShiftEventSource",
    "ShiftHandoverPort",
    "TicketTriagePort",
    "install",
]
