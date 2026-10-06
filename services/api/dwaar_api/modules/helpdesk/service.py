"""Ticket service: state machine, SLA clocks, priority history, duplicates, merge, closure. Every write is a ``mutation``.

REQ: OPS-01 (states, acknowledgement and resolution clocks, pause reason and approver, immutable pause and priority history,
changing priority cannot erase a breach), OPS-02 (scopes, duplicate PROPOSALS, merge never exposes private content), OPS-03
(the standard form works without AI; a draft is confirmed before submit), OPS-04 (closure by confirmation or after the feedback
window; reopen keeps the ORIGINAL clocks and history), OPS-09 (hazard rules, procedure shown at once, contractor routing),
UX-07, INV-06, INV-07 (submitted, triaged, assigned, resolved, closed are distinct, separately recorded facts).

Concurrency: each mutation locks the ticket row (``FOR UPDATE``) and updates with ``WHERE version = :v``; the optional
``expected_version`` of a request turns a stale client into 409 ``stale_version``. Event rows and outbox rows are written
through ``core.audit.mutation`` (one aggregate version = one outbox event). Ticket TEXT never goes into an audit diff or an
event payload: ids, scope, category, priority and state only.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, emit_event, mutation
from ...core.db import RequestContext
from ..identity import store as identity_store
from . import duplicates, hazards, sla
from . import settings as settings_mod
from .schemas import (
    AssignIn,
    MergeIn,
    Note,
    PriorityIn,
    ReasonIn,
    SupportRequestCreate,
    TicketCreate,
    TransitionIn,
    TriageIn,
)
from .views import Actor, my_blocks

OPEN_STATES: Final = frozenset(
    {"submitted", "triaged", "assigned", "in_progress", "awaiting_material", "awaiting_resident"}
)
CANCELLABLE: Final = OPEN_STATES | {"draft"}
#: manager-driven moves (OPS-01). Entering/leaving awaiting_* starts/stops the resolution clock.
TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "assigned": frozenset({"in_progress"}),
    "in_progress": frozenset({"awaiting_material", "awaiting_resident", "resolved"}),
    "awaiting_material": frozenset({"in_progress", "resolved"}),
    "awaiting_resident": frozenset({"in_progress", "resolved"}),
}
PAUSING: Final = frozenset({"awaiting_material", "awaiting_resident"})
_AUDIT_FIELDS: Final = (
    "state", "priority", "category", "assignee_id", "routing", "sla_ack_by", "sla_fix_by", "ack_at",
    "parent_ticket_id", "closed_basis", "reopen_count", "hazard_kind",
)  # fmt: skip
_UPDATABLE: Final = frozenset(
    {
        "category", "priority", "state", "assignee_id", "contractor_name", "routing", "beyond_staff_competence",
        "hazard_kind", "hazard_rule", "sla_started_at", "sla_ack_by", "sla_fix_by", "ack_at", "ack_by",
        "sla_paused_since", "submitted_at", "resolved_at", "feedback_due_at", "closed_at", "closed_basis",
        "reopen_count", "reopened_at", "parent_ticket_id", "merged_at", "photo_refs",
    }
)  # fmt: skip
TICKET_SELECT: Final = (
    "SELECT t.id, t.ticket_no, t.unit_id, t.block_id, t.scope, t.category, t.priority, t.state, t.title, t.description,"
    " t.photo_refs, t.raised_by, t.raised_channel, t.assignee_id, t.contractor_name, t.routing, t.beyond_staff_competence,"
    " t.hazard_kind, t.hazard_rule, t.sla_started_at, t.sla_ack_by, t.sla_fix_by, t.ack_at, t.ack_by, t.sla_paused_since,"
    " t.submitted_at, t.resolved_at, t.feedback_due_at, t.closed_at, t.closed_basis, t.reopen_count, t.reopened_at,"
    " t.parent_ticket_id, t.merged_at, t.version, t.created_at, t.updated_at,"
    " COALESCE((SELECT array_agg(b.clock ORDER BY b.clock) FROM ticket_sla_breaches b WHERE b.ticket_id = t.id),"
    " ARRAY[]::text[]) AS breaches FROM tickets t"
)


# ------------------------------------------------------------------------------------------ reads
def fetch_ticket(
    conn: Connection, ticket_id: uuid.UUID, *, lock: bool = False
) -> dict[str, Any] | None:
    # FOR UPDATE cannot combine with the aggregate sub-select's GROUP BY semantics; lock the row first, then read.
    if lock:
        got = conn.execute(
            text("SELECT id FROM tickets WHERE id = :id FOR UPDATE"), {"id": ticket_id}
        ).first()
        if got is None:
            return None
    row = (
        conn.execute(text(f"{TICKET_SELECT} WHERE t.id = :id"), {"id": ticket_id})
        .mappings()
        .first()
    )  # noqa: S608
    return dict(row) if row else None


def ticket_ref(t: dict[str, Any]) -> duplicates.TicketRef:
    return duplicates.TicketRef(
        t["id"],
        t["scope"],
        t["unit_id"],
        t["block_id"],
        t["category"],
        f"{t['title']} {t['description']}",
    )


def events_of(conn: Connection, ticket_id: uuid.UUID, *, status_only: bool) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT seq, kind, from_state, to_state, actor_role, note, at FROM ticket_events"
            " WHERE ticket_id = :id ORDER BY seq"
        ),
        {"id": ticket_id},
    ).mappings()
    if status_only:  # common-area audience: the status trail only, no notes, no roles
        return [
            {"seq": r["seq"], "kind": r["kind"], "to_state": r["to_state"], "at": r["at"]}
            for r in rows
            if r["kind"] in {"submitted", "triaged", "assigned", "state_changed", "resolved", "closed", "reopened", "cancelled", "merged"}
        ]  # fmt: skip
    return [dict(r) for r in rows]


def sla_history(conn: Connection, ticket_id: uuid.UUID) -> dict[str, Any]:
    prio = conn.execute(
        text(
            "SELECT seq, priority, previous_priority, set_by, set_role, approver_id, rule, reason, ack_due_at, fix_due_at, at"
            " FROM ticket_priority_history WHERE ticket_id = :id ORDER BY seq"
        ),
        {"id": ticket_id},
    ).mappings()
    log = conn.execute(
        text(
            "SELECT seq, kind, reason, actor_id, approver_id, fix_due_before, fix_due_after, at FROM ticket_sla_log"
            " WHERE ticket_id = :id ORDER BY seq"
        ),
        {"id": ticket_id},
    ).mappings()
    breaches = conn.execute(
        text(
            "SELECT clock, due_at, priority_at_breach, basis, recorded_at FROM ticket_sla_breaches"
            " WHERE ticket_id = :id ORDER BY recorded_at, clock"
        ),
        {"id": ticket_id},
    ).mappings()
    return {
        "priority_history": [dict(r) for r in prio],
        "pause_log": [dict(r) for r in log],
        "breaches": [dict(r) for r in breaches],
    }


# ------------------------------------------------------------------------------------------ internals
def _lock(conn: Connection, ticket_id: uuid.UUID, expected_version: int | None) -> dict[str, Any]:
    t = fetch_ticket(conn, ticket_id, lock=True)
    if t is None:
        raise NotFound()
    if expected_version is not None and t["version"] != expected_version:
        raise StaleVersion()
    return t


def _update(conn: Connection, t: dict[str, Any], changes: dict[str, Any], now: dt.datetime) -> int:
    bad = set(changes) - _UPDATABLE
    if bad:
        raise ValueError(f"not an updatable ticket column: {sorted(bad)}")
    sets = "".join(f"{c} = :{c}, " for c in changes)
    sql = f"UPDATE tickets SET {sets}version = version + 1, updated_at = :_now WHERE id = :_id AND version = :_v"  # noqa: S608
    result = conn.execute(text(sql), {**changes, "_now": now, "_id": t["id"], "_v": t["version"]})
    if result.rowcount != 1:
        raise StaleVersion()
    return int(t["version"]) + 1


def _event(
    conn: Connection, ctx: RequestContext, ticket_id: uuid.UUID, kind: str, now: dt.datetime, *,
    from_state: str | None = None, to_state: str | None = None, note: str | None = None,
    data: dict[str, Any] | None = None,
) -> None:  # fmt: skip
    import json

    conn.execute(
        text(
            "INSERT INTO ticket_events (society_id, ticket_id, seq, kind, from_state, to_state, actor_id, actor_role,"
            " note, data, at) VALUES (:s, :t, (SELECT coalesce(max(seq), 0) + 1 FROM ticket_events WHERE ticket_id = :t),"
            " :k, :f, :to, :a, :r, :n, CAST(:d AS jsonb), :at)"
        ),
        {
            "s": ctx.society_id, "t": ticket_id, "k": kind, "f": from_state, "to": to_state, "a": ctx.person_id,
            "r": ctx.actor_role or "system", "n": note, "d": json.dumps(data or {}), "at": now,
        },
    )  # fmt: skip


def _payload(
    t: dict[str, Any],
    *,
    to_state: str,
    from_state: str | None,
    priority: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Minimal outbox payload for the notifications module: ids and state, never ticket text or names."""
    prio = priority or t["priority"]
    return {
        "ticket_id": t["id"], "ticket_no": t["ticket_no"], "scope": t["scope"], "unit_id": t["unit_id"],
        "block_id": t["block_id"], "category": t["category"], "priority": prio, "from_state": from_state,
        "to_state": to_state, "emergency": prio == "emergency", "hazard_kind": t["hazard_kind"], **extra,
    }  # fmt: skip


def _breach(
    conn: Connection, ctx: RequestContext, t: dict[str, Any], clock: str, due: dt.datetime, priority: str,
    basis: str, now: dt.datetime,
) -> bool:  # fmt: skip
    """Record a breach once per (ticket, clock). Never updated, never deleted, whatever happens to the priority later."""
    n = conn.execute(
        text(
            "INSERT INTO ticket_sla_breaches (society_id, ticket_id, clock, due_at, priority_at_breach, basis,"
            " recorded_by, recorded_at) VALUES (:s, :t, :c, :d, :p, :b, :by, :now)"
            " ON CONFLICT (society_id, ticket_id, clock) DO NOTHING"
        ),
        {"s": ctx.society_id, "t": t["id"], "c": clock, "d": due, "p": priority, "b": basis, "by": ctx.person_id, "now": now},
    ).rowcount  # fmt: skip
    if n:
        _event(
            conn,
            ctx,
            t["id"],
            "sla_breached",
            now,
            data={"clock": clock, "due_at": due.isoformat()},
        )
    return bool(n)


def _check_breaches(
    conn: Connection, ctx: RequestContext, t: dict[str, Any], now: dt.datetime, basis: str
) -> list[str]:
    """Record the breaches that exist RIGHT NOW against the ticket's current targets (call BEFORE changing priority or clocks)."""
    found: list[str] = []
    if t["state"] in {"draft", "cancelled"} or t["sla_started_at"] is None:
        return found
    if (
        t["ack_at"] is None
        and t["sla_ack_by"] <= now
        and _breach(conn, ctx, t, "acknowledgement", t["sla_ack_by"], t["priority"], basis, now)
    ):
        found.append("acknowledgement")
    live = t["state"] not in {"resolved", "closed"} and t["sla_paused_since"] is None
    if (
        live
        and t["sla_fix_by"] <= now
        and _breach(conn, ctx, t, "resolution", t["sla_fix_by"], t["priority"], basis, now)
    ):
        found.append("resolution")
    return found


def _priority_row(
    conn: Connection, ctx: RequestContext, ticket_id: uuid.UUID, priority: str, previous: str | None, rule: str,
    reason: str | None, approver: uuid.UUID | None, ack_due: dt.datetime | None, fix_due: dt.datetime | None,
    now: dt.datetime,
) -> None:  # fmt: skip
    conn.execute(
        text(
            "INSERT INTO ticket_priority_history (society_id, ticket_id, seq, priority, previous_priority, set_by, set_role,"
            " approver_id, rule, reason, ack_due_at, fix_due_at, at) VALUES (:s, :t,"
            " (SELECT coalesce(max(seq), 0) + 1 FROM ticket_priority_history WHERE ticket_id = :t), :p, :pp, :by, :role,"
            " :ap, :rule, :reason, :ad, :fd, :at)"
        ),
        {
            "s": ctx.society_id, "t": ticket_id, "p": priority, "pp": previous, "by": ctx.person_id,
            "role": ctx.actor_role or "system", "ap": approver, "rule": rule, "reason": reason, "ad": ack_due,
            "fd": fix_due, "at": now,
        },
    )  # fmt: skip


def _clock_targets(
    cfg: settings_mod.Settings, priority: str, now: dt.datetime
) -> tuple[dt.datetime, dt.datetime]:
    ack_by, fix_by, _a, _f = sla.targets_for(cfg.sla, priority, now, cfg.calendar)
    return ack_by, fix_by


def _start_clock(
    conn: Connection, ctx: RequestContext, cfg: settings_mod.Settings, t_id: uuid.UUID, priority: str,
    now: dt.datetime, rule: str,
) -> tuple[dt.datetime, dt.datetime]:  # fmt: skip
    """Targets for a ticket that exists already, plus its FIRST priority-history row."""
    ack_by, fix_by = _clock_targets(cfg, priority, now)
    _priority_row(conn, ctx, t_id, priority, None, rule, None, None, ack_by, fix_by, now)
    return ack_by, fix_by


def _ack(
    conn: Connection,
    ctx: RequestContext,
    t: dict[str, Any],
    now: dt.datetime,
    changes: dict[str, Any],
) -> None:
    """Acknowledge implicitly: the first manager response stops the acknowledgement clock (late is recorded, never hidden)."""
    if t["ack_at"] is None and t["state"] != "draft":
        changes["ack_at"] = now
        changes["ack_by"] = ctx.person_id
        if t["sla_ack_by"] is not None and now > t["sla_ack_by"]:
            _breach(
                conn, ctx, t, "acknowledgement", t["sla_ack_by"], t["priority"], "met_late", now
            )


def _pause_pairs(conn: Connection, ticket_id: uuid.UUID) -> list[tuple[dt.datetime, dt.datetime]]:
    rows = conn.execute(
        text("SELECT kind, at FROM ticket_sla_log WHERE ticket_id = :id ORDER BY seq"),
        {"id": ticket_id},
    ).all()
    pairs: list[tuple[dt.datetime, dt.datetime]] = []
    start: dt.datetime | None = None
    for kind, at in rows:
        if kind == "pause":
            start = at
        elif start is not None:
            pairs.append((start, at))
            start = None
    return pairs


def _log_pause(
    conn: Connection, ctx: RequestContext, t_id: uuid.UUID, kind: str, reason: str, approver: uuid.UUID | None,
    now: dt.datetime, before: dt.datetime | None = None, after: dt.datetime | None = None,
) -> None:  # fmt: skip
    conn.execute(
        text(
            "INSERT INTO ticket_sla_log (society_id, ticket_id, seq, kind, reason, actor_id, approver_id, fix_due_before,"
            " fix_due_after, at) VALUES (:s, :t, (SELECT coalesce(max(seq), 0) + 1 FROM ticket_sla_log WHERE ticket_id = :t),"
            " :k, :r, :a, :ap, :b, :af, :at)"
        ),
        {
            "s": ctx.society_id, "t": t_id, "k": kind, "r": reason, "a": ctx.person_id, "ap": approver, "b": before,
            "af": after, "at": now,
        },
    )  # fmt: skip


def _resume(
    conn: Connection, ctx: RequestContext, cfg: settings_mod.Settings, t: dict[str, Any], now: dt.datetime,
    changes: dict[str, Any],
) -> None:  # fmt: skip
    """Restart the resolution clock: the due instant moves by the time it was stopped (recorded, immutable)."""
    paused_since = t["sla_paused_since"]
    if paused_since is None:
        return
    fix_target = sla.parse_target(cfg.sla[t["priority"]]["fix"], "sla.fix")
    new_fix = sla.extend_for_pause(t["sla_fix_by"], fix_target, cfg.calendar, paused_since, now)
    _log_pause(conn, ctx, t["id"], "resume", t["state"], None, now, t["sla_fix_by"], new_fix)
    changes["sla_fix_by"] = new_fix
    changes["sla_paused_since"] = None


def _simple_result(
    t: dict[str, Any], changes: dict[str, Any], new_version: int, payload: dict[str, Any]
) -> MutationResult:
    keys = [k for k in _AUDIT_FIELDS if k in changes]
    return MutationResult(
        t["id"], new_version,
        before={k: t[k] for k in keys}, after={k: changes[k] for k in keys}, event_payload=payload,
    )  # fmt: skip


@dataclass
class Plan:
    changes: dict[str, Any] = field(default_factory=dict)
    to_state: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


def _mutate(
    conn: Connection, ctx: RequestContext, ticket_id: uuid.UUID, *, expected_version: int | None, operation: str,
    event_type: str, plan: Callable[[Connection, dict[str, Any], dt.datetime], Plan], now: dt.datetime | None = None,
    reason: str | None = None, approver_id: uuid.UUID | None = None,
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    t = _lock(conn, ticket_id, expected_version)

    def apply(c: Connection) -> MutationResult:
        p = plan(c, t, moment)
        new_version = _update(c, t, p.changes, moment)
        after = {**t, **p.changes}
        payload = _payload(
            after, to_state=p.to_state or t["state"], from_state=t["state"],
            priority=p.changes.get("priority"), **p.payload,
        )  # fmt: skip
        return _simple_result(t, p.changes, new_version, payload)

    mutation(
        conn, ctx, operation=operation, object_type="ticket", event_type=event_type, apply=apply, reason=reason,
        approver_id=approver_id,
    )  # fmt: skip
    fresh = fetch_ticket(conn, ticket_id)
    assert fresh is not None  # noqa: S101
    return fresh


def _require_manager(actor: Actor) -> None:
    if not actor.is_manager:
        raise NotFound()


def _can_act(t: dict[str, Any], actor: Actor) -> bool:
    """Raiser, or the household of a PRIVATE ticket (never a non-resident owner), or a manager."""
    if actor.is_manager:
        return True
    if t["raised_by"] == actor.person_id:
        return True
    return t["scope"] == "private" and t["unit_id"] in actor.unit_ids and actor.role != "owner_nr"


def _validated_person(conn: Connection, person_id: uuid.UUID, field_name: str) -> None:
    """The person must have a relationship in this society (the SQL surface answers for the context society only)."""
    if person_id not in identity_store.society_people(conn, [person_id]):
        raise InvalidSchema.for_fields([(field_name, "unknown_person")])


# ------------------------------------------------------------------------------------------ create / submit
def _resolve_scope(conn: Connection, actor: Actor, body_scope: str, unit_id: uuid.UUID | None, block_id: uuid.UUID | None
                   ) -> tuple[uuid.UUID | None, uuid.UUID | None]:  # fmt: skip
    if body_scope == "private":
        if unit_id is None or block_id is not None:
            raise InvalidSchema.for_fields([("unit_id", "required_for_private")])
        if not actor.society_wide and unit_id not in actor.unit_ids:
            raise NotFound()
        if conn.execute(text("SELECT 1 FROM units WHERE id = :u"), {"u": unit_id}).first() is None:
            raise NotFound()
        return unit_id, None
    if body_scope == "block":
        if block_id is None or unit_id is not None:
            raise InvalidSchema.for_fields([("block_id", "required_for_block")])
        if not actor.society_wide and block_id not in my_blocks(conn, actor):
            raise NotFound()
        if (
            conn.execute(text("SELECT 1 FROM blocks WHERE id = :b"), {"b": block_id}).first()
            is None
        ):
            raise NotFound()
        return None, block_id
    if unit_id is not None or block_id is not None:
        raise InvalidSchema.for_fields([("scope", "society_scope_takes_no_unit_or_block")])
    return None, None


def _alert_event(
    conn: Connection,
    ctx: RequestContext,
    cfg: settings_mod.Settings,
    t: dict[str, Any],
    hazard: hazards.HazardMatch | None,
    priority: str,
) -> None:
    """Immediate alert for notifications (OPS-01 emergency): its own aggregate so the ticket's version sequence stays clean."""
    if priority != "emergency":
        return
    emit_event(
        conn, ctx, aggregate_type="ticket_alert", aggregate_id=t["id"], aggregate_version=int(t["version"]),
        event_type="TicketEmergencyAlert",
        payload=_payload(
            t, to_state=t["state"], from_state=None, priority="emergency",
            ack_target_seconds=sla.parse_target(cfg.sla["emergency"]["ack"], "sla.emergency.ack").seconds(cfg.calendar),
            hazard_rule=hazard.rule if hazard else None,
        ),
    )  # fmt: skip


def create_ticket(
    conn: Connection, ctx: RequestContext, actor: Actor, body: TicketCreate, *, channel: str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    """OPS-03 standard form. Returns {'ticket': row, 'hazard': match|None, 'duplicates': [...], 'procedure': {...}|None}."""
    moment = now or utc_now()
    cfg = settings_mod.ensure_settings(conn, ctx)
    if body.priority is not None and not actor.is_manager:
        raise InvalidSchema.for_fields([("priority", "managers_only")])
    unit_id, block_id = _resolve_scope(conn, actor, body.scope, body.unit_id, body.block_id)
    return _insert_ticket(
        conn, ctx, actor, cfg, scope=body.scope, unit_id=unit_id, block_id=block_id, category=body.category,
        title=body.title, description=body.description, photo_refs=body.photo_refs,
        unsafe=body.unsafe_observation, wanted_priority=body.priority, submit=body.submit,
        channel=channel or ("manager" if actor.is_manager else "guard" if actor.role == "guard" else "form"),
        moment=moment,
    )  # fmt: skip


def _insert_ticket(
    conn: Connection, ctx: RequestContext, actor: Actor, cfg: settings_mod.Settings, *, scope: str,
    unit_id: uuid.UUID | None, block_id: uuid.UUID | None, category: str, title: str, description: str,
    photo_refs: list[str], unsafe: bool, wanted_priority: str | None, submit: bool, channel: str, moment: dt.datetime,
) -> dict[str, Any]:  # fmt: skip
    hazard = hazards.detect(category, f"{title}\n{description}", unsafe_declared=unsafe)
    priority = wanted_priority or "normal"
    if (
        hazard is not None
        and sla.PRIORITY_RANK[priority] > sla.PRIORITY_RANK[hazard.minimum_priority]
    ):
        priority = hazard.minimum_priority
    submit_now = submit or priority == "emergency"  # an unsafe observation is never left as a draft
    ticket_id = uuid7()
    state = "submitted" if submit_now else "draft"

    def apply(c: Connection) -> MutationResult:
        ticket_no = c.execute(
            text(
                "UPDATE helpdesk_settings SET next_ticket_no = next_ticket_no + 1 WHERE society_id = :s"
                " RETURNING next_ticket_no - 1"
            ),
            {"s": ctx.society_id},
        ).scalar_one()
        row: dict[str, Any] = {
            "id": ticket_id, "s": ctx.society_id, "no": ticket_no, "unit": unit_id, "block": block_id, "scope": scope,
            "cat": category, "prio": priority, "state": state, "title": title, "desc": description,
            "photos": photo_refs, "by": ctx.person_id, "chan": channel,
            "routing": "qualified_contractor" if hazard else "staff", "hk": hazard.kind if hazard else None,
            "hr": hazard.rule if hazard else None, "submitted": moment if submit_now else None,
        }  # fmt: skip
        ack_by = fix_by = None
        if submit_now:
            ack_by, fix_by = _clock_targets(cfg, priority, moment)
        c.execute(
            text(
                "INSERT INTO tickets (id, society_id, ticket_no, unit_id, block_id, scope, category, priority, state, title,"
                " description, photo_refs, raised_by, raised_channel, routing, hazard_kind, hazard_rule, submitted_at,"
                " sla_started_at, sla_ack_by, sla_fix_by, created_at, updated_at) VALUES (:id, :s, :no, :unit, :block,"
                " :scope, :cat, :prio, :state, :title, :desc, :photos, :by, :chan, :routing, :hk, :hr, :submitted,"
                " :started, :ack, :fix, :now, :now)"
            ),
            {
                **row,
                "started": moment if submit_now else None,
                "ack": ack_by,
                "fix": fix_by,
                "now": moment,
            },
        )
        _event(c, ctx, ticket_id, "created", moment, to_state="draft" if not submit_now else None)
        if submit_now:
            _priority_row(c, ctx, ticket_id, priority, None, "hazard_rule" if hazard else "initial", None, None,
                          ack_by, fix_by, moment)  # fmt: skip
            _event(c, ctx, ticket_id, "submitted", moment, to_state="submitted",
                   data={"hazard": hazard.kind if hazard else None})  # fmt: skip
        snapshot = {
            "id": ticket_id, "ticket_no": ticket_no, "scope": scope, "unit_id": unit_id, "block_id": block_id,
            "category": category, "priority": priority, "hazard_kind": hazard.kind if hazard else None,
        }  # fmt: skip
        return MutationResult(
            ticket_id, 1, after={"state": state, "category": category, "priority": priority, "hazard_kind": snapshot["hazard_kind"]},
            event_payload=_payload(
                {**snapshot, "state": state}, to_state=state, from_state=None, channel=channel,
            ),
        )  # fmt: skip

    mutation(
        conn, ctx, operation="ticket.submit_new" if submit_now else "ticket.draft",
        object_type="ticket", event_type="TicketSubmitted" if submit_now else "TicketDrafted", apply=apply,
    )  # fmt: skip
    ticket = fetch_ticket(conn, ticket_id)
    assert ticket is not None  # noqa: S101
    if submit_now:
        _alert_event(conn, ctx, cfg, ticket, hazard, priority)
    proposals = _duplicates_for(conn, ctx, cfg, ticket) if submit_now else []
    procedure = None
    if hazard is not None:
        procedure = settings_mod.procedure_for(conn, hazard.kind)
    return {"ticket": ticket, "hazard": hazard, "duplicates": proposals, "procedure": procedure}


def _duplicates_for(
    conn: Connection, ctx: RequestContext, cfg: settings_mod.Settings, ticket: dict[str, Any]
) -> list[dict[str, Any]]:
    if ticket["category"] == "support_privacy":
        return []
    found = duplicates.propose(conn, ticket_ref(ticket), threshold=cfg.duplicate_similarity)
    assert ctx.society_id is not None  # noqa: S101
    return duplicates.store_proposals(conn, ctx.society_id, ticket["id"], found)


def duplicate_proposals(conn: Connection, ticket_id: uuid.UUID) -> list[dict[str, Any]]:
    """Stored proposals for a ticket, re-joined to the CURRENT same-audience tickets only (safe fields)."""
    rows = conn.execute(
        text(
            "SELECT l.id AS link_id, l.state AS link_state, l.similarity, l.method, o.id, o.ticket_no, o.title, o.state, o.scope"
            " FROM ticket_links l JOIN tickets o ON o.id = l.linked_ticket_id JOIN tickets me ON me.id = l.ticket_id"
            " WHERE l.ticket_id = :id AND o.scope = me.scope AND o.unit_id IS NOT DISTINCT FROM me.unit_id"
            " AND o.block_id IS NOT DISTINCT FROM me.block_id AND o.category <> 'support_privacy'"
            " ORDER BY l.similarity DESC NULLS LAST, o.id"
        ),
        {"id": ticket_id},
    ).mappings()
    return [
        {**dict(r), "similarity": None if r["similarity"] is None else str(r["similarity"])}
        for r in rows
    ]


def create_support_request(
    conn: Connection, ctx: RequestContext, actor: Actor, unit_id: uuid.UUID, body: SupportRequestCreate,
    now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    """UX-07: always a private, household-level ticket of category ``support_privacy`` submitted at once."""
    cfg = settings_mod.ensure_settings(conn, ctx)
    return _insert_ticket(
        conn, ctx, actor, cfg, scope="private", unit_id=unit_id, block_id=None, category="support_privacy",
        title=body.title, description=body.description, photo_refs=[], unsafe=False, wanted_priority=None,
        submit=True, channel="support", moment=now or utc_now(),
    )  # fmt: skip


def submit_ticket(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: Note, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    cfg = settings_mod.ensure_settings(conn, ctx)

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if t["raised_by"] != actor.person_id:
            raise NotFound()
        if t["state"] != "draft":
            raise StaleVersion(
                "The ticket is already submitted.", details={"reason": "not_a_draft"}
            )
        ack_by, fix_by = _start_clock(
            c,
            ctx,
            cfg,
            t["id"],
            t["priority"],
            moment,
            "hazard_rule" if t["hazard_kind"] else "initial",
        )
        _event(
            c,
            ctx,
            t["id"],
            "submitted",
            moment,
            from_state="draft",
            to_state="submitted",
            note=body.note,
        )
        return Plan(
            {"state": "submitted", "submitted_at": moment, "sla_started_at": moment, "sla_ack_by": ack_by, "sla_fix_by": fix_by},
            "submitted",
        )  # fmt: skip

    t = _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.submit",
        event_type="TicketSubmitted", plan=plan, now=now,
    )  # fmt: skip
    if t["priority"] == "emergency":
        _alert_event(conn, ctx, cfg, t, None, "emergency")
    return t


# ------------------------------------------------------------------------------------------ manager actions
def acknowledge(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: Note, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    _require_manager(actor)
    current = fetch_ticket(conn, ticket_id)
    if current is None:
        raise NotFound()
    if (
        current["ack_at"] is not None
    ):  # already acknowledged: naturally idempotent, nothing is written
        return current

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if t["state"] in {"draft", "cancelled"}:
            raise StaleVersion(
                "This ticket cannot be acknowledged.", details={"reason": "invalid_state"}
            )
        changes: dict[str, Any] = {}
        _ack(c, ctx, t, moment, changes)
        _event(c, ctx, t["id"], "acknowledged", moment, note=body.note)
        return Plan(changes)

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.acknowledge",
        event_type="TicketAcknowledged", plan=plan, now=now,
    )  # fmt: skip


def triage(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: TriageIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    _require_manager(actor)
    cfg = settings_mod.ensure_settings(conn, ctx)

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if t["state"] not in {"submitted", "triaged"}:
            raise StaleVersion(
                "The ticket cannot be triaged in this state.", details={"reason": "invalid_state"}
            )
        changes: dict[str, Any] = {}
        _check_breaches(c, ctx, t, moment, "before_change")
        if body.category is not None and body.category != t["category"]:
            changes["category"] = body.category
        if body.beyond_staff_competence is not None:
            changes["beyond_staff_competence"] = body.beyond_staff_competence
            if body.beyond_staff_competence:
                changes["routing"] = "qualified_contractor"
        if body.priority is not None and body.priority != t["priority"]:
            if sla.PRIORITY_RANK[body.priority] > sla.PRIORITY_RANK[t["priority"]] and t[
                "priority"
            ] in {"emergency", "urgent"}:
                raise PolicyViolation(
                    "Lowering an urgent or emergency priority needs the priority endpoint with an approver.",
                    details={"reason": "approver_required"},
                )
            changes.update(
                _reprioritise(c, ctx, cfg, t, body.priority, "triage", body.note, None, moment)
            )
        _ack(c, ctx, t, moment, changes)
        changes["state"] = "triaged"
        _event(
            c,
            ctx,
            t["id"],
            "triaged",
            moment,
            from_state=t["state"],
            to_state="triaged",
            note=body.note,
        )
        return Plan(changes, "triaged")

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.triage", event_type="TicketTriaged",
        plan=plan, now=now,
    )  # fmt: skip


def assign(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: AssignIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    _require_manager(actor)
    if (body.assignee_id is None) == (body.contractor_name is None):
        raise InvalidSchema.for_fields([("assignee_id", "exactly_one_of_assignee_or_contractor")])
    if body.assignee_id is not None:
        _validated_person(conn, body.assignee_id, "assignee_id")

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if t["state"] not in {
            "submitted",
            "triaged",
            "assigned",
            "in_progress",
            "awaiting_material",
            "awaiting_resident",
        }:
            raise StaleVersion(
                "The ticket cannot be assigned in this state.", details={"reason": "invalid_state"}
            )
        needs_contractor = (
            bool(t["hazard_kind"])
            or t["beyond_staff_competence"]
            or t["routing"] == "qualified_contractor"
        )
        if needs_contractor and body.contractor_name is None:
            # OPS-09: hazardous or beyond-competence work goes to a qualified contractor, not to in-house staff
            raise PolicyViolation(
                "This work must be routed to a qualified contractor.",
                details={"reason": "contractor_required"},
            )
        changes: dict[str, Any] = {
            "assignee_id": body.assignee_id,
            "contractor_name": body.contractor_name,
            "routing": "qualified_contractor" if body.contractor_name else "staff",
        }
        _ack(c, ctx, t, moment, changes)
        if t["state"] in {"submitted", "triaged"}:
            changes["state"] = "assigned"
        _event(c, ctx, t["id"], "assigned", moment, from_state=t["state"], to_state=changes.get("state", t["state"]),
               note=body.note, data={"routing": changes["routing"]})  # fmt: skip
        return Plan(changes, changes.get("state"), {"routing": changes["routing"]})

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.assign", event_type="TicketAssigned",
        plan=plan, now=now,
    )  # fmt: skip


def transition(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: TransitionIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    _require_manager(actor)
    cfg = settings_mod.ensure_settings(conn, ctx)
    approver = body.approver_id or actor.person_id
    if body.approver_id is not None and body.to in PAUSING:
        _validated_person(conn, body.approver_id, "approver_id")

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if body.to not in TRANSITIONS.get(t["state"], frozenset()):
            raise StaleVersion(
                "That move is not allowed from the current state.",
                details={"reason": "invalid_transition", "from": t["state"], "to": body.to},
            )
        changes: dict[str, Any] = {"state": body.to}
        _ack(c, ctx, t, moment, changes)
        if body.to in PAUSING:
            _check_breaches(c, ctx, t, moment, "before_change")
            _log_pause(c, ctx, t["id"], "pause", body.to, approver, moment)
            changes["sla_paused_since"] = moment
            _event(c, ctx, t["id"], "paused", moment, from_state=t["state"], to_state=body.to, note=body.note,
                   data={"reason": body.to})  # fmt: skip
        else:
            if t["state"] in PAUSING:
                _resume(c, ctx, cfg, {**t, "state": t["state"]}, moment, changes)
                _event(
                    c,
                    ctx,
                    t["id"],
                    "resumed",
                    moment,
                    from_state=t["state"],
                    to_state=body.to,
                    note=body.note,
                )
            if body.to == "resolved":
                live_fix = changes.get("sla_fix_by", t["sla_fix_by"])
                if moment > live_fix:
                    _breach(c, ctx, t, "resolution", live_fix, t["priority"], "met_late", moment)
                changes["resolved_at"] = moment
                changes["feedback_due_at"] = moment + dt.timedelta(hours=cfg.feedback_window_hours)
                _event(
                    c,
                    ctx,
                    t["id"],
                    "resolved",
                    moment,
                    from_state=t["state"],
                    to_state="resolved",
                    note=body.note,
                )
            elif t["state"] not in PAUSING:
                _event(
                    c,
                    ctx,
                    t["id"],
                    "state_changed",
                    moment,
                    from_state=t["state"],
                    to_state=body.to,
                    note=body.note,
                )
        return Plan(changes, body.to)

    event = {
        "resolved": "TicketResolved", "in_progress": "TicketStateChanged",
        "awaiting_material": "TicketStateChanged", "awaiting_resident": "TicketStateChanged",
    }[body.to]  # fmt: skip
    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation=f"ticket.{body.to}", event_type=event,
        plan=plan, now=now, approver_id=approver if body.to in PAUSING else None,
    )  # fmt: skip


def _reprioritise(
    conn: Connection, ctx: RequestContext, cfg: settings_mod.Settings, t: dict[str, Any], new_priority: str, rule: str,
    reason: str | None, approver: uuid.UUID | None, moment: dt.datetime,
) -> dict[str, Any]:  # fmt: skip
    """New targets counted from the ORIGINAL clock start, minus nothing: completed pauses are added back. The history row is
    appended; earlier rows and every recorded breach stay as they are."""
    ack_by, fix_by, _a, fix_target = sla.targets_for(
        cfg.sla, new_priority, t["sla_started_at"], cfg.calendar
    )
    for start, end in _pause_pairs(conn, t["id"]):
        fix_by = sla.extend_for_pause(fix_by, fix_target, cfg.calendar, start, end)
    _priority_row(
        conn,
        ctx,
        t["id"],
        new_priority,
        t["priority"],
        rule,
        reason,
        approver,
        ack_by,
        fix_by,
        moment,
    )
    return {"priority": new_priority, "sla_ack_by": ack_by, "sla_fix_by": fix_by}


def change_priority(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: PriorityIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """OPS-01: lowering an emergency or urgent priority needs a DIFFERENT approver; the approver is recorded. A breach that
    already happened is recorded first and survives the change."""
    _require_manager(actor)
    cfg = settings_mod.ensure_settings(conn, ctx)
    if body.approver_id is not None:
        _validated_person(conn, body.approver_id, "approver_id")

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if t["state"] in {"draft", "closed", "cancelled"} or t["sla_started_at"] is None:
            raise StaleVersion(
                "The priority cannot be changed in this state.", details={"reason": "invalid_state"}
            )
        if body.priority == t["priority"]:
            raise InvalidSchema.for_fields([("priority", "unchanged")])
        lowering = sla.PRIORITY_RANK[body.priority] > sla.PRIORITY_RANK[t["priority"]]
        if (
            lowering
            and t["priority"] in {"emergency", "urgent"}
            and (body.approver_id is None or body.approver_id == actor.person_id)
        ):
            raise PolicyViolation(
                "Lowering an urgent or emergency priority needs approval by another person.",
                details={"reason": "approver_required"},
            )
        _check_breaches(c, ctx, t, moment, "before_change")
        changes = _reprioritise(
            c, ctx, cfg, t, body.priority, "manual", body.reason, body.approver_id, moment
        )
        _check_breaches(c, ctx, {**t, **changes}, moment, "sweep")
        _event(c, ctx, t["id"], "priority_changed", moment, note=body.reason,
               data={"from": t["priority"], "to": body.priority, "approver": str(body.approver_id) if body.approver_id else None})  # fmt: skip
        return Plan(changes, None, {"previous_priority": t["priority"]})

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.priority_change",
        event_type="TicketPriorityChanged", plan=plan, now=now, reason=body.reason, approver_id=body.approver_id,
    )  # fmt: skip


# ------------------------------------------------------------------------------------------ resident / household actions
def respond(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: Note, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    cfg = settings_mod.ensure_settings(conn, ctx)

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if not _can_act(t, actor):
            raise NotFound()
        if t["state"] != "awaiting_resident":
            raise StaleVersion(
                "The ticket is not waiting for the resident.", details={"reason": "invalid_state"}
            )
        changes: dict[str, Any] = {"state": "in_progress"}
        _resume(c, ctx, cfg, t, moment, changes)
        _event(
            c,
            ctx,
            t["id"],
            "resumed",
            moment,
            from_state=t["state"],
            to_state="in_progress",
            note=body.note,
        )
        return Plan(changes, "in_progress")

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.respond",
        event_type="TicketStateChanged", plan=plan, now=now,
    )  # fmt: skip


def _close_plan(
    basis: str, note: str | None, ctx: RequestContext
) -> Callable[[Connection, dict[str, Any], dt.datetime], Plan]:
    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if t["state"] != "resolved":
            raise StaleVersion(
                "Only a resolved ticket can be closed.", details={"reason": "invalid_state"}
            )
        _event(
            c,
            ctx,
            t["id"],
            "closed",
            moment,
            from_state="resolved",
            to_state="closed",
            note=note,
            data={"basis": basis},
        )
        return Plan(
            {"state": "closed", "closed_at": moment, "closed_basis": basis},
            "closed",
            {"basis": basis},
        )

    return plan


def confirm(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: Note, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """OPS-04: closure by the resident's confirmation (a manager may close on their behalf, recorded as such)."""
    t0 = fetch_ticket(conn, ticket_id)
    if t0 is None or not _can_act(t0, actor):
        raise NotFound()
    basis = (
        "manager_closed"
        if actor.is_manager and t0["raised_by"] != actor.person_id
        else "resident_confirmed"
    )
    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.close", event_type="TicketClosed",
        plan=_close_plan(basis, body.note, ctx), now=now,
    )  # fmt: skip


def reopen(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: ReasonIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """OPS-04: within the reopen window (default 7 days from resolution). The ORIGINAL clocks, ack time, breaches and priority
    history are untouched: reopening never restarts or hides anything."""
    cfg = settings_mod.ensure_settings(conn, ctx)

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if not _can_act(t, actor):
            raise NotFound()
        if t["state"] not in {"resolved", "closed"} or t["closed_basis"] == "merged":
            raise StaleVersion(
                "Only a resolved or closed ticket can be reopened.",
                details={"reason": "invalid_state"},
            )
        resolved_at = t["resolved_at"]
        if resolved_at is None or moment > resolved_at + dt.timedelta(days=cfg.reopen_window_days):
            raise PolicyViolation(
                "The reopen window has passed; please raise a new ticket.",
                details={"reason": "reopen_window_passed"},
            )
        target = "assigned" if (t["assignee_id"] or t["contractor_name"]) else "triaged"
        _event(
            c,
            ctx,
            t["id"],
            "reopened",
            moment,
            from_state=t["state"],
            to_state=target,
            note=body.reason,
        )
        return Plan(
            {"state": target, "reopen_count": t["reopen_count"] + 1, "reopened_at": moment, "resolved_at": None,
             "feedback_due_at": None, "closed_at": None, "closed_basis": None},
            target, {"reopen_count": t["reopen_count"] + 1},
        )  # fmt: skip

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.reopen", event_type="TicketReopened",
        plan=plan, now=now, reason=body.reason,
    )  # fmt: skip


def cancel(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: ReasonIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        if not (actor.is_manager or t["raised_by"] == actor.person_id):
            raise NotFound()
        if t["state"] not in CANCELLABLE:
            raise StaleVersion(
                "This ticket cannot be cancelled.", details={"reason": "invalid_state"}
            )
        _event(
            c,
            ctx,
            t["id"],
            "cancelled",
            moment,
            from_state=t["state"],
            to_state="cancelled",
            note=body.reason,
        )
        return Plan({"state": "cancelled", "sla_paused_since": None}, "cancelled")

    return _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.cancel", event_type="TicketCancelled",
        plan=plan, now=now, reason=body.reason,
    )  # fmt: skip


# ------------------------------------------------------------------------------------------ merge (OPS-02)
def merge(
    conn: Connection, ctx: RequestContext, actor: Actor, ticket_id: uuid.UUID, body: MergeIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """Merge ``ticket_id`` into ``into_ticket_id``: only inside the SAME scope and (private) household or (block) block. Nothing
    of the merged ticket's text is copied to the target; the target's audience learns only that a duplicate was merged."""
    _require_manager(actor)
    if body.into_ticket_id == ticket_id:
        raise InvalidSchema.for_fields([("into_ticket_id", "same_ticket")])
    target = fetch_ticket(conn, body.into_ticket_id)
    if target is None:
        raise NotFound()

    def plan(c: Connection, t: dict[str, Any], moment: dt.datetime) -> Plan:
        same = (
            t["scope"] == target["scope"] and t["unit_id"] == target["unit_id"] and t["block_id"] == target["block_id"]
            and t["category"] != "support_privacy" and target["category"] != "support_privacy"
        )  # fmt: skip
        if not same:
            raise PolicyViolation(
                "Tickets can only be merged inside the same scope, household or block.",
                details={"reason": "merge_scope_mismatch"},
            )
        if (
            t["state"] in {"draft", "closed", "cancelled"}
            or target["state"] in {"draft", "cancelled"}
            or target["parent_ticket_id"]
        ):
            raise StaleVersion(
                "These tickets cannot be merged in their current state.",
                details={"reason": "invalid_state"},
            )
        c.execute(
            text(
                "INSERT INTO ticket_links (society_id, ticket_id, linked_ticket_id, state, method, decided_by, decided_at)"
                " VALUES (:s, :t, :l, 'merged', 'manual', :by, :now)"
                " ON CONFLICT (society_id, ticket_id, linked_ticket_id) DO UPDATE SET state = 'merged',"
                " decided_by = EXCLUDED.decided_by, decided_at = EXCLUDED.decided_at"
            ),
            {
                "s": ctx.society_id,
                "t": t["id"],
                "l": target["id"],
                "by": ctx.person_id,
                "now": moment,
            },
        )
        c.execute(
            text("UPDATE ticket_links SET state = 'rejected', decided_by = :by, decided_at = :now WHERE ticket_id = :t"
                 " AND linked_ticket_id <> :l AND state = 'proposed'"),
            {"by": ctx.person_id, "now": moment, "t": t["id"], "l": target["id"]},
        )  # fmt: skip
        changes: dict[str, Any] = {
            "parent_ticket_id": target["id"], "merged_at": moment, "state": "closed", "closed_at": moment,
            "closed_basis": "merged", "sla_paused_since": None,
        }  # fmt: skip
        _event(c, ctx, t["id"], "merged", moment, from_state=t["state"], to_state="closed", note=body.reason,
               data={"into": str(target["id"])})  # fmt: skip
        _event(c, ctx, target["id"], "merged", moment, data={"merged_ticket": str(t["id"])})
        return Plan(changes, "closed", {"merged_into": target["id"]})

    _mutate(
        conn, ctx, ticket_id, expected_version=body.expected_version, operation="ticket.merge", event_type="TicketMerged",
        plan=plan, now=now, reason=body.reason,
    )  # fmt: skip
    fresh = fetch_ticket(conn, body.into_ticket_id)
    assert fresh is not None  # noqa: S101
    return fresh


# ------------------------------------------------------------------------------------------ sweep (closure window, breaches)
def sweep_closures(conn: Connection, ctx: RequestContext, now: dt.datetime | None = None) -> int:
    """OPS-04: close resolved tickets whose feedback window elapsed (basis ``feedback_window_elapsed``). Idempotent; the
    resident can still reopen within the reopen window."""
    moment = now or utc_now()
    closed = 0
    for (tid,) in conn.execute(
        text(
            "SELECT id FROM tickets WHERE state = 'resolved' AND feedback_due_at <= :now ORDER BY feedback_due_at, id FOR UPDATE SKIP LOCKED"
        ),
        {"now": moment},
    ).all():
        _mutate(
            conn, ctx, tid, expected_version=None, operation="ticket.close", event_type="TicketClosed",
            plan=_close_plan("feedback_window_elapsed", None, ctx), now=moment,
        )  # fmt: skip
        closed += 1
    return closed


def sweep_society(
    conn: Connection, ctx: RequestContext, now: dt.datetime | None = None
) -> dict[str, int]:
    """Idempotent housekeeping for ONE society (a worker calls it per society with a system context):

    * resolved tickets whose feedback window elapsed are CLOSED (basis ``feedback_window_elapsed``), OPS-04;
    * acknowledgement and resolution breaches that already happened are recorded (immutable), OPS-01.
    """
    moment = now or utc_now()
    closed = sweep_closures(conn, ctx, moment)
    breached = 0
    rows = conn.execute(
        text(
            "SELECT t.id FROM tickets t WHERE t.sla_started_at IS NOT NULL AND t.state NOT IN ('draft', 'cancelled')"
            " AND ((t.ack_at IS NULL AND t.sla_ack_by <= :now AND NOT EXISTS (SELECT 1 FROM ticket_sla_breaches b"
            " WHERE b.ticket_id = t.id AND b.clock = 'acknowledgement'))"
            " OR (t.state NOT IN ('resolved', 'closed') AND t.sla_paused_since IS NULL AND t.sla_fix_by <= :now"
            " AND NOT EXISTS (SELECT 1 FROM ticket_sla_breaches b WHERE b.ticket_id = t.id AND b.clock = 'resolution')))"
            " ORDER BY t.id FOR UPDATE SKIP LOCKED"
        ),
        {"now": moment},
    ).all()
    for (tid,) in rows:

        def plan(c: Connection, t: dict[str, Any], m: dt.datetime) -> Plan:
            found = _check_breaches(c, ctx, t, m, "sweep")
            return Plan({}, None, {"breached": found})

        _mutate(
            conn, ctx, tid, expected_version=None, operation="ticket.sla_breach", event_type="TicketSlaBreached", plan=plan,
            now=moment,
        )  # fmt: skip
        breached += 1
    return {"closed": closed, "breached": breached}
