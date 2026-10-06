"""Guard shifts, start/end checklists, handovers with acknowledgements and escalation, supervisor overrides, guard profiles and training.

REQ: SHIFT-01 (start checklist; end checklist counts parcels and unresolved inside records; BOTH guards or the supervisor acknowledge; a missing
next guard ESCALATES and never locks anything), SHIFT-02 (the deterministic open-items list is always shown BELOW any summary; a summary is
advisory), UX-08 (guard language per guard), UX-09 (practice-mode training per guard per scenario), Appendix C (supervisor override until shift
end or earlier), INV-08 (essential egress is never blocked: no function here is called by, or can fail, a gate decision), INV-06 (AI proposes;
the summary hook stores text, it never changes the open items), INV-01, PRD 12.4.

Truthful states (INV-07): ``ended`` (the guard finished the shift) is not ``acknowledged`` (both guards or the supervisor signed the handover) and
neither is ``escalated`` (nobody signed in time). The checklist records what was reported and what the server knows; it never blocks.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ...core.pagination import PageParams, Paginator, SortColumn
from ..visits import gates as gates_service
from .config import DEFAULT_CONFIG, ShiftsConfig
from .schemas import (
    SCENARIO_TYPES,
    EndChecklist,
    OverrideGrant,
    ProfilePut,
    ShiftCreate,
    StartChecklist,
)

log = logging.getLogger("dwaar_api.shifts")

SUPERVISOR_ROLES: Final = frozenset({"guard_sup", "secretary"})
ITEM_ORDER: Final = (
    "incident_unresolved", "visit_pending_decision", "visit_inside", "parcel_in_custody", "override_active",
)  # fmt: skip

#: SHIFT-02 / AI-G08 hook. The ai-gateway engineer registers a provider; with none registered a handover has no summary and shows the list alone.
#: A provider receives the deterministic open items and the language and returns text (or None). It never changes the items.
SummaryProvider = Callable[[Sequence[Mapping[str, Any]], str], str | None]
_summary_provider: SummaryProvider | None = None


def set_summary_provider(provider: SummaryProvider | None) -> None:
    """Register (or clear) the AI-G08 summary provider. This module never calls a model itself."""
    global _summary_provider  # noqa: PLW0603 (a single module-level hook is the point)
    _summary_provider = provider


def _version(row: Mapping[Any, Any], expected: int) -> None:
    if int(row["version"]) != expected:
        raise StaleVersion(details={"current_version": int(row["version"])})


# ------------------------------------------------------------------------------------------ guard profile and training
_GUARD_ROLES_SQL: Final = (
    "SELECT 1 FROM role_grants WHERE person_id = :p AND role IN ('guard', 'guard_sup') AND revoked_at IS NULL"
    " AND (expires_at IS NULL OR expires_at > clock_timestamp())"
)


def require_guard(conn: Connection, person_id: uuid.UUID) -> None:
    """The person holds a current guard role in THIS society (RLS context), else 404: another person or society is simply absent."""
    if conn.execute(text(_GUARD_ROLES_SQL), {"p": person_id}).first() is None:
        raise NotFound()


def profile_view(conn: Connection, person_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text("SELECT language, version, updated_at FROM guard_profiles WHERE person_id = :p"),
            {"p": person_id},
        )
        .mappings()
        .first()
    )
    return {
        "person_id": person_id,
        "language": row["language"] if row else None,
        "version": row["version"] if row else 0,
        "updated_at": row["updated_at"] if row else None,
        "training": training_status(conn, person_id),
    }


def put_profile(
    conn: Connection, ctx: RequestContext, person_id: uuid.UUID, body: ProfilePut
) -> dict[str, Any]:
    if body.language == "kn":
        raise PolicyViolation(
            details={"reason": "language_not_available_until_m2", "language": "kn"}
        )
    require_guard(conn, person_id)
    assert ctx.society_id is not None  # noqa: S101
    row = (
        conn.execute(
            text(
                "SELECT id, language, version FROM guard_profiles WHERE person_id = :p FOR UPDATE"
            ),
            {"p": person_id},
        )
        .mappings()
        .first()
    )
    if row is not None:
        _version(row, body.expected_version)
    elif body.expected_version != 0:
        raise StaleVersion(details={"current_version": 0})
    profile_id = row["id"] if row else uuid7()
    version = int(row["version"]) + 1 if row else 1

    def apply(c: Connection) -> MutationResult:
        if row is None:
            c.execute(
                text(
                    "INSERT INTO guard_profiles (id, society_id, person_id, language, updated_by) VALUES (:id, :s, :p, :l, :by)"
                ),
                {
                    "id": profile_id,
                    "s": ctx.society_id,
                    "p": person_id,
                    "l": body.language,
                    "by": ctx.person_id,
                },
            )
        else:
            c.execute(
                text(
                    "UPDATE guard_profiles SET language = :l, version = version + 1, updated_by = :by, updated_at = clock_timestamp()"
                    " WHERE id = :id"
                ),
                {"id": profile_id, "l": body.language, "by": ctx.person_id},
            )
        return MutationResult(
            profile_id, version, before=None if row is None else {"language": row["language"]},
            after={"language": body.language},
            event_payload={"person_id": person_id, "language": body.language},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="guard.profile_set",
        object_type="guard_profile",
        event_type="GuardProfileChanged",
        apply=apply,
    )
    return profile_view(conn, person_id)


def training_status(conn: Connection, person_id: uuid.UUID) -> dict[str, Any]:
    """The latest completion per scenario type and the types still missing (UX-09). Practice-mode data only."""
    rows = conn.execute(
        text(
            "SELECT DISTINCT ON (scenario_type) scenario_type, completed_at, language FROM guard_training_completions"
            " WHERE person_id = :p ORDER BY scenario_type, completed_at DESC, id DESC"
        ),
        {"p": person_id},
    ).all()
    done = {r[0]: {"completed_at": r[1], "language": r[2]} for r in rows}
    return {
        "completed": [{"scenario_type": k, **done[k]} for k in sorted(done)],
        "missing": [s for s in SCENARIO_TYPES if s not in done],
        "practice_mode": True,
    }


def record_training(
    conn: Connection, ctx: RequestContext, person_id: uuid.UUID, scenario_type: str
) -> dict[str, Any]:
    require_guard(conn, person_id)
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    lang = conn.execute(
        text("SELECT language FROM guard_profiles WHERE person_id = :p"), {"p": person_id}
    ).scalar()
    completion_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO guard_training_completions (id, society_id, person_id, scenario_type, language, recorded_by)"
                " VALUES (:id, :s, :p, :t, :l, :by)"
            ),
            {"id": completion_id, "s": ctx.society_id, "p": person_id, "t": scenario_type, "l": lang or "en", "by": ctx.person_id},
        )  # fmt: skip
        return MutationResult(
            completion_id, 1, after={"scenario_type": scenario_type, "practice_mode": True},
            event_payload={"person_id": person_id, "scenario_type": scenario_type, "practice_mode": True},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="guard.training_record", object_type="guard_training", event_type="GuardTrainingCompleted",
        apply=apply,
    )  # fmt: skip
    return profile_view(conn, person_id)


# ------------------------------------------------------------------------------------------ open items (SHIFT-02)
def open_items(
    conn: Connection,
    gate_id: uuid.UUID,
    cfg: ShiftsConfig = DEFAULT_CONFIG,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """The deterministic list of what is still open at a gate: unresolved incidents, requests pending a decision, visitors recorded inside,
    parcels in custody, active overrides. Sorted by kind then id; complete up to ``max_items_per_kind`` per kind and it SAYS so when cut.

    No model is involved. This list is the source of truth of a handover; a summary is only ever shown above it (SHIFT-02).
    """
    moment = now or utc_now()
    cap = cfg.max_items_per_kind
    gate = {"g": gate_id, "cap": cap + 1}
    queries: dict[str, str] = {
        "incident_unresolved": (
            "SELECT id, kind AS what, state AS detail_state FROM exceptions WHERE state <> 'resolved' ORDER BY id LIMIT :cap"
        ),
        "visit_pending_decision": (
            "SELECT id, kind AS what, state AS detail_state FROM visits WHERE state = 'requested'"
            " AND (gate_id = :g OR gate_id IS NULL) ORDER BY id LIMIT :cap"
        ),
        "visit_inside": (
            "SELECT id, kind AS what, confidence_inside AS detail_state FROM visits WHERE state = 'inside'"
            " AND (gate_id = :g OR gate_id IS NULL) ORDER BY id LIMIT :cap"
        ),
        "parcel_in_custody": (
            "SELECT id, state AS what, bin_code AS detail_state FROM parcels WHERE state IN"
            " ('received_at_gate', 'stored', 'pickup_pending', 'refused') AND (gate_id = :g OR gate_id IS NULL) ORDER BY id LIMIT :cap"
        ),
        "override_active": (
            "SELECT o.id, 'supervisor_override' AS what, o.valid_until::text AS detail_state FROM shift_overrides o"
            " JOIN shifts s ON s.society_id = o.society_id AND s.id = o.shift_id WHERE o.gate_id = :g AND o.revoked_at IS NULL"
            " AND o.valid_until > :now AND s.state = 'active' ORDER BY o.id LIMIT :cap"
        ),
    }
    counts_sql: dict[str, str] = {
        "incident_unresolved": "SELECT count(*) FROM exceptions WHERE state <> 'resolved'",
        "visit_pending_decision": "SELECT count(*) FROM visits WHERE state = 'requested' AND (gate_id = :g OR gate_id IS NULL)",
        "visit_inside": "SELECT count(*) FROM visits WHERE state = 'inside' AND (gate_id = :g OR gate_id IS NULL)",
        "parcel_in_custody": (
            "SELECT count(*) FROM parcels WHERE state IN ('received_at_gate', 'stored', 'pickup_pending', 'refused')"
            " AND (gate_id = :g OR gate_id IS NULL)"
        ),
        "override_active": (
            "SELECT count(*) FROM shift_overrides o JOIN shifts s ON s.society_id = o.society_id AND s.id = o.shift_id"
            " WHERE o.gate_id = :g AND o.revoked_at IS NULL AND o.valid_until > :now AND s.state = 'active'"
        ),
    }
    items: list[dict[str, Any]] = []
    counts: dict[str, dict[str, Any]] = {}
    for kind in ITEM_ORDER:
        params = {**gate, "now": moment}
        rows = conn.execute(text(queries[kind]), params).mappings().all()
        total = int(conn.execute(text(counts_sql[kind]), params).scalar_one())
        listed = rows[:cap]
        counts[kind] = {"total": total, "listed": len(listed), "truncated": total > len(listed)}
        for r in listed:
            items.append(
                {
                    "kind": kind,
                    "ref_id": str(r["id"]),
                    "message_key": f"shifts.item.{kind}",
                    "what": r["what"],
                    "detail": r["detail_state"],
                }
            )
    return {
        "items": items,
        "counts": counts,
        "complete": not any(c["truncated"] for c in counts.values()),
    }


# ------------------------------------------------------------------------------------------ checklists
def _policy_age(conn: Connection, gate_id: uuid.UUID, now: dt.datetime) -> dict[str, Any]:
    """Age of the policy a device at this gate applies (edge status), else of the latest published snapshot, else not available."""
    applied = conn.execute(
        text(
            "SELECT max(p.issued_at) FROM devices d JOIN edge_device_state s ON s.society_id = d.society_id AND s.device_id = d.id"
            " JOIN policy_snapshots p ON p.society_id = s.society_id AND p.seq = s.policy_seq_applied"
            " WHERE d.gate_id = :g AND d.state = 'active'"
        ),
        {"g": gate_id},
    ).scalar()
    if applied is not None:
        return {"age_s": max(0, int((now - applied).total_seconds())), "source": "edge_status"}
    latest = conn.execute(text("SELECT max(issued_at) FROM policy_snapshots")).scalar()
    if latest is not None:
        return {
            "age_s": max(0, int((now - latest).total_seconds())),
            "source": "latest_published_snapshot",
        }
    return {"age_s": None, "source": "not_available"}


def _item(key: str, status: str, value: Any, source: str, **extra: Any) -> dict[str, Any]:
    return {"key": key, "status": status, "value": value, "source": source, **extra}


def start_checklist_items(
    conn: Connection, gate_id: uuid.UUID, body: StartChecklist, cfg: ShiftsConfig, now: dt.datetime
) -> list[dict[str, Any]]:
    """SHIFT-01 start items. Reported-by-terminal values are recorded as reported; what the terminal did not report is ``not_reported``,
    never invented. Relay and sensor health are placeholders until the edge reports them (EDGE-08/09)."""
    counts = open_items(conn, gate_id, cfg, now=now)["counts"]
    age = _policy_age(conn, gate_id, now)
    stale = age["age_s"] is not None and age["age_s"] > cfg.policy_stale_hours * 3600

    def reported(key: str, value: Any, ok: bool) -> dict[str, Any]:
        if value is None:
            return _item(key, "not_reported", None, "placeholder")
        return _item(key, "ok" if ok else "attention", value, "terminal")

    return [
        reported("battery", body.battery_percent, body.battery_percent is not None and body.battery_percent >= 30),
        reported("network", body.network, body.network == "ok"),
        _item(
            "policy_age", "not_reported" if age["age_s"] is None else ("attention" if stale else "ok"),
            age["age_s"], age["source"], stale_after_hours=cfg.policy_stale_hours,
        ),
        reported("relay_health", body.relay_health, body.relay_health == "ok"),
        reported("sensor_health", body.sensor_health, body.sensor_health == "ok"),
        _item("pending_visits", "attention" if counts["visit_pending_decision"]["total"] else "ok",
              counts["visit_pending_decision"]["total"], "server"),
        _item("unresolved_incidents", "attention" if counts["incident_unresolved"]["total"] else "ok",
              counts["incident_unresolved"]["total"], "server"),
        _item("parcels_in_custody", "ok", counts["parcel_in_custody"]["total"], "server"),
        reported("keys", body.keys_count, True),
    ]  # fmt: skip


def end_checklist_items(
    conn: Connection, gate_id: uuid.UUID, body: EndChecklist, cfg: ShiftsConfig, now: dt.datetime
) -> list[dict[str, Any]]:
    counts = open_items(conn, gate_id, cfg, now=now)["counts"]
    parcels = counts["parcel_in_custody"]["total"]
    inside = counts["visit_inside"]["total"]
    return [
        _item(
            "parcels", "ok" if body.parcels_counted == parcels else "attention", parcels, "server",
            counted_by_guard=body.parcels_counted, difference=body.parcels_counted - parcels,
        ),
        _item(
            "inside_records", "ok" if inside == 0 or body.inside_records_reviewed else "attention", inside, "server",
            reviewed_by_guard=body.inside_records_reviewed,
        ),
        _item("unresolved_incidents", "attention" if counts["incident_unresolved"]["total"] else "ok",
              counts["incident_unresolved"]["total"], "server"),
        _item("pending_visits", "attention" if counts["visit_pending_decision"]["total"] else "ok",
              counts["visit_pending_decision"]["total"], "server"),
        _item("keys", "not_reported" if body.keys_returned is None else "ok", body.keys_returned,
              "placeholder" if body.keys_returned is None else "terminal"),
    ]  # fmt: skip


def _checklist(conn: Connection, shift_id: uuid.UUID, kind: str) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT items, completed_by, completed_at FROM shift_checklists WHERE shift_id = :s AND kind = :k"
            ),
            {"s": shift_id, "k": kind},
        )
        .mappings()
        .first()
    )
    return (
        None
        if row is None
        else {
            "items": row["items"],
            "completed_by": row["completed_by"],
            "completed_at": row["completed_at"],
        }
    )


# ------------------------------------------------------------------------------------------ shifts
_SHIFT_COLS: Final = (
    "s.id, s.gate_id, s.guard_id, s.planned_start, s.planned_end, s.state, s.started_at, s.started_by, s.ended_at, s.ended_by,"
    " s.version, s.created_at, g.name AS gate_name"
)
_SHIFT_FROM: Final = (
    " FROM shifts s JOIN gates g ON g.society_id = s.society_id AND g.id = s.gate_id"
)


def shift_view(conn: Connection, row: Mapping[Any, Any], *, detail: bool = True) -> dict[str, Any]:
    view: dict[str, Any] = {
        "id": row["id"],
        "gate_id": row["gate_id"],
        "gate_name": row["gate_name"],
        "guard_id": row["guard_id"],
        "planned_start": row["planned_start"],
        "planned_end": row["planned_end"],
        "state": row["state"],
        "started_at": row["started_at"],
        "ended_at": row["ended_at"],
        "version": row["version"],
    }
    if detail:
        view["start_checklist"] = _checklist(conn, row["id"], "start")
        view["end_checklist"] = _checklist(conn, row["id"], "end")
        view["overrides"] = [
            {
                "id": o[0],
                "valid_until": o[1],
                "revoked_at": o[2],
                "revoke_reason": o[3],
                "granted_by": o[4],
            }
            for o in conn.execute(
                text(
                    "SELECT id, valid_until, revoked_at, revoke_reason, granted_by FROM shift_overrides WHERE shift_id = :s"
                    " ORDER BY granted_at, id"
                ),
                {"s": row["id"]},
            )
        ]
    return view


def _locked_shift(conn: Connection, shift_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(text("SELECT * FROM shifts WHERE id = :id FOR UPDATE"), {"id": shift_id})
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return dict(row)


def get_shift(conn: Connection, shift_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(text(f"SELECT {_SHIFT_COLS}{_SHIFT_FROM} WHERE s.id = :id"), {"id": shift_id})  # noqa: S608
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return shift_view(conn, row)


def shift_owner(conn: Connection, shift_id: uuid.UUID) -> uuid.UUID | None:
    row = conn.execute(text("SELECT guard_id FROM shifts WHERE id = :id"), {"id": shift_id}).first()
    return None if row is None else uuid.UUID(str(row[0]))


def create_shift(conn: Connection, ctx: RequestContext, body: ShiftCreate) -> dict[str, Any]:
    gates_service.require_active_gate(conn, body.gate_id)
    require_guard(conn, body.guard_id)
    clash = conn.execute(
        text(
            "SELECT 1 FROM shifts WHERE guard_id = :g AND state <> 'ended' AND planned_start < :e AND planned_end > :s LIMIT 1"
        ),
        {"g": body.guard_id, "s": body.planned_start, "e": body.planned_end},
    ).first()
    if clash:
        raise PolicyViolation(details={"reason": "overlapping_shift"})
    assert ctx.society_id is not None  # noqa: S101
    shift_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO shifts (id, society_id, gate_id, guard_id, planned_start, planned_end, created_by)"
                " VALUES (:id, :s, :g, :guard, :ps, :pe, :by)"
            ),
            {
                "id": shift_id, "s": ctx.society_id, "g": body.gate_id, "guard": body.guard_id, "ps": body.planned_start,
                "pe": body.planned_end, "by": ctx.person_id,
            },
        )  # fmt: skip
        return MutationResult(
            shift_id, 1, after={"gate_id": body.gate_id, "guard_id": body.guard_id, "state": "scheduled"},
            event_payload={"shift_id": shift_id, "gate_id": body.gate_id, "guard_id": body.guard_id, "state": "scheduled"},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="shift.schedule",
        object_type="shift",
        event_type="ShiftScheduled",
        apply=apply,
    )
    return get_shift(conn, shift_id)


def _link_incoming(
    conn: Connection, ctx: RequestContext, shift: Mapping[Any, Any]
) -> dict[str, Any] | None:
    """A guard starting at a gate with an unacknowledged handover from an ENDED shift becomes its incoming guard."""
    row = (
        conn.execute(
            text(
                "SELECT id, version, state FROM shift_handovers WHERE gate_id = :g AND incoming_shift_id IS NULL"
                " AND state IN ('pending', 'escalated') AND outgoing_guard <> :guard ORDER BY created_at DESC, id DESC LIMIT 1"
                " FOR UPDATE"
            ),
            {"g": shift["gate_id"], "guard": shift["guard_id"]},
        )
        .mappings()
        .first()
    )
    if row is None:
        return None

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE shift_handovers SET incoming_shift_id = :sid, incoming_guard = :guard, version = version + 1 WHERE id = :id"
            ),
            {"sid": shift["id"], "guard": shift["guard_id"], "id": row["id"]},
        )
        return MutationResult(
            row["id"], int(row["version"]) + 1, after={"incoming_guard_known": True},
            event_payload={"handover_id": row["id"], "incoming_shift_id": shift["id"]},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="handover.incoming_linked", object_type="shift_handover",
        event_type="HandoverIncomingLinked", apply=apply,
    )  # fmt: skip
    return get_handover(conn, row["id"])


def start_shift(
    conn: Connection,
    ctx: RequestContext,
    shift_id: uuid.UUID,
    body: StartChecklist,
    *,
    cfg: ShiftsConfig = DEFAULT_CONFIG,
) -> dict[str, Any]:
    row = _locked_shift(conn, shift_id)
    if row["state"] == "active":
        return get_shift(conn, shift_id)  # naturally idempotent
    if row["state"] != "scheduled":
        raise PolicyViolation(details={"reason": "shift_not_startable", "state": row["state"]})
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    busy = conn.execute(
        text("SELECT 1 FROM shifts WHERE guard_id = :g AND state = 'active' AND id <> :id"),
        {"g": row["guard_id"], "id": shift_id},
    ).first()
    if busy:
        raise PolicyViolation(details={"reason": "guard_already_on_shift"})
    now = utc_now()
    items = start_checklist_items(conn, row["gate_id"], body, cfg, now)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE shifts SET state = 'active', started_at = clock_timestamp(), started_by = :by, version = version + 1"
                " WHERE id = :id AND state = 'scheduled'"
            ),
            {"id": shift_id, "by": ctx.person_id},
        )
        c.execute(
            text(
                "INSERT INTO shift_checklists (id, society_id, shift_id, kind, items, completed_by) VALUES (:id, :s, :sh, 'start',"
                " CAST(:items AS jsonb), :by)"
            ),
            {
                "id": uuid7(),
                "s": ctx.society_id,
                "sh": shift_id,
                "items": _json_list(items),
                "by": ctx.person_id,
            },
        )
        return MutationResult(
            shift_id, int(row["version"]) + 1, before={"state": "scheduled"}, after={"state": "active"},
            event_payload={
                "shift_id": shift_id, "gate_id": row["gate_id"], "guard_id": row["guard_id"], "state": "active",
                "attention_items": sum(1 for i in items if i["status"] == "attention"),
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="shift.start",
        object_type="shift",
        event_type="ShiftStarted",
        apply=apply,
    )
    view = get_shift(conn, shift_id)
    view["incoming_handover"] = _link_incoming(conn, ctx, row)
    return view


def _json_list(items: Sequence[Mapping[str, Any]]) -> str:
    return json.dumps(list(items), separators=(",", ":"), sort_keys=True, default=str)


def end_shift(
    conn: Connection,
    ctx: RequestContext,
    shift_id: uuid.UUID,
    body: EndChecklist,
    *,
    cfg: ShiftsConfig = DEFAULT_CONFIG,
) -> dict[str, Any]:
    """End the shift, record the end checklist, expire the shift's overrides and create the handover. A missing next guard changes
    NOTHING here: the handover is created pending and escalates later; no gate, device, visit or kiosk state is touched (INV-08)."""
    row = _locked_shift(conn, shift_id)
    if row["state"] == "ended":
        view = get_shift(conn, shift_id)
        view["handover"] = _handover_of_shift(conn, shift_id)
        return view
    if row["state"] != "active":
        raise PolicyViolation(details={"reason": "shift_not_active", "state": row["state"]})
    assert ctx.society_id is not None  # noqa: S101
    now = utc_now()
    items = end_checklist_items(conn, row["gate_id"], body, cfg, now)
    open_payload = open_items(conn, row["gate_id"], cfg, now=now)
    handover_id = uuid7()
    incoming = (
        conn.execute(
            text(
                "SELECT id, guard_id FROM shifts WHERE gate_id = :g AND state = 'active' AND id <> :id AND guard_id <> :guard"
                " ORDER BY started_at, id LIMIT 1"
            ),
            {"g": row["gate_id"], "id": shift_id, "guard": row["guard_id"]},
        )
        .mappings()
        .first()
    )
    summary = None
    language = "en"
    if _summary_provider is not None:
        language = _language_of(conn, incoming["guard_id"] if incoming else None)
        try:
            summary = _summary_provider(open_payload["items"], language)
        except Exception as exc:  # a failing summary never blocks a handover
            log.warning("handover summary provider failed", extra={"exc_type": type(exc).__name__})

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE shifts SET state = 'ended', ended_at = clock_timestamp(), ended_by = :by, version = version + 1"
                " WHERE id = :id AND state = 'active'"
            ),
            {"id": shift_id, "by": ctx.person_id},
        )
        c.execute(
            text(
                "INSERT INTO shift_checklists (id, society_id, shift_id, kind, items, completed_by) VALUES (:id, :s, :sh, 'end',"
                " CAST(:items AS jsonb), :by)"
            ),
            {
                "id": uuid7(),
                "s": ctx.society_id,
                "sh": shift_id,
                "items": _json_list(items),
                "by": ctx.person_id,
            },
        )
        c.execute(
            text(
                "UPDATE shift_overrides SET revoked_at = clock_timestamp(), revoke_reason = 'shift_ended', version = version + 1"
                " WHERE shift_id = :id AND revoked_at IS NULL"
            ),
            {"id": shift_id},
        )
        c.execute(
            text(
                "INSERT INTO shift_handovers (id, society_id, gate_id, outgoing_shift_id, incoming_shift_id, outgoing_guard,"
                " incoming_guard, open_items, summary_text, summary_source, summary_language) VALUES (:id, :s, :g, :out, :inc, :og,"
                " :ig, CAST(:items AS jsonb), :sum, :src, :lang)"
            ),
            {
                "id": handover_id, "s": ctx.society_id, "g": row["gate_id"], "out": shift_id,
                "inc": incoming["id"] if incoming else None, "og": row["guard_id"],
                "ig": incoming["guard_id"] if incoming else None, "items": _json_list(open_payload["items"]),
                "sum": summary, "src": "ai_gateway" if summary else None, "lang": language if summary else None,
            },
        )  # fmt: skip
        return MutationResult(
            shift_id, int(row["version"]) + 1, before={"state": "active"}, after={"state": "ended"},
            event_payload={
                "shift_id": shift_id, "gate_id": row["gate_id"], "guard_id": row["guard_id"], "state": "ended",
                "handover_id": handover_id, "open_item_count": len(open_payload["items"]),
                "incoming_guard_known": incoming is not None,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="shift.end", object_type="shift", event_type="ShiftEnded", apply=apply
    )
    view = get_shift(conn, shift_id)
    view["handover"] = get_handover(conn, handover_id)
    return view


def _language_of(conn: Connection, person_id: uuid.UUID | None) -> str:
    if person_id is None:
        return "en"
    lang = conn.execute(
        text("SELECT language FROM guard_profiles WHERE person_id = :p"), {"p": person_id}
    ).scalar()
    return str(lang) if lang else "en"


def list_shifts(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    own_only: uuid.UUID | None,
    gate_id: uuid.UUID | None,
    state: str | None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    if own_only is not None:
        where.append("s.guard_id = :me")
        params["me"] = own_only
        filters["me"] = str(own_only)
    if gate_id is not None:
        where.append("s.gate_id = :gate")
        params["gate"] = gate_id
        filters["gate_id"] = gate_id
    if state is not None:
        where.append("s.state = :state")
        params["state"] = state
        filters["state"] = state
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_SHIFT_COLS}{_SHIFT_FROM}",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("s.planned_start", "timestamptz", nullable=False),
            SortColumn("s.id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    return {
        "items": [shift_view(conn, r, detail=False) for r in result.items],
        "next_cursor": result.next_cursor,
    }


def current_context(
    conn: Connection, person_id: uuid.UUID, cfg: ShiftsConfig = DEFAULT_CONFIG
) -> dict[str, Any]:
    """GATE-09 / GATE-11 shift context of the guard's active shift: the pending queue, parcels, inside records, open incidents."""
    row = (
        conn.execute(
            text(
                f"SELECT {_SHIFT_COLS}{_SHIFT_FROM} WHERE s.guard_id = :p AND s.state = 'active' LIMIT 1"
            ),  # noqa: S608
            {"p": person_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        return {"shift": None, "context": None}
    counts = open_items(conn, row["gate_id"], cfg)["counts"]
    overstays = conn.execute(
        text("SELECT count(*) FROM exceptions WHERE kind = 'overstay' AND state <> 'resolved'")
    ).scalar_one()
    return {
        "shift": shift_view(conn, row, detail=False),
        "context": {
            "pending_queue": counts["visit_pending_decision"]["total"],
            "parcels_in_custody": counts["parcel_in_custody"]["total"],
            "inside_records": counts["visit_inside"]["total"],
            "unresolved_incidents": counts["incident_unresolved"]["total"],
            "overstay_alerts": int(overstays),
            "active_overrides": counts["override_active"]["total"],
            "guard_language": _language_of(conn, person_id),
        },
    }


# ------------------------------------------------------------------------------------------ handovers
_HANDOVER_COLS: Final = (
    "id, gate_id, outgoing_shift_id, incoming_shift_id, outgoing_guard, incoming_guard, open_items, summary_text, summary_source,"
    " summary_language, state, outgoing_ack_at, incoming_ack_at, supervisor_ack_at, supervisor_ack_by, escalated_at,"
    " escalation_reason, signed_at, version, created_at"
)


def handover_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    """The handover as a guard reads it. Layout contract (SHIFT-02): the summary, when there is one, comes FIRST; the deterministic open
    items always follow, are always present and are never replaced or filtered by the summary."""
    items = list(row["open_items"])
    out: dict[str, Any] = {
        "id": row["id"],
        "gate_id": row["gate_id"],
        "outgoing_shift_id": row["outgoing_shift_id"],
        "incoming_shift_id": row["incoming_shift_id"],
        "outgoing_guard": row["outgoing_guard"],
        "incoming_guard": row["incoming_guard"],
        "state": row["state"],
        "acknowledgements": {
            "outgoing_at": row["outgoing_ack_at"],
            "incoming_at": row["incoming_ack_at"],
            "supervisor_at": row["supervisor_ack_at"],
            "signed_at": row["signed_at"],
        },
        "escalated_at": row["escalated_at"],
        "escalation_reason": row["escalation_reason"],
        "version": row["version"],
        "created_at": row["created_at"],
    }
    if row["summary_text"] is not None:
        out["summary"] = {
            "text": row["summary_text"],
            "source": row["summary_source"],
            "language": row["summary_language"],
            "advisory": True,
        }
    out["display_order"] = (
        ["summary", "open_items"] if row["summary_text"] is not None else ["open_items"]
    )
    out["open_items"] = items
    return out


def get_handover(conn: Connection, handover_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text(f"SELECT {_HANDOVER_COLS} FROM shift_handovers WHERE id = :id"),  # noqa: S608
            {"id": handover_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return handover_view(row)


def _handover_of_shift(conn: Connection, shift_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(
        text("SELECT id FROM shift_handovers WHERE outgoing_shift_id = :s"), {"s": shift_id}
    ).first()
    return None if row is None else get_handover(conn, row[0])


def handover_parties(
    conn: Connection, handover_id: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID | None] | None:
    row = conn.execute(
        text("SELECT outgoing_guard, incoming_guard FROM shift_handovers WHERE id = :id"),
        {"id": handover_id},
    ).first()
    return (
        None
        if row is None
        else (uuid.UUID(str(row[0])), uuid.UUID(str(row[1])) if row[1] else None)
    )


def list_handovers(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    own_only: uuid.UUID | None,
    state: str | None,
    gate_id: uuid.UUID | None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    if own_only is not None:
        where.append("(outgoing_guard = :me OR incoming_guard = :me)")
        params["me"] = own_only
        filters["me"] = str(own_only)
    if state is not None:
        where.append("state = :state")
        params["state"] = state
        filters["state"] = state
    if gate_id is not None:
        where.append("gate_id = :gate")
        params["gate"] = gate_id
        filters["gate_id"] = gate_id
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_HANDOVER_COLS} FROM shift_handovers",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("created_at", "timestamptz", nullable=False),
            SortColumn("id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    return {"items": [handover_view(r) for r in result.items], "next_cursor": result.next_cursor}


def acknowledge(
    conn: Connection, ctx: RequestContext, handover_id: uuid.UUID, expected_version: int | None
) -> dict[str, Any]:
    """SHIFT-01: both guards, or the supervisor. A guard who is neither the outgoing nor the incoming guard is told 404."""
    row = (
        conn.execute(
            text("SELECT * FROM shift_handovers WHERE id = :id FOR UPDATE"), {"id": handover_id}
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    me = ctx.person_id
    supervisor = ctx.actor_role in SUPERVISOR_ROLES
    party: str | None = None
    if supervisor:
        party = "supervisor"
    elif me == row["outgoing_guard"]:
        party = "outgoing"
    elif me is not None and me == row["incoming_guard"]:
        party = "incoming"
    if party is None:
        raise NotFound()
    if expected_version is not None:
        _version(row, expected_version)
    column = {
        "supervisor": "supervisor_ack_at",
        "outgoing": "outgoing_ack_at",
        "incoming": "incoming_ack_at",
    }[party]
    if row[column] is not None:
        return get_handover(conn, handover_id)  # naturally idempotent
    if party == "supervisor":
        signs = True
    elif party == "outgoing":
        signs = row["incoming_ack_at"] is not None
    else:
        signs = row["outgoing_ack_at"] is not None

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE shift_handovers SET"
                " outgoing_ack_at = CASE WHEN :party = 'outgoing' THEN clock_timestamp() ELSE outgoing_ack_at END,"
                " incoming_ack_at = CASE WHEN :party = 'incoming' THEN clock_timestamp() ELSE incoming_ack_at END,"
                " supervisor_ack_at = CASE WHEN :party = 'supervisor' THEN clock_timestamp() ELSE supervisor_ack_at END,"
                " supervisor_ack_by = CASE WHEN :party = 'supervisor' THEN CAST(:me AS uuid) ELSE supervisor_ack_by END,"
                " state = CASE WHEN :signs THEN 'acknowledged' ELSE state END,"
                " signed_at = CASE WHEN :signs THEN clock_timestamp() ELSE signed_at END, version = version + 1 WHERE id = :id"
            ),
            {"id": handover_id, "me": me, "signs": signs, "party": party},
        )
        return MutationResult(
            handover_id, int(row["version"]) + 1, before={"state": row["state"]},
            after={"acknowledged_by": party, "signed": signs},
            event_payload={"handover_id": handover_id, "gate_id": row["gate_id"], "acknowledged_by": party, "signed": signs},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="handover.acknowledge", object_type="shift_handover",
        event_type="HandoverSigned" if signs else "HandoverAcknowledged", apply=apply,
    )  # fmt: skip
    return get_handover(conn, handover_id)


def attach_summary(
    conn: Connection,
    ctx: RequestContext,
    handover_id: uuid.UUID,
    text_: str,
    *,
    source: str = "ai_gateway",
) -> dict[str, Any]:
    """AI-G08 hook: store a (machine or manual) SUMMARY on a handover. It is advisory text shown ABOVE the open items; it cannot change
    them, and a handover without a summary is complete. No model is called here: the ai-gateway engineer calls this with its output."""
    if source not in ("ai_gateway", "manual"):
        raise InvalidSchema.for_fields([("source", "unknown_source")])
    row = (
        conn.execute(
            text(
                "SELECT id, version, incoming_guard FROM shift_handovers WHERE id = :id FOR UPDATE"
            ),
            {"id": handover_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    language = _language_of(conn, row["incoming_guard"])

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE shift_handovers SET summary_text = :t, summary_source = :src, summary_language = :l, version = version + 1"
                " WHERE id = :id"
            ),
            {"t": text_[:4000], "src": source, "l": language, "id": handover_id},
        )
        return MutationResult(
            handover_id, int(row["version"]) + 1, after={"summary_source": source, "summary_language": language},
            event_payload={"handover_id": handover_id, "summary_source": source},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="handover.summary_attach", object_type="shift_handover", event_type="HandoverSummaryAttached",
        apply=apply,
    )  # fmt: skip
    return get_handover(conn, handover_id)


# ------------------------------------------------------------------------------------------ overrides (Appendix C)
def grant_override(
    conn: Connection,
    ctx: RequestContext,
    shift_id: uuid.UUID,
    body: OverrideGrant,
    cfg: ShiftsConfig = DEFAULT_CONFIG,
) -> dict[str, Any]:
    """A supervisor override valid until the shift ends or earlier: ``valid_until`` is capped to the shift's planned end, and the shift
    ending (or the sweep) revokes it at once."""
    row = _locked_shift(conn, shift_id)
    if row["state"] != "active":
        raise PolicyViolation(details={"reason": "shift_not_active", "state": row["state"]})
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    minutes = body.minutes or cfg.default_override_minutes
    now = utc_now()
    until = min(now + dt.timedelta(minutes=minutes), row["planned_end"])
    if until <= now:
        raise PolicyViolation(details={"reason": "shift_past_planned_end"})
    override_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO shift_overrides (id, society_id, shift_id, gate_id, granted_by, reason, valid_until) VALUES"
                " (:id, :s, :sh, :g, :by, :why, :until)"
            ),
            {
                "id": override_id, "s": ctx.society_id, "sh": shift_id, "g": row["gate_id"], "by": ctx.person_id,
                "why": body.reason, "until": until,
            },
        )  # fmt: skip
        return MutationResult(
            override_id, 1, after={"shift_id": shift_id, "valid_until": until},
            event_payload={"override_id": override_id, "shift_id": shift_id, "gate_id": row["gate_id"], "valid_until": until},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="shift.override_grant", object_type="shift_override", event_type="SupervisorOverrideGranted",
        apply=apply, reason=body.reason,
    )  # fmt: skip
    return {
        "id": override_id,
        "shift_id": shift_id,
        "gate_id": row["gate_id"],
        "valid_until": until,
        "expires": "at the earlier of valid_until and the end of the shift",
    }


def active_override(
    conn: Connection, gate_id: uuid.UUID, now: dt.datetime | None = None
) -> dict[str, Any] | None:
    """The supervisor override in force at a gate right now, or None. An override whose shift ended is never in force."""
    moment = now or utc_now()
    row = (
        conn.execute(
            text(
                "SELECT o.id, o.shift_id, o.valid_until FROM shift_overrides o JOIN shifts s ON s.society_id = o.society_id"
                " AND s.id = o.shift_id WHERE o.gate_id = :g AND o.revoked_at IS NULL AND o.valid_until > :now"
                " AND s.state = 'active' ORDER BY o.valid_until DESC, o.id LIMIT 1"
            ),
            {"g": gate_id, "now": moment},
        )
        .mappings()
        .first()
    )
    return None if row is None else dict(row)


def scope_is_supervisor(scope: Scope) -> bool:
    return scope.role in SUPERVISOR_ROLES
