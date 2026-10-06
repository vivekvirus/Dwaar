"""Shifts: guard language and training, six guard shifts with checklists, an acknowledged handover, an escalated one, an active shift.

REQ: SHIFT-01 (start and end checklists; both guards or the supervisor acknowledge; a missing next guard escalates), SHIFT-02 (open items),
UX-08 (guard language per guard), UX-09 (training completion per guard per scenario, practice mode), PRD 8.3 seed dataset (slice 4 part).

SIX guard shifts appear: Sahyadri (MH) has four (the day shift ends and hands over to the night guard who is already on duty: signed by BOTH
guards; the night shift ends with nobody to take over: the sweep escalates it and the supervisor signs; today's day shift is active; tonight's is
scheduled) and Nandana (KA) has two (yesterday's shift ended with nobody taking over and the handover is left ESCALATED; today's is active).

Honest limits: ``started_at`` / ``ended_at`` are the moments of the seeding run (the service stamps the database clock); only the PLANNED windows
tell the story of yesterday and today. A society that already has shifts at its gate is left alone, which makes a second run change nothing.
Kannada is M2 (UX-08): the Karnataka guard's profile language is English although the person's own language is Kannada.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from zoneinfo import ZoneInfo

from sqlalchemy import text

from dwaar_common.timeutil import utc_now

from ...modules.shifts import jobs, service
from ...modules.shifts.schemas import EndChecklist, ProfilePut, ShiftCreate, StartChecklist
from ..runtime import SeedContext, SocietyRef

NAME = "shifts"
ORDER = 490
IST = ZoneInfo("Asia/Kolkata")


@dataclass(frozen=True)
class ProfileSpec:
    person: str
    language: str
    completed: tuple[str, ...]


PROFILES: dict[str, tuple[ProfileSpec, ...]] = {
    "mh": (
        ProfileSpec(
            "mh.guard1", "mr", ("guest_entry", "delivery_entry", "parcel_receive", "shift_handover")
        ),
        ProfileSpec("mh.guard2", "hi", ("guest_entry", "staff_checkin")),
        ProfileSpec("mh.guard_sup", "mr", ("guest_entry", "emergency_entry", "incident_report")),
    ),
    "ka": (ProfileSpec("ka.guard1", "en", ("guest_entry",)), ProfileSpec("ka.guard_sup", "en", ())),
}
GATES = {"mh": "Main Gate", "ka": "Tower Gate"}


def _day(offset_days: int, hour: int) -> dt.datetime:
    today = dt.datetime.now(IST).replace(hour=0, minute=0, second=0, microsecond=0)
    return (today + dt.timedelta(days=offset_days, hours=hour)).astimezone(dt.UTC)


def _on_duty_start() -> dt.datetime:
    """The start of the shift that is ON DUTY now: three hours ago, on the hour, so its planned end (14 h later) is always in the future whatever the time
    of day the seed runs (a calendar-day shift would already be over in the evening: an active shift past its planned end is not a believable demo and
    cannot take a supervisor override)."""
    return utc_now().replace(minute=0, second=0, microsecond=0) - dt.timedelta(hours=3)


def _profiles(ctx: SeedContext, key: str, soc: SocietyRef) -> None:
    actor = ctx.person(f"{key}.secretary")
    for spec in PROFILES[key]:
        pid = ctx.person(spec.person)
        with ctx.tx(f"shifts:profile-read:{spec.person}", society=soc.id, role="seed") as (
            conn,
            _c,
        ):
            known = conn.execute(
                text("SELECT 1 FROM guard_profiles WHERE person_id = :p"), {"p": pid}
            ).first()
            done = {
                r[0]
                for r in conn.execute(
                    text(
                        "SELECT scenario_type FROM guard_training_completions WHERE person_id = :p"
                    ),
                    {"p": pid},
                )
            }
        if known is None:
            with ctx.tx(
                f"shifts:profile:{spec.person}", society=soc.id, person=actor, role="secretary"
            ) as (conn, rctx):
                service.put_profile(conn, rctx, pid, ProfilePut(language=spec.language))
            ctx.count("guard_profiles_created")
        for scenario in spec.completed:
            if scenario in done:
                continue
            with ctx.tx(
                f"shifts:training:{spec.person}:{scenario}",
                society=soc.id,
                person=pid,
                role="guard",
            ) as (conn, rctx):
                service.record_training(conn, rctx, pid, scenario)
            ctx.count("training_completions_created")


def _create(
    ctx: SeedContext,
    soc: SocietyRef,
    sup: uuid.UUID,
    gate: uuid.UUID,
    guard: uuid.UUID,
    start: dt.datetime,
    hours: int,
    tag: str,
) -> uuid.UUID:
    with ctx.tx(f"shifts:create:{tag}", society=soc.id, person=sup, role="guard_sup") as (
        conn,
        rctx,
    ):
        view = service.create_shift(
            conn,
            rctx,
            ShiftCreate(
                gate_id=gate,
                guard_id=guard,
                planned_start=start,
                planned_end=start + dt.timedelta(hours=hours),
            ),
        )
    ctx.count("shifts_created")
    return uuid.UUID(str(view["id"]))


def _start(
    ctx: SeedContext,
    soc: SocietyRef,
    guard: uuid.UUID,
    shift: uuid.UUID,
    tag: str,
    body: StartChecklist,
) -> None:
    with ctx.tx(f"shifts:start:{tag}", society=soc.id, person=guard, role="guard") as (conn, rctx):
        service.start_shift(conn, rctx, shift, body)


def _end(
    ctx: SeedContext, soc: SocietyRef, guard: uuid.UUID, shift: uuid.UUID, tag: str, counted: int
) -> uuid.UUID:
    with ctx.tx(f"shifts:end:{tag}", society=soc.id, person=guard, role="guard") as (conn, rctx):
        out = service.end_shift(
            conn, rctx, shift, EndChecklist(parcels_counted=counted, inside_records_reviewed=True)
        )
    return uuid.UUID(str(out["handover"]["id"]))


def _ack(
    ctx: SeedContext, soc: SocietyRef, who: uuid.UUID, role: str, handover: uuid.UUID, tag: str
) -> None:
    with ctx.tx(f"shifts:ack:{tag}", society=soc.id, person=who, role=role) as (conn, rctx):
        service.acknowledge(conn, rctx, handover, None)


def _parcels_held(ctx: SeedContext, soc: SocietyRef, tag: str) -> int:
    with ctx.tx(f"shifts:parcels:{tag}", society=soc.id, role="seed") as (conn, _c):
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM parcels WHERE state IN ('received_at_gate', 'stored', 'pickup_pending', 'refused')"
                )
            ).scalar_one()
        )


def _escalate(ctx: SeedContext, soc: SocietyRef, tag: str) -> None:
    with ctx.tx(f"shifts:escalate:{tag}", society=soc.id, role="system") as (conn, rctx):
        jobs.escalate_unacknowledged(conn, rctx, now=utc_now() + dt.timedelta(hours=1))


def _mh(ctx: SeedContext, soc: SocietyRef, gate: uuid.UUID) -> None:
    g1, g2, sup = ctx.person("mh.guard1"), ctx.person("mh.guard2"), ctx.person("mh.guard_sup")
    held = _parcels_held(ctx, soc, "mh")
    ok = StartChecklist(
        battery_percent=88, network="ok", relay_health="ok", sensor_health="ok", keys_count=3
    )
    # 1 + 2: the day shift hands over to the night guard, who is already on duty: BOTH guards sign
    day = _create(ctx, soc, sup, gate, g1, _day(-1, 6), 8, "mh-day-1")
    night = _create(ctx, soc, sup, gate, g2, _day(-1, 14), 8, "mh-night-1")
    _start(ctx, soc, g1, day, "mh-day-1", ok)
    _start(
        ctx,
        soc,
        g2,
        night,
        "mh-night-1",
        StartChecklist(
            battery_percent=64,
            network="ok",
            relay_health="ok",
            sensor_health="unknown",
            keys_count=3,
        ),
    )
    handover = _end(ctx, soc, g1, day, "mh-day-1", held)
    _ack(ctx, soc, g1, "guard", handover, "mh-day-1-out")
    _ack(ctx, soc, g2, "guard", handover, "mh-day-1-in")
    ctx.count("handovers_signed")
    # the night shift ends with nobody to take over: escalated, then the supervisor signs
    late = _end(ctx, soc, g2, night, "mh-night-1", held)
    _escalate(ctx, soc, "mh")
    _ack(ctx, soc, sup, "guard_sup", late, "mh-night-1-sup")
    ctx.count("handovers_escalated")
    # 3: the day shift is on duty now; 4: the next one is scheduled after it
    on_duty = _on_duty_start()
    today = _create(ctx, soc, sup, gate, g1, on_duty, 14, "mh-day-2")
    _start(
        ctx,
        soc,
        g1,
        today,
        "mh-day-2",
        StartChecklist(
            battery_percent=91, network="ok", relay_health="ok", sensor_health="ok", keys_count=3
        ),
    )
    _create(ctx, soc, sup, gate, g2, on_duty + dt.timedelta(hours=14), 8, "mh-night-2")


def _ka(ctx: SeedContext, soc: SocietyRef, gate: uuid.UUID) -> None:
    g1, sup = ctx.person("ka.guard1"), ctx.person("ka.guard_sup")
    held = _parcels_held(ctx, soc, "ka")
    yesterday = _create(ctx, soc, sup, gate, g1, _day(-1, 8), 8, "ka-day-1")
    _start(
        ctx,
        soc,
        g1,
        yesterday,
        "ka-day-1",
        StartChecklist(
            battery_percent=72, network="degraded", relay_health="ok", sensor_health="ok"
        ),
    )
    _end(ctx, soc, g1, yesterday, "ka-day-1", held)
    _escalate(
        ctx, soc, "ka"
    )  # nobody took over and nobody signed: the handover stays ESCALATED, which is the point of this row
    ctx.count("handovers_escalated")
    today = _create(ctx, soc, sup, gate, g1, _on_duty_start(), 14, "ka-day-2")
    _start(
        ctx,
        soc,
        g1,
        today,
        "ka-day-2",
        StartChecklist(battery_percent=95, network="ok", relay_health="ok", sensor_health="ok"),
    )


def run(ctx: SeedContext) -> None:
    for key in ("mh", "ka"):
        soc = ctx.society(key)
        with ctx.tx(f"shifts:gate:{key}", society=soc.id, role="seed") as (conn, _c):
            row = conn.execute(
                text("SELECT id FROM gates WHERE lower(name) = lower(:n)"), {"n": GATES[key]}
            ).first()
            has_shifts = conn.execute(text("SELECT 1 FROM shifts LIMIT 1")).first() is not None
        if row is None:
            ctx.say(
                f"  shifts: no gate {GATES[key]!r} in {key} (the visits step has not run): skipped"
            )
            continue
        _profiles(ctx, key, soc)
        if has_shifts:
            continue
        (_mh if key == "mh" else _ka)(ctx, soc, row[0])
    ctx.say(
        "  shifts: 6 guard shifts (signed, escalated, active, scheduled), guard languages, training completions"
    )
