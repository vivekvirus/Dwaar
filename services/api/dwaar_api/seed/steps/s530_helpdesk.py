"""Helpdesk: emergency procedures, tickets in several states, a common-area duplicate, an emergency, a UX-07 support issue.

REQ: OPS-01 (states and clocks), OPS-02 (private household / society scope, a duplicate PROPOSED), OPS-04 (a resolved and closed
ticket), OPS-09 (the society's emergency procedure and an unsafe lift observation routed to a contractor), UX-07 (the tenant whose
membership is DISPUTED raises a support issue), PRD 8.3 seed dataset (slice 4 part).

Everything goes through the module's SERVICE functions as ``dwaar_app`` with the RLS context of the real actor (resident, secretary),
so each row has its audit and outbox record, and a second run changes nothing (every ticket is found by raiser and title first).
Ids are deterministic. The procedures and contacts are INVENTED text and the reserved fictional numbers (+91 99999 00xxx):
nothing here is a real emergency plan, and the product never claims rescue is guaranteed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import text

from ...modules.helpdesk import service
from ...modules.helpdesk import settings as hd_settings
from ...modules.helpdesk.schemas import (
    AssignIn,
    EmergencyProcedureIn,
    Note,
    TicketCreate,
    TransitionIn,
    TriageIn,
)
from ...modules.helpdesk.views import Actor
from ..runtime import SeedContext, SocietyRef

NAME = "helpdesk"
ORDER = 530

_PROCEDURES = {
    "lift": (
        "Lift emergency: use the in-cabin alarm and call the guard room",
        "Stay calm and do not force the doors. Use the intercom or the alarm button. The guard room informs the secretary and the lift contractor. "
        "This is the society's own plan and is not a promise of rescue within any time.",
    ),
    "fire": (
        "Fire: raise the alarm and leave by the stairs",
        "Raise the alarm, leave by the stairs, do not use the lift, assemble at the main gate and tell the guard room. Call the local fire service.",
    ),
    "electrical": (
        "Electrical danger: keep away and call the guard room",
        "Keep people away from sparking or exposed equipment. Do not touch it. The guard room informs the estate manager and the electrical contractor.",
    ),
    "gas": (
        "Gas smell: ventilate, no flames or switches, leave and call",
        "Open windows, do not operate switches or flames, leave the flat and call the gas provider and the guard room.",
    ),
    "general": (
        "Emergency: tell the guard room first",
        "Tell the guard room, follow the guard supervisor's instructions and assemble at the main gate.",
    ),
}
_CONTACTS = {
    "mh": [
        {"role": "Secretary", "name": "Anita Kulkarni", "phone": "+919999901001"},
        {"role": "Guard room", "name": "Main gate", "phone": "+919999901006"},
    ],
    "ka": [{"role": "Secretary", "name": "Meera Joshi", "phone": "+919999901101"}],
}
_CONTRACTORS = {
    "mh": "Sahyadri Lift & Electrical Services (invented)",
    "ka": "Nandana Facility Works (invented)",
}


@dataclass(frozen=True)
class TicketSpec:
    key: str
    who: str
    role: str
    block: str
    label: str
    scope: str
    category: str
    title: str
    description: str
    unsafe: bool = False
    steps: tuple[str, ...] = ()  # manager steps: triage | assign | progress | resolve | confirm


TICKETS: tuple[TicketSpec, ...] = (
    TicketSpec(
        "tap",
        "neha",
        "owner_occ",
        "A",
        "101",
        "private",
        "plumbing",
        "Kitchen tap leaking",
        "The kitchen tap drips all night; the washer may need replacing.",
        steps=("triage", "assign", "progress", "resolve", "confirm"),
    ),
    TicketSpec(
        "seep",
        "ganesh",
        "owner_occ",
        "A",
        "203",
        "private",
        "plumbing",
        "Ceiling seepage in the bedroom",
        "Water marks have appeared on the bedroom ceiling after the rain.",
        steps=("triage", "assign"),
    ),
    TicketSpec(
        "bulb",
        "neha",
        "owner_occ",
        "A",
        "101",
        "society",
        "common_area",
        "Stairwell light flickering on the 3rd floor",
        "The light flickers every evening.",
    ),
    TicketSpec(
        "bulb2",
        "priya",
        "tenant",
        "B",
        "205",
        "society",
        "common_area",
        "Stairwell light flickering on the 3rd floor",
        "Same light as reported earlier.",
    ),
    TicketSpec(
        "lift",
        "neha",
        "owner_occ",
        "A",
        "101",
        "society",
        "lift",
        "Lift B is sparking near the door",
        "Sparks seen at the cabin door and a burning smell on the landing.",
        unsafe=True,
        steps=("assign",),
    ),
)


def _actor(role: str, pid: uuid.UUID, units: tuple[uuid.UUID, ...] = ()) -> Actor:
    return Actor(pid, role, role in {"secretary", "estate_mgr"}, frozenset(units))


def _known(ctx: SeedContext, soc: SocietyRef, pid: uuid.UUID, title: str) -> uuid.UUID | None:
    with ctx.tx(f"helpdesk:read:{pid}:{title}", society=soc.id, role="seed") as (conn, _c):
        row = conn.execute(
            text("SELECT id FROM tickets WHERE raised_by = :p AND title = :t"),
            {"p": pid, "t": title},
        ).first()
    return None if row is None else row[0]


def _procedures(ctx: SeedContext, key: str, soc: SocietyRef) -> None:
    secretary = ctx.person(f"{key}.secretary")
    with ctx.tx(f"helpdesk:proc-read:{key}", society=soc.id, role="seed") as (conn, _c):
        have = set(hd_settings.list_procedures(conn))
    for hazard, (headline, steps) in _PROCEDURES.items():
        if hazard in have:
            continue
        with ctx.tx(
            f"helpdesk:proc:{key}:{hazard}", society=soc.id, person=secretary, role="secretary"
        ) as (conn, rctx):
            hd_settings.put_procedure(
                conn, rctx, hazard,
                EmergencyProcedureIn(headline=headline, steps=steps, contacts=_CONTACTS[key], qualified_contractor=_CONTRACTORS[key]),
            )  # fmt: skip
        ctx.count("procedures_created")


def _tickets(ctx: SeedContext, soc: SocietyRef) -> None:
    secretary = ctx.person("mh.secretary")
    estate = ctx.person("mh.estate_mgr")
    sec = _actor("secretary", secretary)
    for spec in TICKETS:
        pid, unit = ctx.person(spec.who), soc.unit(spec.block, spec.label)
        if _known(ctx, soc, pid, spec.title) is not None:
            continue  # idempotent: a second run changes nothing
        body = TicketCreate(
            scope=spec.scope, unit_id=unit if spec.scope == "private" else None, category=spec.category, title=spec.title,
            description=spec.description, unsafe_observation=spec.unsafe,
        )  # fmt: skip
        resident = _actor(spec.role, pid, (unit,))
        with ctx.tx(f"helpdesk:ticket:{spec.key}", society=soc.id, person=pid, role=spec.role) as (
            conn,
            rctx,
        ):
            ticket_id = service.create_ticket(conn, rctx, resident, body)["ticket"]["id"]
        ctx.count("tickets_created")
        for step in spec.steps:
            who, role = (pid, spec.role) if step == "confirm" else (secretary, "secretary")
            with ctx.tx(f"helpdesk:{spec.key}:{step}", society=soc.id, person=who, role=role) as (
                conn,
                rctx,
            ):
                if step == "triage":
                    service.triage(conn, rctx, sec, ticket_id, TriageIn(note="Seed: triaged"))
                elif step == "assign" and spec.unsafe:
                    service.assign(
                        conn, rctx, sec, ticket_id, AssignIn(contractor_name=_CONTRACTORS["mh"])
                    )
                elif step == "assign":
                    service.assign(conn, rctx, sec, ticket_id, AssignIn(assignee_id=estate))
                elif step == "progress":
                    service.transition(conn, rctx, sec, ticket_id, TransitionIn(to="in_progress"))
                elif step == "resolve":
                    service.transition(conn, rctx, sec, ticket_id, TransitionIn(to="resolved"))
                elif step == "confirm":
                    service.confirm(conn, rctx, resident, ticket_id, Note())


def _support(ctx: SeedContext, soc: SocietyRef) -> None:
    """UX-07: Dev Rane's tenancy is DISPUTED (identity seed); he can still raise a support or privacy issue."""
    from ...modules.helpdesk.schemas import SupportRequestCreate

    dev = ctx.person("dev")
    title = "Please correct my tenancy record and hide my phone number from the directory"
    if _known(ctx, soc, dev, title) is not None:
        return
    unit = soc.unit("A", "305")
    with ctx.tx("helpdesk:support:dev", society=soc.id, person=dev, role="applicant") as (
        conn,
        rctx,
    ):
        service.create_support_request(
            conn, rctx, _actor("applicant", dev, (unit,)), unit,
            SupportRequestCreate(title=title, description="The move-out dispute is open; my contact details should not be shown to other residents."),
        )  # fmt: skip
    ctx.count("support_requests_created")


def run(ctx: SeedContext) -> None:
    for key in ("mh", "ka"):
        _procedures(ctx, key, ctx.society(key))
    soc = ctx.society("mh")
    _tickets(ctx, soc)
    _support(ctx, soc)
    ctx.say(
        "  helpdesk: emergency procedures, tickets (resolved, assigned, common-area duplicate, emergency to a contractor) and a "
        f"disputed-tenancy support issue seeded ({ctx.counts.get('tickets_created', 0)} tickets this run)"
    )
