"""Staff: a cook with THREE employers (AT-12), a driver with one, consent receipts captured first, a check-in code, attendance.

REQ: STAFF-01 (one person, separate engagements per household), STAFF-02 (attendance observations), STAFF-04 (consent receipt BEFORE any capture),
STAFF-05 (check-in by code), PRIV-04 (an ID is stored masked to its last 4 digits; police verification as a status), PRD 8.3 seed dataset (slice 4).

Honest limit of the demonstrator data: the seeded person count is asserted by ``tests/acceptance/test_seed_dataset.py`` (it equals the number of
people in ``seed/dataset.py``), and that file is not owned by this slice. The staff of this step therefore RE-USE the person rows of the last two
plain owner-occupiers of each society (``mh.bulk35``, ``mh.bulk36``, ``ka.bulk28``): their phone numbers identify the person, while the staff
register carries its own display name (``Sunita Kamble`` ...). When the dataset gains dedicated staff persons, only ``PLANS`` below changes.
Staff names, numbers and the demo check-in codes are invented; the codes are printed by ``python -m dwaar_api.seed`` documentation only here.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import text

from dwaar_common.timeutil import utc_now

from ...modules.staff import attendance, service
from ...modules.staff.schemas import (
    AttendanceCreate,
    ConsentCapture,
    Credential,
    CredentialIssue,
    EngagementCreate,
    IdDocument,
    Schedule,
    StaffRegister,
)
from ..ids import scoped_uuid
from ..people import by_key
from ..runtime import SeedContext, SocietyRef

NAME = "staff_register"
ORDER = 480

ALL_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri")


@dataclass(frozen=True)
class EngagementSpec:
    block: str
    label: str
    employer: str  # person key of the household member who engages
    employer_role: str
    duty: str
    days: tuple[str, ...]
    start: str
    end: str


@dataclass(frozen=True)
class StaffSpec:
    society: str
    person: str  # an existing person row (see the module docstring)
    display_name: str
    staff_type: str
    language: str
    consent_by: str
    id_kind: str | None
    id_number: str | None
    police: str
    code: str
    engagements: tuple[EngagementSpec, ...]


PLANS: tuple[StaffSpec, ...] = (
    StaffSpec(
        "mh",
        "mh.bulk35",
        "Sunita Kamble",
        "cook",
        "mr",
        "mh.secretary",
        "aadhaar",
        "2345 6789 0123",
        "verified",
        "SUNITA01",
        (
            EngagementSpec(
                "A", "203", "ganesh", "owner_occ", "morning cooking", ALL_DAYS, "07:00", "10:00"
            ),
            EngagementSpec(
                "A",
                "101",
                "neha",
                "owner_occ",
                "cooking and cleaning",
                ALL_DAYS[:6],
                "10:30",
                "12:30",
            ),
            EngagementSpec(
                "B", "205", "priya", "tenant", "evening cooking", WEEKDAYS, "17:00", "19:00"
            ),
        ),
    ),
    StaffSpec(
        "mh",
        "mh.bulk36",
        "Raju Pardeshi",
        "driver",
        "hi",
        "mh.secretary",
        "other",
        "MH12 2019 0004567",
        "requested",
        "RAJU0001",
        (
            EngagementSpec(
                "A", "402", "sanjay", "owner_occ", "family driver", ALL_DAYS[:6], "08:00", "20:00"
            ),
        ),
    ),
    StaffSpec(
        "ka",
        "ka.bulk28",
        "Lakshmi Naik",
        "cook",
        "kn",
        "ka.secretary",
        None,
        None,
        "not_recorded",
        "LAKSHMI1",
        (
            EngagementSpec(
                "Tower 1", "101", "farhan", "owner_occ", "cooking", ALL_DAYS, "07:00", "09:00"
            ),
        ),
    ),
)


def _staff_id(ctx: SeedContext, soc: SocietyRef, person_id: uuid.UUID) -> uuid.UUID | None:
    with ctx.tx(f"staff:read:{person_id}", society=soc.id, role="seed") as (conn, _c):
        row = conn.execute(
            text("SELECT id FROM staff WHERE person_id = :p"), {"p": person_id}
        ).first()
    return None if row is None else row[0]


def _register(ctx: SeedContext, spec: StaffSpec, soc: SocietyRef) -> uuid.UUID:
    secretary = ctx.person(spec.consent_by)
    purposes = ["engagement_record", "attendance", "photo", "police_verification_status"]
    if spec.id_kind:
        purposes.append("id_capture")
    with ctx.tx(
        f"staff:consent:{spec.person}", society=soc.id, person=secretary, role="secretary"
    ) as (conn, rctx):
        consent = service.capture_consent(
            conn, rctx,
            ConsentCapture(
                language=spec.language, notice_version="staff-notice-v1", purposes=purposes,
                staff_action_recorded=True, notice_read_aloud=True,
            ),
        )  # fmt: skip
    ctx.count("staff_consents_created")
    phone = by_key()[spec.person].phone
    with ctx.tx(
        f"staff:register:{spec.person}", society=soc.id, person=secretary, role="secretary"
    ) as (conn, rctx):
        created = service.register_staff(
            conn, rctx, ctx.config,
            StaffRegister(
                consent_id=consent["id"], display_name=spec.display_name, phone=phone, staff_type=spec.staff_type,
                id_document=IdDocument(kind=spec.id_kind, number=spec.id_number) if spec.id_kind and spec.id_number else None,
                police_verification_status=spec.police,
            ),
        )  # fmt: skip
    ctx.count("staff_created")
    staff_id = created["id"]
    with ctx.tx(
        f"staff:credential:{spec.person}", society=soc.id, person=secretary, role="secretary"
    ) as (conn, rctx):
        service.issue_credential(
            conn, rctx, ctx.config, staff_id, CredentialIssue(kind="code", expected_version=int(created["version"])),
            fixed_secret=spec.code,
        )  # fmt: skip
    return uuid.UUID(str(staff_id))


def _engage(ctx: SeedContext, spec: StaffSpec, soc: SocietyRef, staff_id: uuid.UUID) -> None:
    now = utc_now()
    for e in spec.engagements:
        unit = soc.unit(e.block, e.label)
        with ctx.tx(f"staff:eng-read:{staff_id}:{unit}", society=soc.id, role="seed") as (conn, _c):
            have = conn.execute(
                text("SELECT 1 FROM staff_engagements WHERE staff_id = :s AND unit_id = :u"),
                {"s": staff_id, "u": unit},
            ).first()
        if have is not None:
            continue
        with ctx.tx(
            f"staff:eng:{staff_id}:{unit}",
            society=soc.id,
            person=ctx.person(e.employer),
            role=e.employer_role,
        ) as (conn, rctx):
            service.create_engagement(
                conn, rctx,
                EngagementCreate(
                    staff_id=staff_id, unit_id=unit, duty=e.duty,
                    schedule=Schedule(days=list(e.days), **{"from": e.start}, to=e.end),
                ),
                at=now,
            )  # fmt: skip
        ctx.count("engagements_created")


def _attendance(ctx: SeedContext, spec: StaffSpec, soc: SocietyRef) -> None:
    guard = ctx.person(f"{spec.society}.guard1")
    when = utc_now() - dt.timedelta(minutes=30)
    for direction, minutes in (("in", 0), ("out", 12)):
        cid = scoped_uuid(f"staff:attendance:{spec.person}:{direction}")
        with ctx.tx(
            f"staff:attendance:{spec.person}:{direction}",
            society=soc.id,
            person=guard,
            role="guard",
        ) as (conn, rctx):
            before = conn.execute(
                text("SELECT count(*) FROM attendance_events WHERE client_event_id = :c"),
                {"c": cid},
            ).scalar_one()
            attendance.record(
                conn, rctx, ctx.config,
                AttendanceCreate(
                    credential=Credential(kind="code", value=spec.code), direction=direction,
                    client_event_id=cid, occurred_at=when + dt.timedelta(minutes=minutes),
                ),
                now=utc_now(),
            )  # fmt: skip
        if not before:
            ctx.count("attendance_created")


def run(ctx: SeedContext) -> None:
    for spec in PLANS:
        soc = ctx.society(spec.society)
        person_id = ctx.person(spec.person)
        staff_id = _staff_id(ctx, soc, person_id) or _register(ctx, spec, soc)
        _engage(ctx, spec, soc, staff_id)
        _attendance(ctx, spec, soc)
    ctx.say(
        "  staff: a cook with three employers, a driver, a cook in the second society; consent first, masked ID, check-in codes"
    )
