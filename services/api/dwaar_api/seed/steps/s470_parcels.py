"""Parcels: a pre-approval, parcels at the gate and in storage, one awaiting pickup, one collected on a supervised alternate proof, one refused and
returned, a courier claim kept apart from custody, and a custody report.

REQ: PAR-01 (brand + window pre-approval), PAR-02 (states and custody chain), PAR-03 (single-use token; supervised alternate proof), PAR-04 (a
courier's "delivered" claim is an external observation), PAR-05 (custody report), PRD 8.3 seed dataset (slice 4 part).

Everything goes through the module's SERVICE functions as ``dwaar_app`` with the RLS context of the real actor (guard, supervisor, household), so
every row has its audit and outbox record. Parcels are looked up by (unit, carrier reference) first, so a second run changes nothing. Times are
relative to the moment of the first run.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import text

from dwaar_common.timeutil import utc_now

from ...core.authz import Scope, ScopeKind
from ...modules.parcels import service
from ...modules.parcels.schemas import (
    AlternateProof,
    Collector,
    CourierClaim,
    CustodyReportCreate,
    ExpectationCreate,
    ParcelCollect,
    ParcelReceive,
    ParcelResolve,
    ParcelStore,
)
from ..runtime import SeedContext, SocietyRef

NAME = "parcels"
ORDER = 470


@dataclass(frozen=True)
class ParcelSpec:
    ref: str  # the carrier reference doubles as the natural key
    brand: str
    carrier: str
    block: str
    label: str
    owner: str  # person key of the household member
    owner_role: str
    journey: str  # received | stored | pickup_pending | collected_alt | refused_returned


PLANS: dict[str, tuple[str, str, str, tuple[ParcelSpec, ...]]] = {
    "mh": (
        "mh.guard1", "mh.guard_sup", "Main Gate",
        (
            ParcelSpec("SEED-P2", "Bluecart", "Bluefleet", "A", "101", "neha", "owner_occ", "stored"),
            ParcelSpec("SEED-P3", "Meesho Mart", "Swiftpost", "B", "205", "priya", "tenant", "pickup_pending"),
            ParcelSpec("SEED-P4", "Pharma Direct", "Bluefleet", "A", "402", "sanjay", "owner_occ", "collected_alt"),
            ParcelSpec("SEED-P5", "Gadgetly", "Swiftpost", "A", "203", "ganesh", "owner_occ", "refused_returned"),
            ParcelSpec("SEED-P6", "Books Corner", "Bluefleet", "A", "101", "neha", "owner_occ", "received"),
        ),
    ),
    "ka": (
        "ka.guard1", "ka.guard_sup", "Tower Gate",
        (ParcelSpec("SEED-K1", "Groceries Now", "Swiftpost", "Tower 1", "101", "farhan", "owner_occ", "stored"),),
    ),
}  # fmt: skip


def _scope(sid: uuid.UUID, role: str, unit: uuid.UUID) -> Scope:
    return Scope(
        society_id=sid, role=role, kind=ScopeKind.UNIT, unit_id=unit, unit_ids=frozenset({unit})
    )


def _parcel(
    ctx: SeedContext, soc: SocietyRef, unit: uuid.UUID, ref: str
) -> dict[str, object] | None:
    with ctx.tx(f"parcels:read:{ref}", society=soc.id, role="seed") as (conn, _c):
        row = conn.execute(
            text("SELECT id, state, version FROM parcels WHERE unit_id = :u AND carrier_ref = :r"),
            {"u": unit, "r": ref},
        ).first()
    return None if row is None else {"id": row[0], "state": row[1], "version": row[2]}


def _version(ctx: SeedContext, soc: SocietyRef, parcel_id: object) -> int:
    with ctx.tx(f"parcels:version:{parcel_id}", society=soc.id, role="seed") as (conn, _c):
        return int(
            conn.execute(
                text("SELECT version FROM parcels WHERE id = :i"), {"i": parcel_id}
            ).scalar_one()
        )


def _run_journey(
    ctx: SeedContext,
    soc: SocietyRef,
    spec: ParcelSpec,
    gate: uuid.UUID,
    guard: uuid.UUID,
    sup: uuid.UUID,
) -> None:
    unit = soc.unit(spec.block, spec.label)
    owner = ctx.person(spec.owner)
    with ctx.tx(f"parcels:receive:{spec.ref}", society=soc.id, person=guard, role="guard") as (
        conn,
        rctx,
    ):
        view = service.receive(
            conn, rctx,
            ParcelReceive(unit_id=unit, gate_id=gate, brand=spec.brand, carrier=spec.carrier, carrier_ref=spec.ref),
        )  # fmt: skip
    parcel_id = view["id"]
    ctx.count("parcels_created")
    if spec.journey == "received":
        return
    if spec.journey == "refused_returned":
        with ctx.tx(f"parcels:refuse:{spec.ref}", society=soc.id, person=guard, role="guard") as (
            conn,
            rctx,
        ):
            refused = service.resolve(
                conn, rctx, parcel_id,
                ParcelResolve(outcome="refused", note="Recipient refused: ordered by mistake", expected_version=_version(ctx, soc, parcel_id)),
                may_declare_lost=False,
            )  # fmt: skip
        with ctx.tx(f"parcels:return:{spec.ref}", society=soc.id, person=guard, role="guard") as (
            conn,
            rctx,
        ):
            service.resolve(
                conn, rctx, parcel_id,
                ParcelResolve(outcome="returned", note="Handed back to the carrier's rider", expected_version=int(refused["version"])),
                may_declare_lost=False,
            )  # fmt: skip
        return
    with ctx.tx(f"parcels:store:{spec.ref}", society=soc.id, person=guard, role="guard") as (
        conn,
        rctx,
    ):
        stored = service.store(
            conn, rctx, parcel_id,
            ParcelStore(bin_code="B-01", expected_version=_version(ctx, soc, parcel_id)),
        )  # fmt: skip
    if spec.journey == "stored":
        return
    if spec.journey == "pickup_pending":
        with ctx.tx(
            f"parcels:token:{spec.ref}", society=soc.id, person=owner, role=spec.owner_role
        ) as (conn, rctx):
            service.issue_pickup_token(
                conn, rctx, _scope(soc.id, spec.owner_role, unit), parcel_id, int(stored["version"])
            )
        return
    if spec.journey == "collected_alt":
        with ctx.tx(
            f"parcels:collect:{spec.ref}", society=soc.id, person=sup, role="guard_sup"
        ) as (conn, rctx):
            service.collect(
                conn, rctx, _scope(soc.id, "guard_sup", unit), parcel_id,
                ParcelCollect(
                    method="alternate_proof", collector=Collector(kind="recipient"),
                    alternate_proof=AlternateProof(kind="photo_id_checked", note="Seed: ID card shown at the desk, name matches"),
                ),
                supervised_roles=frozenset({"guard_sup"}),
            )  # fmt: skip


def _expectation_and_claim(ctx: SeedContext, soc: SocietyRef, guard: uuid.UUID) -> None:
    unit = soc.unit("A", "203")
    owner = ctx.person("ganesh")
    with ctx.tx("parcels:expect-read", society=soc.id, role="seed") as (conn, _c):
        known = conn.execute(
            text(
                "SELECT id FROM parcels WHERE unit_id = :u AND state IN ('expected', 'received_at_gate') AND brand = 'Zomart' AND expected_by = :o"
            ),
            {"u": unit, "o": owner},
        ).first()
    if known is not None:
        return
    now = utc_now()
    with ctx.tx("parcels:expect", society=soc.id, person=owner, role="owner_occ") as (conn, rctx):
        view = service.create_expectation(
            conn, rctx,
            ExpectationCreate(unit_id=unit, brand="Zomart", expected_from=now - dt.timedelta(hours=1), expected_until=now + dt.timedelta(hours=8), carrier="Zomart riders"),
            now=now,
        )  # fmt: skip
    ctx.count("parcels_created")
    with ctx.tx("parcels:claim", society=soc.id, person=guard, role="guard") as (conn, rctx):
        service.record_courier_claim(
            conn, rctx, view["id"],
            CourierClaim(source="courier_app", claim="delivered", claimed_at=now, external_ref="SEED-EXT-1"),
        )  # fmt: skip
    ctx.count("courier_claims_created")


def _report(ctx: SeedContext, soc: SocietyRef, guard: uuid.UUID, gate: uuid.UUID) -> None:  # noqa: ARG001
    with ctx.tx(f"parcels:report-read:{soc.key}", society=soc.id, role="seed") as (conn, _c):
        if conn.execute(text("SELECT 1 FROM parcel_custody_reports LIMIT 1")).first() is not None:
            return
        held = int(
            conn.execute(
                text(
                    "SELECT count(*) FROM parcels WHERE state IN ('received_at_gate', 'stored', 'pickup_pending', 'refused')"
                )
            ).scalar_one()
        )
    with ctx.tx(f"parcels:report:{soc.key}", society=soc.id, person=guard, role="guard") as (
        conn,
        rctx,
    ):
        service.create_custody_report(
            conn,
            rctx,
            CustodyReportCreate(physical_count=held, note="Seed: physical count matches"),
        )
    ctx.count("custody_reports_created")


def run(ctx: SeedContext) -> None:
    for key, (guard_key, sup_key, gate_name, specs) in PLANS.items():
        soc = ctx.society(key)
        guard, sup = ctx.person(guard_key), ctx.person(sup_key)
        with ctx.tx(f"parcels:gate:{key}", society=soc.id, role="seed") as (conn, _c):
            row = conn.execute(
                text("SELECT id FROM gates WHERE lower(name) = lower(:n)"), {"n": gate_name}
            ).first()
        if row is None:
            ctx.say(
                f"  parcels: no gate {gate_name!r} in {key} (the visits step has not run): skipped"
            )
            continue
        gate = row[0]
        for spec in specs:
            if _parcel(ctx, soc, soc.unit(spec.block, spec.label), spec.ref) is None:
                _run_journey(ctx, soc, spec, gate, guard, sup)
        if key == "mh":
            _expectation_and_claim(ctx, soc, guard)
        _report(ctx, soc, guard, gate)
    ctx.say(
        "  parcels: expectation, courier claim, stored / pending / collected / returned parcels, custody report"
    )
