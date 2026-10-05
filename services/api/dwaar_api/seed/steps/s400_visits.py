"""Visits and gate: gates, lanes, devices, passes, a pending request, a completed visit, an overstay, a denied request.

REQ: GATE-01 (invitations with explicit windows, a revoked pass), GATE-02 (a pending request), GATE-03/INV-07 (a completed
visit: approval, observed entry, observed exit), GATE-08 (a phone-free pass), GATE-11 (an overstay exception), SOC-05 (devices:
requested by a guard, approved by the supervisor; one left pending), PRD 8.3 seed dataset (slice 2 part).

Everything goes through the module's SERVICE functions as ``dwaar_app`` with the RLS context of the real actor (guard,
guard supervisor, secretary, resident), so each row has its audit and outbox record, and a second run changes nothing (every
object is looked up by its natural key first). Ids are deterministic; times are relative to the moment of the first seed
run (a pass window cannot be anything else). Cryptographic nonces and 6-digit codes are random by design.

Honest limits of the demonstrator data
--------------------------------------
* The pending request keeps the policy's 90 seconds: a minute and a half after seeding it reads as ``expired`` (lazy expiry),
  exactly as in production. Raise a fresh one from the guard terminal to demo the household decision.
* The overstay story needs a delivery that entered more than 20 minutes ago. The seed enters the visitor through the normal
  observation path and then SHIFTS the visit's authorisation/entry times back by 35 minutes in one audited write
  (``visit.seed_timeline_shift``): a synthetic timeline, never done by the API.
* Delegation of the household approval to the owner's family members (A-203) is a flag on the membership
  (``is_primary_approver``); no API sets it yet, so the seed does it through an audited mutation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Connection, text

from dwaar_common.signing import public_key_to_b64
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope, ScopeKind
from ...modules.visits import approvals, gates, invitations, visits
from ...modules.visits import policy as policy_mod
from ...modules.visits.config import VisitsConfig
from ...modules.visits.schemas import (
    ApprovalRequestCreate,
    DecisionIn,
    DeviceDecision,
    DeviceEnrol,
    GateCreate,
    InvitationCreate,
    LaneCreate,
    ObservationIn,
    VisitorNotice,
    Window,
)
from ..ids import scoped_uuid
from ..runtime import SeedContext, SocietyRef

NAME = "visits"
ORDER = 400


@dataclass(frozen=True)
class GateSpec:
    name: str
    kind: str
    lanes: tuple[tuple[str, str], ...]
    device: str
    approve_device: bool


@dataclass(frozen=True)
class PassSpec:
    host: str
    block: str
    label: str
    purpose: str
    alias: str
    kind: str
    windows: str  # "evening" | "mornings" | "later"
    max_uses: int = 1
    with_code: bool = True
    revoke: bool = False
    plate: str | None = None


@dataclass(frozen=True)
class SocietyPlan:
    society: str
    guard: str
    supervisor: str
    secretary: str
    gates: tuple[GateSpec, ...]
    passes: tuple[PassSpec, ...]
    delegated: tuple[
        tuple[str, str, str], ...
    ] = ()  # (person key, block, label) family members who may decide
    visits: tuple[str, ...] = field(default=())  # which demo flows to run


PLANS: tuple[SocietyPlan, ...] = (
    SocietyPlan(
        "mh", "mh.guard1", "mh.guard_sup", "mh.secretary",
        (
            GateSpec("Main Gate", "mixed", (("Entry lane", "in"), ("Exit lane", "out")), "Main gate terminal", True),
            GateSpec("Pedestrian Gate", "pedestrian", (("Turnstile", "both"),), "Pedestrian gate handheld", False),
        ),
        (
            PassSpec("ganesh", "A", "203", "Family dinner", "Aunt Sulabha", "guest", "evening", plate="MH 12 AB 4321"),
            PassSpec("rekha", "A", "203", "Daily milk delivery", "Milk vendor", "vendor", "mornings", 7, with_code=False),
            PassSpec("ganesh", "A", "203", "Plumber visit (plan changed)", "Plumber", "service", "later", revoke=True),
            PassSpec("priya", "B", "205", "Friend visiting (no phone)", "Anjali", "guest", "evening"),
        ),
        (("rekha", "A", "203"), ("aarav", "A", "203")),
        ("completed", "overstay", "denied", "pending"),
    ),
    SocietyPlan(
        "ka", "ka.guard1", "ka.guard_sup", "ka.secretary",
        (GateSpec("Tower Gate", "mixed", (("Gate lane", "both"),), "Tower gate terminal", True),),
        (PassSpec("farhan", "Tower 1", "101", "Courier pickup", "Courier", "delivery", "evening", with_code=False),),
    ),
)  # fmt: skip


# ------------------------------------------------------------------------------------------ helpers
def _device_key(label: str) -> str:
    """A deterministic PUBLIC key for a demo device (the private half is derived from a label and thrown away)."""
    seed = hashlib.sha256(b"dwaar-seed-device|" + label.encode()).digest()
    return public_key_to_b64(Ed25519PrivateKey.from_private_bytes(seed).public_key())


def _windows(kind: str) -> list[Window]:
    now = utc_now().replace(minute=0, second=0, microsecond=0)
    if kind == "mornings":
        # seven short, explicit morning windows (a recurring pass is never an open-ended code)
        start = now + dt.timedelta(days=1)
        first = start.replace(hour=0) + dt.timedelta(hours=0, minutes=30)  # ~06:00 IST (00:30 UTC)
        return [
            Window(start=first + dt.timedelta(days=i), end=first + dt.timedelta(days=i, hours=1))
            for i in range(7)
        ]
    if kind == "later":
        return [Window(start=now + dt.timedelta(days=2), end=now + dt.timedelta(days=2, hours=4))]
    return [Window(start=now - dt.timedelta(minutes=5), end=now + dt.timedelta(days=1, hours=4))]


def _scope(sid: uuid.UUID, role: str, unit: uuid.UUID) -> Scope:
    return Scope(
        society_id=sid, role=role, kind=ScopeKind.UNIT, unit_id=unit, unit_ids=frozenset({unit})
    )


def _notice() -> VisitorNotice:
    return VisitorNotice(version="visitor-notice-v1", language="en", consent_given=True)


def _decide(
    ctx: SeedContext, soc: SocietyRef, who: str, role: str, unit: uuid.UUID, request_id: uuid.UUID,
    decision: str, tag: str,
) -> None:  # fmt: skip
    pid = ctx.person(who)
    with ctx.tx(f"visits:decide:{tag}", society=soc.id, person=pid, role=role) as (conn, rctx):
        policy = policy_mod.load_policy(conn)
        body = DecisionIn(
            decision=decision, expected_version=1,
            client_action_id=scoped_uuid(f"visits:action:{tag}"),
        )  # fmt: skip
        approvals.decide(conn, rctx, _scope(soc.id, role, unit), request_id, body, policy)


# ------------------------------------------------------------------------------------------ gates, lanes, devices
def _ensure_gates(
    ctx: SeedContext, plan: SocietyPlan, soc: SocietyRef
) -> dict[str, tuple[uuid.UUID, uuid.UUID | None]]:
    """name -> (gate id, ACTIVE device id or None)."""
    secretary, guard, supervisor = (
        ctx.person(plan.secretary),
        ctx.person(plan.guard),
        ctx.person(plan.supervisor),
    )
    found: dict[str, tuple[uuid.UUID, uuid.UUID | None]] = {}
    for spec in plan.gates:
        with ctx.tx(
            f"visits:gate-read:{plan.society}:{spec.name}", society=soc.id, role="seed"
        ) as (conn, _c):
            row = conn.execute(
                text("SELECT id FROM gates WHERE lower(name) = lower(:n)"), {"n": spec.name}
            ).first()
        if row is None:
            with ctx.tx(
                f"visits:gate:{plan.society}:{spec.name}",
                society=soc.id,
                person=secretary,
                role="secretary",
            ) as (conn, rctx):
                gate = gates.create_gate(
                    conn, rctx, soc.id, GateCreate(name=spec.name, kind=spec.kind)
                )
            gate_id = uuid.UUID(str(gate["id"]))
            ctx.count("gates_created")
        else:
            gate_id = row[0]
        for label, direction in spec.lanes:
            with ctx.tx(
                f"visits:lane-read:{plan.society}:{spec.name}:{label}", society=soc.id, role="seed"
            ) as (conn, _c):
                have = conn.execute(
                    text("SELECT 1 FROM lanes WHERE gate_id = :g AND lower(label) = lower(:l)"),
                    {"g": gate_id, "l": label},
                ).first()
            if have is None:
                with ctx.tx(
                    f"visits:lane:{plan.society}:{spec.name}:{label}",
                    society=soc.id,
                    person=secretary,
                    role="secretary",
                ) as (conn, rctx):
                    gates.create_lane(
                        conn, rctx, soc.id, gate_id, LaneCreate(label=label, direction=direction)
                    )
                ctx.count("lanes_created")
        key = _device_key(f"{plan.society}:{spec.device}")
        with ctx.tx(
            f"visits:device-read:{plan.society}:{spec.device}", society=soc.id, role="seed"
        ) as (conn, _c):
            dev = conn.execute(
                text("SELECT id, state, version FROM devices WHERE public_key = :k"), {"k": key}
            ).first()
        if dev is None:
            with ctx.tx(
                f"visits:device:{plan.society}:{spec.device}",
                society=soc.id,
                person=guard,
                role="guard",
            ) as (conn, rctx):
                created = gates.enrol_device(
                    conn, rctx, soc.id,
                    DeviceEnrol(kind="terminal", name=spec.device, gate_id=gate_id, public_key=key,
                                firmware="demo-0.1", capabilities={"qr": True, "nfc": False}, simulation=True),
                )  # fmt: skip
            device_id, state, version = uuid.UUID(str(created["id"])), "pending_approval", 1
            ctx.count("devices_enrolled")
        else:
            device_id, state, version = dev[0], dev[1], dev[2]
        if spec.approve_device and state == "pending_approval":
            with ctx.tx(
                f"visits:device-approve:{plan.society}:{spec.device}",
                society=soc.id,
                person=supervisor,
                role="guard_sup",
            ) as (conn, rctx):
                gates.decide_device(
                    conn,
                    rctx,
                    device_id,
                    DeviceDecision(decision="approve", expected_version=version),
                )
            state = "active"
            ctx.count("device_approvals_created")
        found[spec.name] = (gate_id, device_id if state == "active" else None)
    return found


# ------------------------------------------------------------------------------------------ delegation, passes
def _delegate(ctx: SeedContext, plan: SocietyPlan, soc: SocietyRef) -> None:
    for who, block, label in plan.delegated:
        pid, unit = ctx.person(who), soc.unit(block, label)
        with ctx.tx(
            f"visits:delegate:{who}:{block}:{label}",
            society=soc.id,
            person=ctx.person(plan.secretary),
            role="secretary",
        ) as (conn, rctx):
            row = conn.execute(
                text(
                    "SELECT id, is_primary_approver, version FROM memberships WHERE person_id = :p AND unit_id = :u"
                    " AND kind = 'family' AND verification = 'verified'"
                ),
                {"p": pid, "u": unit},
            ).first()
            if row is None or row[1]:
                continue

            def apply(c: Connection, row: Any = row) -> MutationResult:
                updated = c.execute(
                    text(
                        "UPDATE memberships SET is_primary_approver = true, version = version + 1 WHERE id = :id RETURNING version"
                    ),
                    {"id": row[0]},
                ).scalar_one()
                return MutationResult(
                    row[0],
                    int(updated),
                    before={"is_primary_approver": False},
                    after={"is_primary_approver": True},
                    event_payload={"membership_id": row[0], "delegated_approver": True},
                )

            mutation(
                conn,
                rctx,
                operation="membership.delegate_approver",
                object_type="membership",
                event_type="MembershipApproverDelegated",
                apply=apply,
                reason="Seed: household approval delegated to family",
            )
        ctx.count("approvers_delegated_created")


def _ensure_passes(ctx: SeedContext, plan: SocietyPlan, soc: SocietyRef, cfg: VisitsConfig) -> None:
    for spec in plan.passes:
        host, unit = ctx.person(spec.host), soc.unit(spec.block, spec.label)
        with ctx.tx(
            f"visits:pass-read:{plan.society}:{spec.purpose}", society=soc.id, role="seed"
        ) as (conn, _c):
            row = conn.execute(
                text(
                    "SELECT id, state FROM invitations WHERE host_person_id = :h AND unit_id = :u AND purpose = :p"
                ),
                {"h": host, "u": unit, "p": spec.purpose},
            ).first()
        if row is None:
            body = InvitationCreate(
                unit_id=unit, kind=spec.kind, purpose=spec.purpose, visitor_alias=spec.alias,
                people_count=2 if spec.kind == "guest" else 1, windows=_windows(spec.windows), max_uses=spec.max_uses,
                vehicle_plate=spec.plate, with_code=spec.with_code,
            )  # fmt: skip
            role = "tenant" if spec.host == "priya" else "owner_occ"
            if spec.host in ("rekha", "aarav"):
                role = "family"
            with ctx.tx(
                f"visits:pass:{plan.society}:{spec.purpose}", society=soc.id, person=host, role=role
            ) as (conn, rctx):
                created = invitations.create_invitation(conn, rctx, cfg, soc.id, body)
            invitation_id, state = uuid.UUID(str(created["id"])), "active"
            ctx.count("invitations_issued")
        else:
            invitation_id, state = row[0], row[1]
        if spec.revoke and state == "active":
            with ctx.tx(
                f"visits:pass-revoke:{plan.society}:{spec.purpose}",
                society=soc.id,
                person=host,
                role="owner_occ",
            ) as (conn, rctx):
                invitations.revoke_invitation(conn, rctx, soc.id, invitation_id)
            ctx.count("invitations_revoked_ended")


# ------------------------------------------------------------------------------------------ demo flows
def _have_visit(ctx: SeedContext, soc: SocietyRef, alias: str) -> bool:
    with ctx.tx(f"visits:visit-read:{alias}", society=soc.id, role="seed") as (conn, _c):
        return (
            conn.execute(
                text("SELECT 1 FROM visits WHERE visitor_alias = :a"), {"a": alias}
            ).first()
            is not None
        )


def _raise_request(
    ctx: SeedContext, plan: SocietyPlan, soc: SocietyRef, gate_id: uuid.UUID, unit: uuid.UUID, alias: str, kind: str, tag: str
) -> dict[str, object]:  # fmt: skip
    guard = ctx.person(plan.guard)
    with ctx.tx(f"visits:request:{tag}", society=soc.id, person=guard, role="guard") as (
        conn,
        rctx,
    ):
        policy = policy_mod.load_policy(conn)
        cfg = VisitsConfig.from_environment(ctx.settings)
        body = ApprovalRequestCreate(
            unit_id=unit, kind=kind, visitor_alias=alias, gate_id=gate_id, destination_confirmed=True,
            notice=_notice(), people_count=1,
        )  # fmt: skip
        out = approvals.create_request(conn, rctx, cfg, soc.id, body, policy)
    ctx.count("requests_opened")
    return out


def _enter(
    ctx: SeedContext,
    plan: SocietyPlan,
    soc: SocietyRef,
    visit_id: uuid.UUID,
    gate_id: uuid.UUID,
    device_id: uuid.UUID,
    seq: int,
    kind: str,
    tag: str,
) -> None:  # noqa: PLR0913
    guard = ctx.person(plan.guard)
    with ctx.tx(f"visits:observe:{tag}:{kind}", society=soc.id, person=guard, role="guard") as (
        conn,
        rctx,
    ):
        body = ObservationIn(
            type=kind, gate_id=gate_id, device_id=device_id, event_id=scoped_uuid(f"visits:event:{tag}:{kind}"),
            seq=seq, occurred_at=utc_now(), clock_uncertainty_ms=50,
            exit_basis="scanned" if kind == "exit" else None, credential_kind="qr" if kind == "exit" else "guard_assisted",
            decision_source="resident_app" if kind == "entry" else "cached_policy",
        )  # fmt: skip
        visits.observe(conn, rctx, soc.id, visit_id, body)
    ctx.count("observations_created")


def _flows(
    ctx: SeedContext, plan: SocietyPlan, soc: SocietyRef, gate: tuple[uuid.UUID, uuid.UUID | None]
) -> None:
    gate_id, device_id = gate
    assert device_id is not None  # noqa: S101 (the main gate's terminal is approved by this step)
    a203, a101, b205 = soc.unit("A", "203"), soc.unit("A", "101"), soc.unit("B", "205")
    seq = 100
    if "completed" in plan.visits and not _have_visit(ctx, soc, "Vikas (cousin)"):
        req = _raise_request(ctx, plan, soc, gate_id, a203, "Vikas (cousin)", "guest", "completed")
        _decide(
            ctx, soc, "ganesh", "owner_occ", a203, uuid.UUID(str(req["id"])), "approve", "completed"
        )
        visit = uuid.UUID(str(req["visit_id"]))
        _enter(ctx, plan, soc, visit, gate_id, device_id, seq + 1, "entry", "completed")
        _enter(ctx, plan, soc, visit, gate_id, device_id, seq + 2, "exit", "completed")
        ctx.count("visits_created")
    if "overstay" in plan.visits and not _have_visit(ctx, soc, "Grocery Basket delivery"):
        req = _raise_request(
            ctx, plan, soc, gate_id, a101, "Grocery Basket delivery", "delivery", "overstay"
        )
        _decide(
            ctx, soc, "neha", "owner_occ", a101, uuid.UUID(str(req["id"])), "approve", "overstay"
        )
        visit = uuid.UUID(str(req["visit_id"]))
        _enter(ctx, plan, soc, visit, gate_id, device_id, seq + 3, "entry", "overstay")
        guard = ctx.person(plan.guard)
        with ctx.tx("visits:overstay-shift", society=soc.id, person=guard, role="guard") as (
            conn,
            rctx,
        ):

            def apply(c: Connection) -> MutationResult:
                version = c.execute(
                    text(
                        "UPDATE visits SET authorised_at = authorised_at - interval '36 minutes',"
                        " entered_at = entered_at - interval '35 minutes', version = version + 1 WHERE id = :id RETURNING version"
                    ),
                    {"id": visit},
                ).scalar_one()
                return MutationResult(
                    visit,
                    int(version),
                    after={"timeline_shift_minutes": 35},
                    event_payload={"visit_id": visit},
                )

            mutation(
                conn,
                rctx,
                operation="visit.seed_timeline_shift",
                object_type="visit",
                event_type="VisitTimelineShifted",
                apply=apply,
                reason="Seed: a delivery that entered 35 minutes ago",
            )
            policy = policy_mod.load_policy(conn)
            visits.detect_overstays(conn, rctx, policy)
        ctx.count("visits_created")
        ctx.count("overstays_opened")
    if "denied" in plan.visits and not _have_visit(ctx, soc, "Unknown sales visitor"):
        req = _raise_request(
            ctx, plan, soc, gate_id, b205, "Unknown sales visitor", "guest", "denied"
        )
        _decide(ctx, soc, "priya", "tenant", b205, uuid.UUID(str(req["id"])), "deny", "denied")
        ctx.count("visits_created")
    if "pending" in plan.visits and not _have_visit(ctx, soc, "Courier parcel"):
        _raise_request(ctx, plan, soc, gate_id, a203, "Courier parcel", "delivery", "pending")
        ctx.count("visits_created")


def run(ctx: SeedContext) -> None:
    cfg = VisitsConfig.from_environment(ctx.settings)
    for plan in PLANS:
        soc = ctx.society(plan.society)
        built = _ensure_gates(ctx, plan, soc)
        _delegate(ctx, plan, soc)
        _ensure_passes(ctx, plan, soc, cfg)
        if plan.visits:
            _flows(ctx, plan, soc, built[plan.gates[0].name])
    ctx.say(
        "  visits: gates, lanes, devices, passes, requests, visits and an overstay seeded"
        f" ({ctx.counts.get('gates_created', 0)} gates, {ctx.counts.get('invitations_issued', 0)} passes this run)"
    )
