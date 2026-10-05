"""Residents: owners, non-resident owners, tenants, family, a disputed move-out and a mover (PRD 8.3).

REQ: IAM-01 (a membership names a unit, a kind and dates), IAM-05 (a dispute never removes occupancy), IAM-07 (household
approvals, reasons, ended memberships), IAM-12 (tenant onboarding needs the owner's confirmation; the only exception is a
reasoned waiver when the unit has no effective owner), INV-04 (ownership, occupancy and billing liability are separate
facts: ``lives`` and ``billing_liable`` are different columns).

Every claim goes through ``identity.members`` (``create_membership``, ``advance_case``, ``owner_decide``): applicants apply
for themselves, a DIFFERENT person decides, the tenant waits for the owner. Each phase reads the current state first, so a
re-run (or a run that stopped halfway) continues instead of repeating.

Liability and voting entitlement are only RECORDED by identity (owned by finance and governance, ADR-0011); the seed marks
the verified owner of each unit liable and entitled through an audited mutation because no service owns that write yet.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text

from ...core.audit import MutationResult, mutation
from ...modules.identity import members
from ..dataset import BULK, RESIDENTS, SOCIETIES, Resident, bulk_people
from ..runtime import SeedContext

NAME = "residents"
ORDER = 300


def _find(
    ctx: SeedContext, sid: uuid.UUID, pid: uuid.UUID, unit: uuid.UUID, kind: str
) -> dict[str, Any] | None:
    with ctx.tx(f"m-read:{pid}:{unit}:{kind}", society=sid, role="seed") as (conn, _c):
        row = (
            conn.execute(
                text(
                    "SELECT m.id, m.verification, m.owner_decision, m.ended_at, m.billing_liable,"
                    " (SELECT c.id FROM verification_cases c WHERE c.membership_id = m.id AND c.kind <> 'dispute'"
                    "  ORDER BY c.created_at, c.id LIMIT 1) AS case_id,"
                    " (SELECT c.state FROM verification_cases c WHERE c.membership_id = m.id AND c.kind <> 'dispute'"
                    "  ORDER BY c.created_at, c.id LIMIT 1) AS case_state"
                    " FROM memberships m WHERE m.person_id = :p AND m.unit_id = :u AND m.kind = :k"
                    " ORDER BY m.created_at LIMIT 1"
                ),
                {"p": pid, "u": unit, "k": kind},
            )
            .mappings()
            .first()
        )
    return dict(row) if row else None


def _decider(ctx: SeedContext, r: Resident) -> tuple[uuid.UUID, str]:
    if r.decided_by.startswith("owner:"):
        return ctx.person(r.decided_by.split(":", 1)[1]), "owner"
    return ctx.person(f"{r.society}.secretary"), "secretary"


def apply_resident(ctx: SeedContext, r: Resident) -> None:
    soc = ctx.society(r.society)
    sid = soc.id
    unit = soc.unit(r.block, r.label)
    pid = ctx.person(r.person)
    tag = f"{r.society}:{r.person}:{r.block}:{r.label}:{r.kind}"
    found = _find(ctx, sid, pid, unit, r.kind)
    if found is None:
        evidence = (
            "seed:synthetic-ownership-document"
            if r.kind != "tenant"
            else "seed:synthetic-tenancy-agreement"
        )
        with ctx.tx(f"m-create:{tag}", society=sid, person=pid, role="applicant") as (conn, rctx):
            members.create_membership(
                conn, rctx, person_id=pid, unit_id=unit, kind=r.kind, effective_from=None,
                lives_in_unit=r.lives, evidence_ref=evidence, requested_by=pid,
            )  # fmt: skip
        ctx.count("memberships_created")
        found = _find(ctx, sid, pid, unit, r.kind)
        assert found is not None  # noqa: S101
    else:
        ctx.count("memberships_existing")
    if r.outcome == "pending":
        return
    if r.outcome == "held":
        _place_hold(ctx, r, sid, found["id"], tag)
        return
    case_id, state = found["case_id"], found["case_state"]
    decider, decider_role = _decider(ctx, r)

    def advance(action: str, **extra: Any) -> None:
        with ctx.tx(f"m-{action}:{tag}", society=sid, person=decider, role=decider_role) as (
            conn,
            rctx,
        ):
            members.advance_case(
                conn, rctx, case_id=case_id, action=action, actor=decider, as_applicant=False,
                reason=extra.get("reason"), evidence_ref=None,
                waive_owner_confirmation=bool(extra.get("waive", False)),
            )  # fmt: skip

    if r.outcome == "rejected":
        if state == "requested":
            advance("start_review")
            state = "society_review"
        if state == "society_review":
            advance("reject", reason=r.reason)
            ctx.count("claims_rejected")
        return
    # tenants wait for the owner (IAM-12)
    waive = False
    if r.kind == "tenant" and found["owner_decision"] is None:
        if r.owner_confirms is not None:
            owner = ctx.person(r.owner_confirms)
            with ctx.tx(f"m-owner-confirm:{tag}", society=sid, person=owner, role="owner") as (
                conn,
                rctx,
            ):
                members.owner_decide(
                    conn, rctx, membership_id=found["id"], decision="confirm", reason=None
                )
        else:
            waive = True
    if state == "requested":
        advance("start_review")
        state = "society_review"
    if state == "society_review":
        advance("verify", reason=r.reason or None, waive=waive)
        ctx.count("claims_verified")
    if r.kind in ("owner", "joint_owner") and not found["billing_liable"]:
        _record_liability(ctx, sid, found["id"], decider, tag)
    if r.outcome == "disputed" and found["owner_decision"] != "disputed":
        owner = ctx.person(r.owner_confirms or "")
        with ctx.tx(f"m-dispute:{tag}", society=sid, person=owner, role="owner") as (conn, rctx):
            members.owner_decide(
                conn, rctx, membership_id=found["id"], decision="dispute", reason=r.reason
            )
        ctx.count("disputes_opened")
    if r.outcome == "ended" and found["ended_at"] is None:
        advance("deactivate", reason=r.reason)
        ctx.count("memberships_ended")


def _place_hold(
    ctx: SeedContext, r: Resident, sid: uuid.UUID, membership: uuid.UUID, tag: str
) -> None:
    placer = ctx.person(f"{r.society}.committee1")
    with ctx.tx(f"m-hold:{tag}", society=sid, person=placer, role="committee") as (conn, rctx):
        if members.holds_of(conn, membership):
            return
        members.place_hold(conn, rctx, membership_id=membership, reason=r.reason)
    ctx.count("holds_placed")


def _record_liability(
    ctx: SeedContext, sid: uuid.UUID, membership: uuid.UUID, actor: uuid.UUID, tag: str
) -> None:
    with ctx.tx(f"m-liability:{tag}", society=sid, person=actor, role="secretary") as (conn, rctx):

        def apply(c: Any) -> MutationResult:
            row = c.execute(
                text(
                    "UPDATE memberships SET billing_liable = true, voting_entitled = true, version = version + 1,"
                    " updated_at = now() WHERE id = :id RETURNING version"
                ),
                {"id": membership},
            ).one()
            return MutationResult(
                object_id=membership, object_version=int(row[0]),
                before={"billing_liable": False, "voting_entitled": False},
                after={"billing_liable": True, "voting_entitled": True},
                event_payload={"membership_id": membership, "billing_liable": True, "voting_entitled": True},
            )  # fmt: skip

        mutation(
            conn, rctx, operation="membership.liability_recorded", object_type="membership",
            event_type="identity.membership_changed", apply=apply,
            reason="seed: owner is the liable and voting-entitled party (recorded, owned by finance and governance)",
        )  # fmt: skip


def run(ctx: SeedContext) -> None:
    for r in RESIDENTS:
        apply_resident(ctx, r)
    named = {(r.society, r.block, r.label) for r in RESIDENTS}
    for spec in BULK:
        soc = ctx.society(spec.society)
        block_order = [b.name for s in SOCIETIES if s.key == spec.society for b in s.blocks]
        free = [
            (b, label)
            for (b, label) in sorted(soc.units, key=lambda k: (block_order.index(k[0]), int(k[1])))
            if (spec.society, b, label) not in named
        ][: spec.count]
        for person, (block, label) in zip(bulk_people(spec), free, strict=True):
            apply_resident(ctx, Resident(spec.society, person.key, block, label, "owner"))
    ctx.say(
        "  residents: "
        + ", ".join(
            f"{k.replace('_', ' ')} {v}"
            for k, v in sorted(ctx.counts.items())
            if k.startswith(("membership", "claims", "disputes", "holds"))
        )
    )
