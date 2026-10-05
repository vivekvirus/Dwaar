"""Membership, verification-case, hold and dispute operations (society-scoped, RLS context set by the caller).

REQ: IAM-01, IAM-05, IAM-07, IAM-12, IAM-13, INV-01, INV-04, PRD 12.4 (mutation + audit + outbox in one transaction).

Every function takes a connection already inside ``Database.app_tx(ctx)`` for the society; the authorising layer
(routes) decided WHO may call it. Rules that protect people, not just roles, live here and are re-checked in the database
where possible (reviewer != applicant, appeal reviewer != original decider, decider != hold placer).
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound, PolicyViolation
from dwaar_common.timeutil import ist_date, utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import states

CASE_COLUMNS = (
    "id, membership_id, kind, state, requested_by, reviewer_id, reason, evidence_ref, appeal_of, decided_at, "
    "version, created_at, updated_at"
)
MEMBERSHIP_COLUMNS = (
    "id, person_id, unit_id, kind, effective_from, effective_to, verification, evidence_ref, is_primary_approver, "
    "lives_in_unit, billing_liable, voting_entitled, owner_decision, owner_decision_at, owner_decision_reason, version"
)


def _one(conn: Connection, sql: str, params: dict[str, Any]) -> dict[str, Any] | None:
    row = conn.execute(text(sql), params).mappings().first()
    return None if row is None else dict(row)


def get_membership(conn: Connection, membership_id: uuid.UUID, *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        conn,
        f"SELECT {MEMBERSHIP_COLUMNS} FROM memberships WHERE id = :id" + (" FOR UPDATE" if lock else ""),  # noqa: S608
        {"id": membership_id},
    )
    if row is None:
        raise NotFound()
    return row


def get_case(conn: Connection, case_id: uuid.UUID, *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        conn,
        f"SELECT {CASE_COLUMNS} FROM verification_cases WHERE id = :id" + (" FOR UPDATE" if lock else ""),  # noqa: S608
        {"id": case_id},
    )
    if row is None:
        raise NotFound()
    return row


def _public(row: dict[str, Any]) -> dict[str, Any]:
    return {k: (str(v) if isinstance(v, uuid.UUID) else v) for k, v in row.items()}


# ------------------------------------------------------------------------------------------------- create
def create_membership(
    conn: Connection,
    ctx: RequestContext,
    *,
    person_id: uuid.UUID,
    unit_id: uuid.UUID,
    kind: str,
    effective_from: date | None,
    lives_in_unit: bool,
    evidence_ref: str | None,
    requested_by: uuid.UUID,
) -> dict[str, Any]:
    """A membership is ALWAYS created ``pending`` with a verification case in ``requested``: nothing here, and no
    sign-up path, can create an effective membership or any role grant (IAM-13)."""
    membership_id, case_id = uuid.uuid4(), uuid.uuid4()
    case_kind = states.CASE_KIND[kind]

    def apply_membership(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "INSERT INTO memberships (id, society_id, person_id, unit_id, kind, effective_from, verification,"
                " evidence_ref, lives_in_unit, created_by) VALUES (:id, :soc, :person, :unit, :kind,"
                " coalesce(:eff, (now() AT TIME ZONE 'Asia/Kolkata')::date), 'pending', :evidence, :lives, :by)"
                " RETURNING version"
            ),
            {
                "id": membership_id, "soc": ctx.society_id, "person": person_id, "unit": unit_id, "kind": kind,
                "eff": effective_from, "evidence": evidence_ref, "lives": lives_in_unit, "by": requested_by,
            },
        ).one()  # fmt: skip
        return MutationResult(
            object_id=membership_id,
            object_version=int(row[0]),
            after={"kind": kind, "unit_id": unit_id, "verification": "pending", "person_id": person_id},
            event_payload={"membership_id": membership_id, "kind": kind, "verification": "pending"},
        )

    mutation(
        conn, ctx, operation="membership.request", object_type="membership",
        event_type="identity.membership_requested", apply=apply_membership,
    )  # fmt: skip

    def apply_case(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO verification_cases (id, society_id, membership_id, kind, state, requested_by,"
                " evidence_ref) VALUES (:id, :soc, :m, :kind, 'requested', :by, :evidence)"
            ),
            {"id": case_id, "soc": ctx.society_id, "m": membership_id, "kind": case_kind, "by": requested_by,
             "evidence": evidence_ref},
        )  # fmt: skip
        return MutationResult(
            object_id=case_id, object_version=1, after={"kind": case_kind, "state": "requested"},
            event_payload={"case_id": case_id, "membership_id": membership_id, "state": "requested"},
        )

    mutation(
        conn, ctx, operation="verification_case.open", object_type="verification_case",
        event_type="identity.verification_case_opened", apply=apply_case,
    )  # fmt: skip
    return {
        "membership_id": str(membership_id),
        "case_id": str(case_id),
        "verification": "pending",
        "case_state": "requested",
        "kind": kind,
    }


# ------------------------------------------------------------------------------------------------- advance
def has_blocking_hold(conn: Connection, membership_id: uuid.UUID) -> bool:
    row = conn.execute(
        text(
            "SELECT 1 FROM membership_holds WHERE membership_id = :m AND state IN ('active', 'appealed', 'upheld')"
            " LIMIT 1"
        ),
        {"m": membership_id},
    ).first()
    return row is not None


def unit_has_effective_owner(conn: Connection, unit_id: uuid.UUID, *, excluding: uuid.UUID) -> bool:
    row = conn.execute(
        text(
            "SELECT 1 FROM memberships WHERE unit_id = :u AND kind IN ('owner', 'joint_owner')"
            " AND verification IN ('verified', 'disputed') AND (effective_to IS NULL OR effective_to >= :today)"
            " AND id <> :me LIMIT 1"
        ),
        {"u": unit_id, "today": ist_date(utc_now()), "me": excluding},
    ).first()
    return row is not None


def _set_membership(
    conn: Connection, ctx: RequestContext, membership: dict[str, Any], *, verification: str,
    end_today: bool = False, operation: str, reason: str | None,
) -> None:  # fmt: skip
    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE memberships SET verification = :v, version = version + 1, updated_at = now(),"
                " effective_to = CASE WHEN :end AND effective_to IS NULL THEN :today ELSE effective_to END"
                " WHERE id = :id RETURNING version, effective_to"
            ),
            {"v": verification, "end": end_today, "today": ist_date(utc_now()), "id": membership["id"]},
        ).one()
        return MutationResult(
            object_id=membership["id"],
            object_version=int(row[0]),
            before={"verification": membership["verification"], "effective_to": membership["effective_to"]},
            after={"verification": verification, "effective_to": row[1]},
            event_payload={"membership_id": membership["id"], "verification": verification},
        )

    mutation(
        conn, ctx, operation=operation, object_type="membership", event_type="identity.membership_changed",
        apply=apply, reason=reason,
    )  # fmt: skip


def advance_case(
    conn: Connection,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID,
    action: str,
    actor: uuid.UUID,
    as_applicant: bool,
    reason: str | None,
    evidence_ref: str | None,
    waive_owner_confirmation: bool,
) -> dict[str, Any]:
    """One transition of a verification case. ``as_applicant`` is decided by the route from who the caller IS."""
    case = get_case(conn, case_id, lock=True)
    membership = get_membership(conn, case["membership_id"], lock=True)
    if action not in (states.APPLICANT_ACTIONS if as_applicant else states.REVIEWER_ACTIONS):
        raise PolicyViolation(details={"reason": "action_not_allowed_for_caller", "action": action})
    if action in states.REASON_REQUIRED and len((reason or "").strip()) < 5:
        raise PolicyViolation(details={"reason": "reason_required"})
    if not as_applicant and actor == membership["person_id"]:
        raise PolicyViolation(details={"reason": "self_verification"})  # nobody reviews their own claim

    if action == "appeal":
        return _open_appeal(conn, ctx, case, membership, actor, reason or "")

    target = states.next_state(case["state"], action, case_kind=case["kind"])
    decision = action in ("verify", "reject", "deactivate")
    if case["state"] == "appealed" and case["appeal_of"] is not None:
        original = get_case(conn, case["appeal_of"])
        if original["reviewer_id"] == actor:
            raise PolicyViolation(details={"reason": "appeal_reviewer_must_differ"})
    if action == "verify":
        _check_can_verify(conn, case, membership, waive_owner_confirmation, reason)

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE verification_cases SET state = :state, reviewer_id = CASE WHEN :applicant THEN reviewer_id"
                " ELSE :actor END, reason = coalesce(:reason, reason), evidence_ref = coalesce(:evidence, evidence_ref),"
                " decided_at = CASE WHEN :decision THEN now() ELSE decided_at END,"
                " version = version + 1, updated_at = now() WHERE id = :id RETURNING version"
            ),
            {
                "state": target, "applicant": as_applicant, "actor": actor, "reason": (reason or "").strip() or None,
                "evidence": evidence_ref, "decision": decision, "id": case_id,
            },
        ).one()  # fmt: skip
        return MutationResult(
            object_id=case_id,
            object_version=int(row[0]),
            before={"state": case["state"]},
            after={"state": target},
            event_payload={"case_id": case_id, "membership_id": membership["id"], "state": target, "action": action},
        )

    mutation(
        conn, ctx, operation=f"verification_case.{action}", object_type="verification_case",
        event_type="identity.verification_case_advanced", apply=apply, reason=reason,
    )  # fmt: skip
    _apply_membership_effect(conn, ctx, case, membership, target, action, reason)
    return {"case_id": str(case_id), "state": target, "membership_id": str(membership["id"])}


def _check_can_verify(
    conn: Connection, case: dict[str, Any], membership: dict[str, Any], waive: bool, reason: str | None
) -> None:
    if has_blocking_hold(conn, membership["id"]):
        raise PolicyViolation(details={"reason": "committee_hold_active"})
    if case["kind"] == "tenant_onboarding":
        decision = membership["owner_decision"]
        if decision == "disputed":
            raise PolicyViolation(details={"reason": "owner_dispute_open"})
        if decision != "confirmed":
            # IAM-12: tenant onboarding needs the owner's confirmation. The only way around it is an explicit,
            # reasoned waiver, and only while the unit has NO effective owner who could confirm.
            if not waive or len((reason or "").strip()) < 10:
                raise PolicyViolation(details={"reason": "owner_confirmation_required"})
            if unit_has_effective_owner(conn, membership["unit_id"], excluding=membership["id"]):
                raise PolicyViolation(details={"reason": "owner_exists_confirmation_required"})


def _apply_membership_effect(
    conn: Connection, ctx: RequestContext, case: dict[str, Any], membership: dict[str, Any], target: str,
    action: str, reason: str | None,
) -> None:  # fmt: skip
    if target == "verified":
        if case["kind"] == "dispute" and membership["verification"] != "disputed":
            return  # a dispute on a not-yet-verified membership never verifies it as a side effect
        _set_membership(conn, ctx, membership, verification="verified", operation="membership.verify", reason=reason)
    elif target == "rejected":
        _set_membership(conn, ctx, membership, verification="rejected", operation="membership.reject", reason=reason)
    elif target == "inactive":
        # an explicit human decision (a reviewer, or the member leaving) is the ONLY way occupancy ends (IAM-05)
        _set_membership(
            conn, ctx, membership, verification=membership["verification"] if membership["verification"] != "disputed" else "verified",
            end_today=True, operation="membership.end", reason=reason,
        )  # fmt: skip


def _open_appeal(
    conn: Connection, ctx: RequestContext, case: dict[str, Any], membership: dict[str, Any], actor: uuid.UUID, reason: str
) -> dict[str, Any]:
    if case["state"] != "rejected":
        raise PolicyViolation(details={"reason": "invalid_transition", "state": case["state"], "action": "appeal"})
    open_appeal = conn.execute(
        text("SELECT 1 FROM verification_cases WHERE appeal_of = :c AND state IN ('appealed') LIMIT 1"),
        {"c": case["id"]},
    ).first()
    if open_appeal is not None:
        raise PolicyViolation(details={"reason": "appeal_already_open"})
    appeal_id = uuid.uuid4()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO verification_cases (id, society_id, membership_id, kind, state, requested_by, reason,"
                " evidence_ref, appeal_of) VALUES (:id, :soc, :m, :kind, 'appealed', :by, :reason, :evidence, :orig)"
            ),
            {
                "id": appeal_id, "soc": ctx.society_id, "m": membership["id"], "kind": case["kind"], "by": actor,
                "reason": reason.strip(), "evidence": case["evidence_ref"], "orig": case["id"],
            },
        )  # fmt: skip
        return MutationResult(
            object_id=appeal_id, object_version=1, after={"state": "appealed", "appeal_of": case["id"]},
            event_payload={"case_id": appeal_id, "appeal_of": case["id"], "state": "appealed"},
        )

    mutation(
        conn, ctx, operation="verification_case.appeal", object_type="verification_case",
        event_type="identity.verification_appealed", apply=apply, reason=reason,
    )  # fmt: skip
    _set_membership(conn, ctx, membership, verification="pending", operation="membership.reopen", reason=reason)
    return {"case_id": str(appeal_id), "state": "appealed", "membership_id": str(membership["id"])}


# ------------------------------------------------------------------------------------------------- owner confirm / dispute
def owner_decide(
    conn: Connection, ctx: RequestContext, *, membership_id: uuid.UUID, decision: str, reason: str | None
) -> dict[str, Any]:
    """The unit's owner confirms (or contests) a tenant. Contesting a tenant who already lives there opens a review; it
    NEVER ends the occupancy (IAM-05): the tenancy stays effective until a reviewer decides otherwise."""
    membership = get_membership(conn, membership_id, lock=True)
    if membership["kind"] not in ("tenant", "family"):
        raise PolicyViolation(details={"reason": "not_a_tenancy"})
    if decision == "dispute" and len((reason or "").strip()) < 10:
        raise PolicyViolation(details={"reason": "reason_required"})
    stored = "confirmed" if decision == "confirm" else "disputed"

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE memberships SET owner_decision = :d, owner_decision_by = :by, owner_decision_at = now(),"
                " owner_decision_reason = :reason, version = version + 1, updated_at = now(),"
                " verification = CASE WHEN :d = 'disputed' AND verification = 'verified' THEN 'disputed'"
                "                     WHEN :d = 'confirmed' AND verification = 'disputed' THEN 'verified'"
                "                     ELSE verification END"
                " WHERE id = :id RETURNING version, verification"
            ),
            {"d": stored, "by": ctx.person_id, "reason": (reason or "").strip() or None, "id": membership_id},
        ).one()
        return MutationResult(
            object_id=membership_id, object_version=int(row[0]),
            before={"owner_decision": membership["owner_decision"], "verification": membership["verification"]},
            after={"owner_decision": stored, "verification": row[1]},
            event_payload={"membership_id": membership_id, "owner_decision": stored, "verification": row[1]},
        )  # fmt: skip

    mutation(
        conn, ctx, operation=f"membership.owner_{stored}", object_type="membership",
        event_type="identity.owner_decision", apply=apply, reason=reason,
    )  # fmt: skip
    updated = get_membership(conn, membership_id)
    if stored == "disputed":
        _open_dispute_case(conn, ctx, updated, reason or "")
    return {"membership_id": str(membership_id), "owner_decision": stored, "verification": updated["verification"]}


def _open_dispute_case(conn: Connection, ctx: RequestContext, membership: dict[str, Any], reason: str) -> uuid.UUID | None:
    existing = conn.execute(
        text(
            "SELECT id FROM verification_cases WHERE membership_id = :m AND kind = 'dispute'"
            " AND state IN ('requested', 'society_review') LIMIT 1"
        ),
        {"m": membership["id"]},
    ).first()
    if existing is not None:
        return None
    case_id = uuid.uuid4()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO verification_cases (id, society_id, membership_id, kind, state, requested_by, reason)"
                " VALUES (:id, :soc, :m, 'dispute', 'society_review', :by, :reason)"
            ),
            {"id": case_id, "soc": ctx.society_id, "m": membership["id"], "by": ctx.person_id, "reason": reason.strip() or None},
        )
        return MutationResult(
            object_id=case_id, object_version=1, after={"kind": "dispute", "state": "society_review"},
            event_payload={"case_id": case_id, "membership_id": membership["id"], "kind": "dispute"},
        )

    mutation(
        conn, ctx, operation="verification_case.open_dispute", object_type="verification_case",
        event_type="identity.dispute_opened", apply=apply, reason=reason,
    )  # fmt: skip
    return case_id


def raise_dispute(
    conn: Connection, ctx: RequestContext, *, membership_id: uuid.UUID, reason: str
) -> dict[str, Any]:
    if len(reason.strip()) < 10:
        raise PolicyViolation(details={"reason": "reason_required"})
    membership = get_membership(conn, membership_id, lock=True)
    case_id = None
    if membership["verification"] == "verified":

        def apply(c: Connection) -> MutationResult:
            row = c.execute(
                text(
                    "UPDATE memberships SET verification = 'disputed', version = version + 1, updated_at = now()"
                    " WHERE id = :id RETURNING version"
                ),
                {"id": membership_id},
            ).one()
            return MutationResult(
                object_id=membership_id, object_version=int(row[0]),
                before={"verification": "verified"}, after={"verification": "disputed"},
                event_payload={"membership_id": membership_id, "verification": "disputed"},
            )  # fmt: skip

        mutation(
            conn, ctx, operation="membership.dispute", object_type="membership",
            event_type="identity.membership_disputed", apply=apply, reason=reason,
        )  # fmt: skip
    elif membership["verification"] not in ("pending", "disputed", "reverification"):
        raise PolicyViolation(details={"reason": "nothing_to_dispute"})
    case_id = _open_dispute_case(conn, ctx, get_membership(conn, membership_id), reason)
    if case_id is None:
        raise PolicyViolation(details={"reason": "dispute_already_open"})
    return {
        "membership_id": str(membership_id),
        "case_id": str(case_id),
        "verification": get_membership(conn, membership_id)["verification"],
        "occupancy_unchanged": True,
    }


# ------------------------------------------------------------------------------------------------- holds
def place_hold(conn: Connection, ctx: RequestContext, *, membership_id: uuid.UUID, reason: str) -> dict[str, Any]:
    if len(reason.strip()) < 10:
        raise PolicyViolation(details={"reason": "reason_required"})
    membership = get_membership(conn, membership_id, lock=True)
    if membership["kind"] != "tenant" or membership["verification"] not in ("pending", "reverification"):
        # A hold stops an ONBOARDING; it can never remove someone who already lives there (IAM-05 / IAM-12).
        raise PolicyViolation(details={"reason": "hold_would_remove_occupancy"})
    hold_id = uuid.uuid4()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO membership_holds (id, society_id, membership_id, placed_by, reason)"
                " VALUES (:id, :soc, :m, :by, :reason)"
            ),
            {"id": hold_id, "soc": ctx.society_id, "m": membership_id, "by": ctx.person_id, "reason": reason.strip()},
        )
        return MutationResult(
            object_id=hold_id, object_version=1, after={"state": "active"},
            event_payload={"hold_id": hold_id, "membership_id": membership_id, "state": "active"},
        )

    mutation(
        conn, ctx, operation="membership_hold.place", object_type="membership_hold",
        event_type="identity.hold_placed", apply=apply, reason=reason,
    )  # fmt: skip
    return {"hold_id": str(hold_id), "membership_id": str(membership_id), "state": "active"}


def get_hold(conn: Connection, hold_id: uuid.UUID, *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        conn,
        "SELECT id, membership_id, state, placed_by, reason, placed_at, appeal_by, appeal_reason, appealed_at,"
        " decided_by, decision_reason, decided_at, version FROM membership_holds WHERE id = :id"
        + (" FOR UPDATE" if lock else ""),
        {"id": hold_id},
    )
    if row is None:
        raise NotFound()
    return row


def appeal_hold(conn: Connection, ctx: RequestContext, *, hold_id: uuid.UUID, reason: str) -> dict[str, Any]:
    if len(reason.strip()) < 10:
        raise PolicyViolation(details={"reason": "reason_required"})
    hold = get_hold(conn, hold_id, lock=True)
    if hold["state"] != "active":
        raise PolicyViolation(details={"reason": "invalid_transition", "state": hold["state"]})

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE membership_holds SET state = 'appealed', appeal_by = :by, appeal_reason = :reason,"
                " appealed_at = now(), version = version + 1 WHERE id = :id RETURNING version"
            ),
            {"by": ctx.person_id, "reason": reason.strip(), "id": hold_id},
        ).one()
        return MutationResult(
            object_id=hold_id, object_version=int(row[0]), before={"state": "active"}, after={"state": "appealed"},
            event_payload={"hold_id": hold_id, "state": "appealed"},
        )

    mutation(
        conn, ctx, operation="membership_hold.appeal", object_type="membership_hold",
        event_type="identity.hold_appealed", apply=apply, reason=reason,
    )  # fmt: skip
    return {"hold_id": str(hold_id), "state": "appealed"}


def decide_hold(
    conn: Connection, ctx: RequestContext, *, hold_id: uuid.UUID, outcome: str, reason: str
) -> dict[str, Any]:
    hold = get_hold(conn, hold_id, lock=True)
    if hold["state"] not in ("active", "appealed"):
        raise PolicyViolation(details={"reason": "invalid_transition", "state": hold["state"]})
    if hold["placed_by"] == ctx.person_id:
        raise PolicyViolation(details={"reason": "decider_must_differ_from_placer"})
    if len(reason.strip()) < 5:
        raise PolicyViolation(details={"reason": "reason_required"})
    target = "released" if outcome == "release" else "upheld"

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE membership_holds SET state = :s, decided_by = :by, decision_reason = :reason, decided_at = now(),"
                " version = version + 1 WHERE id = :id RETURNING version"
            ),
            {"s": target, "by": ctx.person_id, "reason": reason.strip(), "id": hold_id},
        ).one()
        return MutationResult(
            object_id=hold_id, object_version=int(row[0]), before={"state": hold["state"]}, after={"state": target},
            event_payload={"hold_id": hold_id, "state": target},
        )

    mutation(
        conn, ctx, operation=f"membership_hold.{outcome}", object_type="membership_hold",
        event_type="identity.hold_decided", apply=apply, reason=reason,
    )  # fmt: skip
    return {"hold_id": str(hold_id), "state": target}


def holds_of(conn: Connection, membership_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, membership_id, state, reason, placed_at, appeal_reason, appealed_at, decision_reason,"
            " decided_at FROM membership_holds WHERE membership_id = :m ORDER BY placed_at DESC"
        ),
        {"m": membership_id},
    ).mappings()
    return [_public(dict(r)) for r in rows]


# ------------------------------------------------------------------------------------------------- IAM-11 re-verification
def reopen_for_reverification(conn: Connection, ctx: RequestContext, *, person_id: uuid.UUID) -> int:
    """After a number change: every verified membership of the person goes back to review (``reverification``) with a
    case the society must decide. Occupancy dates are untouched; only the grants pause until a human re-verifies."""
    rows = conn.execute(
        text(
            "SELECT id FROM memberships WHERE person_id = :p AND verification IN ('verified', 'disputed')"
            " AND (effective_to IS NULL OR effective_to >= :today) FOR UPDATE"
        ),
        {"p": person_id, "today": ist_date(utc_now())},
    ).all()
    for (mid,) in rows:
        membership = get_membership(conn, mid)
        _set_membership(
            conn, ctx, membership, verification="reverification", operation="membership.reverify",
            reason="phone number changed",
        )  # fmt: skip
        case_id = uuid.uuid4()

        def apply(c: Connection, case_id: uuid.UUID = case_id, mid: uuid.UUID = mid) -> MutationResult:
            c.execute(
                text(
                    "INSERT INTO verification_cases (id, society_id, membership_id, kind, state, requested_by, reason)"
                    " VALUES (:id, :soc, :m, 'reverification', 'evidence_pending', :by,"
                    " 'Phone number changed: please present identity evidence again')"
                ),
                {"id": case_id, "soc": ctx.society_id, "m": mid, "by": person_id},
            )
            return MutationResult(
                object_id=case_id, object_version=1, after={"kind": "reverification", "state": "evidence_pending"},
                event_payload={"case_id": case_id, "membership_id": mid, "kind": "reverification"},
            )

        mutation(
            conn, ctx, operation="verification_case.open_reverification", object_type="verification_case",
            event_type="identity.reverification_required", apply=apply,
        )  # fmt: skip
    return len(rows)
