"""Identity endpoints: ``/v1/me``, memberships, verification cases, owner confirmation, disputes, holds, role grants.

REQ: IAM-01, IAM-02, IAM-03, IAM-04, IAM-05, IAM-07, IAM-12, IAM-13, INV-01, INV-04, PRD 12.1.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from dwaar_common.crypto import InvalidPhoneError
from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation
from dwaar_common.ids import uuid7
from dwaar_common.masking import mask_aadhaar

from ...core import ratelimit
from ...core.authn import Principal, current_principal
from ...core.authz import AuthContext, idempotency_exempt, require
from ...core.db import RequestContext
from ...core.idempotency import IdempotentCall, idempotency_required
from . import crypto, grants, members, states, store
from .access import (
    applicant_context,
    authorize,
    clean_purpose,
    grants_in,
    log_privileged_read,
    owns_unit,
    request_id_of,
)
from .matrix import ELEVATED_ROLES
from .runtime import Runtime

router = APIRouter(tags=["identity"])
Principal_ = Annotated[Principal, Depends(current_principal)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ===================================================================================================== /v1/me
class ProfileIn(Strict):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    preferred_language: Literal["en", "hi", "mr", "kn"] | None = None
    email: str | None = Field(default=None, min_length=3, max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    id_document_number: str | None = Field(default=None, min_length=4, max_length=32)


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime | date) else value


@router.get("/v1/me")
def me(principal: Principal_, request: Request, rt: Runtime) -> dict[str, Any]:
    """Who the server says you are: profile, memberships and the EFFECTIVE roles per society, all computed on the server
    from current database state (never from the token)."""
    pid = principal.person_id
    base = RequestContext(person_id=pid)
    with rt.db.app_tx(base) as conn:
        profile = store.person_profile(conn, pid)
        if profile is None:
            raise NotFound()
        overview = store.access_overview(conn, pid)
        factor = store.mfa_get(conn, pid)
        elevated_present = any(r.role in ELEVATED_ROLES for r in overview)
        mfa_fresh = False
        if principal.session_id:
            try:
                mfa_fresh = store.session_mfa_fresh(conn, pid, uuid.UUID(principal.session_id), rt.config.mfa_ttl_seconds)
            except ValueError:
                mfa_fresh = False
    societies: dict[uuid.UUID, dict[str, Any]] = {}
    for row in overview:
        entry = societies.setdefault(row.society_id, {"society_id": str(row.society_id), "roles": [], "memberships": []})
        elevated = row.role in ELEVATED_ROLES
        entry["roles"].append(
            {
                "role": row.role,
                "source": row.source_kind,
                "unit_id": str(row.unit_id) if row.unit_id else None,
                "active": row.effective and (mfa_fresh or not elevated),
                "valid_now": row.effective,
                "not_before": _iso(row.not_before),
                "expires_at": _iso(row.expires_at),
                "requires_mfa": elevated,
                "mfa_satisfied": mfa_fresh if elevated else True,
            }
        )
    for society_id, entry in societies.items():
        with rt.db.app_tx(RequestContext(society_id, pid, "self", request_id_of(request))) as conn:
            entry["memberships"] = _own_memberships(conn, pid)
    return {
        "person": {
            "id": str(profile.id),
            "display_name": profile.display_name,
            "preferred_language": profile.preferred_language,
            "is_minor": profile.is_minor,
        },
        "simulation": rt.config.simulation,
        "mfa": {
            "enrolled": factor is not None,
            "confirmed": bool(factor and factor.confirmed_at),
            "session_verified": mfa_fresh,
            "required_for_roles": elevated_present,
        },
        "societies": list(societies.values()),
    }


def _own_memberships(conn: Any, person_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, unit_id, kind, verification, effective_from, effective_to, lives_in_unit, owner_decision"
            " FROM memberships WHERE person_id = :p ORDER BY created_at, id"
        ),
        {"p": person_id},
    ).mappings().all()
    ids = [r["id"] for r in rows]
    cases: dict[uuid.UUID, dict[str, Any]] = {}
    if ids:
        for c in conn.execute(
            text(
                "SELECT DISTINCT ON (membership_id) membership_id, id, kind, state, reason, decided_at"
                " FROM verification_cases WHERE membership_id = ANY(:ids) ORDER BY membership_id, created_at DESC, id DESC"
            ),
            {"ids": ids},
        ).mappings():
            cases[c["membership_id"]] = {
                "id": str(c["id"]), "kind": c["kind"], "state": c["state"],
                "reason": c["reason"], "decided_at": _iso(c["decided_at"]),
            }  # fmt: skip
    out = []
    for r in rows:
        out.append(
            {
                "id": str(r["id"]),
                "unit_id": str(r["unit_id"]),
                "kind": r["kind"],
                "verification": r["verification"],
                "effective_from": _iso(r["effective_from"]),
                "effective_to": _iso(r["effective_to"]),
                "lives_in_unit": r["lives_in_unit"],
                "owner_decision": r["owner_decision"],
                "case": cases.get(r["id"]),
                "holds": members.holds_of(conn, r["id"]),
            }
        )
    return out


@router.patch("/v1/me/profile", dependencies=[Depends(idempotency_exempt("idempotent field update of one's own profile"))])
def update_profile(body: ProfileIn, principal: Principal_, request: Request, rt: Runtime) -> dict[str, Any]:
    pid = principal.person_id
    email_enc = rt.config.cipher.encrypt(body.email, crypto.vault_aad(pid, "email")) if body.email else None
    masked = mask_aadhaar(body.id_document_number) if body.id_document_number else None
    with rt.db.app_tx(RequestContext(person_id=pid, request_id=request_id_of(request))) as conn:
        ok = store.update_profile(conn, pid, body.display_name, body.preferred_language)
        if not ok:
            raise NotFound()
        if email_enc or masked:
            store.vault_put(conn, pid, email_enc, masked)
        rt.auth._audit(  # noqa: SLF001
            conn, "person.profile_updated", person=pid, obj=pid, object_type="person",
            diff={"fields": sorted(k for k, v in body.model_dump().items() if v is not None)},
            request_id=request_id_of(request),
        )  # fmt: skip
    return {"updated": True}


# ===================================================================================================== memberships
class MembershipIn(Strict):
    unit_id: uuid.UUID
    kind: Literal["owner", "joint_owner", "tenant", "family", "staff"]
    effective_from: date | None = None
    lives_in_unit: bool | None = None
    evidence_ref: str | None = Field(default=None, max_length=300)
    person_phone: str | None = Field(default=None, min_length=8, max_length=24)
    display_name: str | None = Field(default=None, min_length=1, max_length=120)


@router.post(
    "/v1/societies/{society_id}/memberships",
    status_code=201,
    dependencies=[Depends(idempotency_exempt("naturally idempotent: one live claim per person, unit and kind (unique index)"))],
)
def create_membership(
    society_id: uuid.UUID, body: MembershipIn, principal: Principal_, request: Request, rt: Runtime
) -> JSONResponse:
    """Ask to join a unit (or, as a secretary, record a membership for someone else).

    Always yields a PENDING membership and a verification case: this endpoint cannot create an effective membership or a
    role, whoever calls it (IAM-13), and a caller can never verify their own claim.
    """
    if body.person_phone is None:
        # Applicant path: any signed-in person, only for THEMSELVES, never staff.
        if body.kind not in states.APPLICANT_KINDS:
            raise PolicyViolation(details={"reason": "staff_are_added_by_the_society"})
        ratelimit.enforce(
            rt.db, crypto.rate_key(rt.config, "membership_req", str(principal.person_id)),
            capacity=rt.config.membership_request_capacity,
            refill_per_second=rt.config.membership_request_capacity / rt.config.membership_request_refill_seconds,
        )  # fmt: skip
        ctx = applicant_context(society_id, principal, request)
        person_id = principal.person_id
        lives = body.lives_in_unit if body.lives_in_unit is not None else body.kind != "staff"
        with rt.db.app_tx(ctx) as conn:
            result = members.create_membership(
                conn, ctx, person_id=person_id, unit_id=body.unit_id, kind=body.kind,
                effective_from=body.effective_from, lives_in_unit=lives, evidence_ref=body.evidence_ref,
                requested_by=principal.person_id,
            )  # fmt: skip
        return JSONResponse(result, status_code=201)
    auth = authorize(request, principal, ["iam.membership.manage"], society_id)
    try:
        e164 = crypto.normalise_phone(body.person_phone)
    except InvalidPhoneError:
        raise InvalidSchema.for_fields([("person_phone", "invalid_phone")]) from None
    token = crypto.phone_token(rt.config, e164)
    new_id = uuid7()
    enc = rt.config.cipher.encrypt(e164, crypto.vault_aad(new_id, "phone"))
    lives = body.lives_in_unit if body.lives_in_unit is not None else body.kind != "staff"
    with auth.tx() as conn:
        person_id = store.ensure_person(
            conn, new_id=new_id, token=token, phone_enc=enc, display_name=body.display_name or "Resident"
        )
        result = members.create_membership(
            conn, auth.ctx, person_id=person_id, unit_id=body.unit_id, kind=body.kind,
            effective_from=body.effective_from, lives_in_unit=lives, evidence_ref=body.evidence_ref,
            requested_by=principal.person_id,
        )  # fmt: skip
    return JSONResponse(result, status_code=201)


def _mask_name(name: str) -> str:
    parts = [p for p in name.split() if p]
    return " ".join(p[0].upper() + "." for p in parts) or "*"


@router.get("/v1/societies/{society_id}/memberships")
def list_memberships(
    society_id: uuid.UUID,
    principal: Principal_,
    request: Request,
    unit_id: uuid.UUID | None = None,
    purpose: Annotated[str | None, Query(max_length=200)] = None,
    after: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    """The member register (PRD 5.2 "Unit and member register"): secretary and committee-class roles read it in full, the
    GUARD sees initials only, a resident sees only their own rows. Every non-own read logs its purpose and scope (IAM-04)."""
    auth = authorize(
        request, principal,
        ["iam.membership.read_register", "iam.membership.read_masked", "matrix.unit_register.read_own"],
        society_id, unit_id=unit_id,
    )  # fmt: skip
    action = auth.permission.action
    own_only = action == "matrix.unit_register.read_own"
    masked = action == "iam.membership.read_masked"
    if not own_only:
        purpose = clean_purpose(purpose)
    with auth.tx() as conn:
        rows = conn.execute(
            text(
                "SELECT id, person_id, unit_id, kind, verification, effective_from, effective_to, lives_in_unit,"
                " is_primary_approver FROM memberships"
                " WHERE (CAST(:unit AS uuid) IS NULL OR unit_id = CAST(:unit AS uuid))"
                " AND (CAST(:after AS uuid) IS NULL OR id > CAST(:after AS uuid))"
                " AND (NOT :own OR person_id = :me) ORDER BY id LIMIT :limit"
            ),
            {"unit": unit_id, "after": after, "own": own_only, "me": principal.person_id, "limit": limit + 1},
        ).mappings().all()
        page = rows[:limit]
        names = store.society_people(conn, list({r["person_id"] for r in page}))
        if not own_only:
            log_privileged_read(
                conn, auth.ctx, object_type="membership_register", purpose=purpose or "",
                scope={"unit_id": str(unit_id) if unit_id else None, "view": "masked" if masked else "full"},
                returned=len(page),
            )  # fmt: skip
    items = []
    for r in page:
        name = names.get(r["person_id"], ("", "", False))[0]
        items.append(
            {
                "id": str(r["id"]),
                "person_id": None if masked else str(r["person_id"]),
                "display_name": _mask_name(name) if masked else name,
                "unit_id": str(r["unit_id"]),
                "kind": r["kind"],
                "verification": r["verification"],
                "effective_from": _iso(r["effective_from"]),
                "effective_to": _iso(r["effective_to"]),
                "lives_in_unit": r["lives_in_unit"],
                "masked": masked,
            }
        )
    return {"items": items, "next_after": str(page[-1]["id"]) if len(rows) > limit and page else None}


# ===================================================================================================== cases
class AdvanceIn(Strict):
    action: Literal["request_evidence", "start_review", "verify", "reject", "deactivate", "submit_evidence", "appeal", "leave"]
    reason: str | None = Field(default=None, max_length=500)
    evidence_ref: str | None = Field(default=None, max_length=300)
    waive_owner_confirmation: bool = False


@router.get("/v1/societies/{society_id}/verification-cases")
def list_cases(
    auth: Annotated[AuthContext, Depends(require("iam.case.read"))],
    state: Annotated[str | None, Query(pattern="^(requested|evidence_pending|society_review|verified|rejected|appealed|inactive)$")] = None,
    after: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    with auth.tx() as conn:
        rows = conn.execute(
            text(
                f"SELECT {members.CASE_COLUMNS} FROM verification_cases"  # noqa: S608
                " WHERE (CAST(:state AS text) IS NULL OR state = CAST(:state AS text))"
                " AND (CAST(:after AS uuid) IS NULL OR id > CAST(:after AS uuid)) ORDER BY id LIMIT :limit"
            ),
            {"state": state, "after": after, "limit": limit + 1},
        ).mappings().all()
    page = [members._public({k: _iso(v) for k, v in dict(r).items()}) for r in rows[:limit]]  # noqa: SLF001
    return {"items": page, "next_after": page[-1]["id"] if len(rows) > limit and page else None}


@router.post(
    "/v1/societies/{society_id}/verification-cases/{case_id}/advance",
    dependencies=[Depends(idempotency_exempt("each transition is validated against the current state; a repeat is refused"))],
)
def advance_case(
    society_id: uuid.UUID, case_id: uuid.UUID, body: AdvanceIn, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, Any]:
    """Move a verification case. Applicants (submit evidence, appeal, leave) act on their OWN membership; reviewers need
    secretary authority, or, for a tenant or family claim, ownership of THAT unit. Nobody reviews their own claim."""
    applicant_ctx = applicant_context(society_id, principal, request)
    with rt.db.app_tx(applicant_ctx) as conn:
        case = members.get_case(conn, case_id)  # RLS: only the named society's rows
        membership = members.get_membership(conn, case["membership_id"])
    is_applicant = membership["person_id"] == principal.person_id
    if body.action in states.APPLICANT_ACTIONS:
        if not is_applicant:
            raise NotFound()  # not your claim: indistinguishable from "no such case"
        ctx = applicant_ctx
    else:
        actions = ["matrix.verify_tenancy.approve"]
        if membership["kind"] not in states.SOCIETY_ONLY_KINDS and case["kind"] != "dispute":
            actions.append("matrix.verify_tenancy.approve_own")
        auth = authorize(request, principal, actions, society_id, unit_id=membership["unit_id"])
        if auth.permission.action.endswith("approve_own") and not owns_unit(
            grants_in(request, principal, society_id), membership["unit_id"]
        ):
            raise NotFound()
        ctx = auth.ctx
    with rt.db.app_tx(ctx) as conn:
        return members.advance_case(
            conn, ctx, case_id=case_id, action=body.action, actor=principal.person_id,
            as_applicant=body.action in states.APPLICANT_ACTIONS, reason=body.reason,
            evidence_ref=body.evidence_ref, waive_owner_confirmation=body.waive_owner_confirmation,
        )  # fmt: skip


# ===================================================================================================== owner confirm / dispute
class OwnerConfirmIn(Strict):
    decision: Literal["confirm", "dispute"] = "confirm"
    reason: str | None = Field(default=None, max_length=500)


@router.post(
    "/v1/memberships/{membership_id}/owner-confirm",
    dependencies=[Depends(idempotency_exempt("a repeated decision overwrites the same owner decision"))],
)
def owner_confirm(
    membership_id: uuid.UUID, body: OwnerConfirmIn, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, Any]:
    """The OWNER OF THAT UNIT confirms (or contests) a tenant or household member (IAM-12, IAM-05). Anyone else, and any
    unknown id, gets the same 404."""
    with rt.db.app_tx(RequestContext(person_id=principal.person_id)) as conn:
        located = store.locate_membership(conn, membership_id)
    if located is None or located[1] is None:
        raise NotFound()
    society_id, unit_id = located
    if not owns_unit(grants_in(request, principal, society_id), unit_id):
        raise NotFound()
    ctx = RequestContext(society_id, principal.person_id, "owner", request_id_of(request))
    with rt.db.app_tx(ctx) as conn:
        target = members.get_membership(conn, membership_id)
        if target["unit_id"] != unit_id or target["person_id"] == principal.person_id:
            raise NotFound()
        return members.owner_decide(conn, ctx, membership_id=membership_id, decision=body.decision, reason=body.reason)


class DisputeIn(Strict):
    reason: str = Field(min_length=10, max_length=500)


@router.post(
    "/v1/societies/{society_id}/memberships/{membership_id}/dispute",
    status_code=201,
    dependencies=[Depends(idempotency_exempt("a second open dispute on one membership is refused"))],
)
def raise_dispute(
    society_id: uuid.UUID, membership_id: uuid.UUID, body: DisputeIn, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, Any]:
    """Open an owner-tenant dispute review. The membership becomes ``disputed`` and a case goes to the society; the
    occupancy is NOT touched: only an explicit reviewer decision can end it (IAM-05)."""
    peek = applicant_context(society_id, principal, request)
    with rt.db.app_tx(peek) as conn:
        target = members.get_membership(conn, membership_id)
    auth = authorize(
        request, principal, ["iam.dispute.raise", "iam.dispute.raise_own"], society_id, unit_id=target["unit_id"]
    )
    with auth.tx() as conn:
        return members.raise_dispute(conn, auth.ctx, membership_id=membership_id, reason=body.reason)


# ===================================================================================================== holds (IAM-12)
class HoldIn(Strict):
    reason: str = Field(min_length=10, max_length=500)


class HoldDecisionIn(Strict):
    outcome: Literal["release", "uphold"]
    reason: str = Field(min_length=5, max_length=500)


@router.post(
    "/v1/societies/{society_id}/memberships/{membership_id}/holds",
    status_code=201,
    dependencies=[Depends(idempotency_exempt("one open hold per membership (unique index)"))],
)
def place_hold(
    membership_id: uuid.UUID, body: HoldIn, auth: Annotated[AuthContext, Depends(require("iam.hold.place"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return members.place_hold(conn, auth.ctx, membership_id=membership_id, reason=body.reason)


def _hold_standing(
    request: Request, principal: Principal, society_id: uuid.UUID, membership: dict[str, Any]
) -> bool:
    """Who may see or appeal a hold: the member it is about, the owner of that unit, or the committee/secretary."""
    if membership["person_id"] == principal.person_id:
        return True
    grants = grants_in(request, principal, society_id)
    if owns_unit(grants, membership["unit_id"]):
        return True
    return any(g.role in ("secretary", "committee", "secretary_mfa_pending", "committee_mfa_pending") for g in grants)


@router.get("/v1/societies/{society_id}/memberships/{membership_id}/holds")
def list_holds(
    society_id: uuid.UUID, membership_id: uuid.UUID, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, Any]:
    """Holds are visible to the owner AND the tenant, with their reasons (IAM-12)."""
    ctx = applicant_context(society_id, principal, request)
    with rt.db.app_tx(ctx) as conn:
        membership = members.get_membership(conn, membership_id)
        if not _hold_standing(request, principal, society_id, membership):
            raise NotFound()
        return {"items": members.holds_of(conn, membership_id)}


@router.post(
    "/v1/societies/{society_id}/holds/{hold_id}/appeal",
    dependencies=[Depends(idempotency_exempt("a hold can be appealed once while active"))],
)
def appeal_hold(
    society_id: uuid.UUID, hold_id: uuid.UUID, body: HoldIn, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, Any]:
    ctx = applicant_context(society_id, principal, request)
    with rt.db.app_tx(ctx) as conn:
        hold = members.get_hold(conn, hold_id)
        membership = members.get_membership(conn, hold["membership_id"])
        grants = grants_in(request, principal, society_id)
        if membership["person_id"] != principal.person_id and not owns_unit(grants, membership["unit_id"]):
            raise NotFound()  # only the tenant concerned or the owner of the unit appeal
        return members.appeal_hold(conn, ctx, hold_id=hold_id, reason=body.reason)


@router.post(
    "/v1/societies/{society_id}/holds/{hold_id}/decide",
    dependencies=[Depends(idempotency_exempt("a hold is decided once; a repeat is refused by state"))],
)
def decide_hold(
    hold_id: uuid.UUID, body: HoldDecisionIn, auth: Annotated[AuthContext, Depends(require("iam.hold.decide"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return members.decide_hold(conn, auth.ctx, hold_id=hold_id, outcome=body.outcome, reason=body.reason)


# ===================================================================================================== role grants
class GrantIn(Strict):
    person_id: uuid.UUID | None = None
    person_phone: str | None = Field(default=None, min_length=8, max_length=24)
    role: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=5, max_length=500)
    expires_at: datetime | None = None
    not_before: datetime | None = None
    unit_id: uuid.UUID | None = None


class RevokeIn(Strict):
    reason: str = Field(min_length=5, max_length=500)


@router.post("/v1/societies/{society_id}/role-grants", status_code=201)
def issue_role_grant(
    body: GrantIn,
    auth: Annotated[AuthContext, Depends(require("iam.role_grant.issue"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    request: Request,
) -> Any:
    """Grant a staff or committee role (secretary only, MFA, reason mandatory, never to oneself, never a platform role)."""
    if (body.person_id is None) == (body.person_phone is None):
        raise InvalidSchema.for_fields([("person_id", "exactly_one_of_person_id_or_person_phone")])
    rt: Any = request.app.state.identity

    def work(conn: Any) -> dict[str, Any]:
        person_id = body.person_id
        introduced = False
        if body.person_phone is not None:
            try:
                e164 = crypto.normalise_phone(body.person_phone)
            except InvalidPhoneError:
                raise InvalidSchema.for_fields([("person_phone", "invalid_phone")]) from None
            new_id = uuid7()
            person_id = store.ensure_person(
                conn, new_id=new_id, token=crypto.phone_token(rt.config, e164),
                phone_enc=rt.config.cipher.encrypt(e164, crypto.vault_aad(new_id, "phone")), display_name="Staff",
            )  # fmt: skip
            introduced = True
        assert person_id is not None  # noqa: S101
        return grants.issue_grant(
            conn, auth.ctx, person_id=person_id, role=body.role, reason=body.reason, expires_at=body.expires_at,
            not_before=body.not_before, unit_id=body.unit_id, introduced_by_phone=introduced,
        )  # fmt: skip

    return idem.run(auth, work, status_code=201)


@router.post(
    "/v1/societies/{society_id}/role-grants/{grant_id}/revoke",
    dependencies=[Depends(idempotency_exempt("revoking twice is refused by state, never doubled"))],
)
def revoke_role_grant(
    grant_id: uuid.UUID, body: RevokeIn, auth: Annotated[AuthContext, Depends(require("iam.role_grant.revoke"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return grants.revoke_grant(conn, auth.ctx, grant_id=grant_id, reason=body.reason)


@router.get("/v1/societies/{society_id}/role-grants")
def list_role_grants(
    auth: Annotated[AuthContext, Depends(require("iam.role_grant.read"))],
    purpose: Annotated[str | None, Query(max_length=200)] = None,
    after: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    purpose = clean_purpose(purpose)
    with auth.tx() as conn:
        items = grants.list_grants(conn, after=after, limit=limit)
        log_privileged_read(
            conn, auth.ctx, object_type="role_grants", purpose=purpose, scope={"view": "all"}, returned=len(items)
        )
    return {"items": items, "next_after": items[-1]["id"] if len(items) == limit else None}

