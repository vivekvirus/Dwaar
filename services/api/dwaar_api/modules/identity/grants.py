"""Role grants: issue, revoke, list (IAM-02, IAM-03, IAM-13).

REQ: IAM-02 (grants carry scope, issuer, expiry and reason; they expire automatically and expiry revokes the sessions
that used the privilege: ``iam.sweep_person``), IAM-03 (elevated roles cannot be self-granted; platform roles are never
assignable here), IAM-13 (this API is the ONLY writer of ``role_grants`` and needs the secretary permission: no sign-up or
membership path can create a grant), PRD 5.1.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound, PolicyViolation
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from .makerchecker import require_distinct
from .matrix import ASSIGNABLE_ROLES, ELEVATED_ROLES, TIME_BOUND_ROLES

MAX_GRANT_DAYS = 366


def issue_grant(
    conn: Connection,
    ctx: RequestContext,
    *,
    person_id: uuid.UUID,
    role: str,
    reason: str,
    expires_at: datetime | None,
    not_before: datetime | None,
    unit_id: uuid.UUID | None,
    introduced_by_phone: bool,
) -> dict[str, Any]:
    assert ctx.person_id is not None  # noqa: S101 (the route authorises first)
    require_distinct(ctx.person_id, person_id, what="self_grant")
    if role not in ASSIGNABLE_ROLES:
        # platform roles (org_admin, plat_support) and unknown roles: never through this API (IAM-13)
        raise PolicyViolation(details={"reason": "role_not_assignable"})
    reason = reason.strip()
    if len(reason) < (10 if role in ELEVATED_ROLES else 5):
        raise PolicyViolation(details={"reason": "reason_required"})
    now = utc_now()
    if role in TIME_BOUND_ROLES and expires_at is None:
        raise PolicyViolation(details={"reason": "expiry_required"})
    if expires_at is not None and not now < expires_at <= now + timedelta(days=MAX_GRANT_DAYS):
        raise PolicyViolation(details={"reason": "expiry_out_of_range"})
    if not_before is not None and expires_at is not None and not_before >= expires_at:
        raise PolicyViolation(details={"reason": "window_empty"})
    if unit_id is not None:
        known_unit = conn.execute(text("SELECT 1 FROM units WHERE id = :u"), {"u": unit_id}).first()
        if known_unit is None:
            raise NotFound()
    if not introduced_by_phone:
        # a person id is only accepted for someone who already has a relationship with THIS society: ids of strangers
        # answer 404 exactly like ids that do not exist (no person enumeration through the grant API)
        known = conn.execute(
            text(
                "SELECT 1 FROM memberships WHERE person_id = :p UNION ALL SELECT 1 FROM role_grants WHERE person_id = :p LIMIT 1"
            ),
            {"p": person_id},
        ).first()
        if known is None:
            raise NotFound()
    grant_id = uuid.uuid4()
    scope = {"kind": "unit", "unit_id": str(unit_id)} if unit_id else {"kind": "society"}

    def apply(c: Connection) -> MutationResult:
        import json

        row = c.execute(
            text(
                "INSERT INTO role_grants (id, society_id, person_id, role, scope, issued_by, reason, not_before,"
                " expires_at) VALUES (:id, :soc, :person, :role, CAST(:scope AS jsonb), :by, :reason, :nb, :exp)"
                " RETURNING version"
            ),
            {
                "id": grant_id, "soc": ctx.society_id, "person": person_id, "role": role,
                "scope": json.dumps(scope), "by": ctx.person_id, "reason": reason, "nb": not_before, "exp": expires_at,
            },
        ).one()  # fmt: skip
        return MutationResult(
            object_id=grant_id, object_version=int(row[0]),
            after={"role": role, "person_id": person_id, "scope": scope, "expires_at": expires_at},
            event_payload={"grant_id": grant_id, "role": role, "person_id": person_id, "expires_at": expires_at},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="role_grant.issue", object_type="role_grant", event_type="identity.role_granted",
        apply=apply, reason=reason,
    )  # fmt: skip
    return {
        "grant_id": str(grant_id),
        "person_id": str(person_id),
        "role": role,
        "scope": scope,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "issued_by": str(ctx.person_id),
        "requires_mfa": role in ELEVATED_ROLES,
    }


def revoke_grant(
    conn: Connection, ctx: RequestContext, *, grant_id: uuid.UUID, reason: str
) -> dict[str, Any]:
    if len(reason.strip()) < 5:
        raise PolicyViolation(details={"reason": "reason_required"})
    row = conn.execute(
        text("SELECT person_id, role, revoked_at FROM role_grants WHERE id = :id FOR UPDATE"),
        {"id": grant_id},
    ).first()
    if row is None:
        raise NotFound()
    if row[2] is not None:
        raise PolicyViolation(details={"reason": "already_revoked"})

    def apply(c: Connection) -> MutationResult:
        r = c.execute(
            text(
                "UPDATE role_grants SET revoked_at = now(), revoked_by = :by, revoke_reason = :reason,"
                " version = version + 1 WHERE id = :id RETURNING version"
            ),
            {"by": ctx.person_id, "reason": reason.strip(), "id": grant_id},
        ).one()
        return MutationResult(
            object_id=grant_id,
            object_version=int(r[0]),
            before={"revoked": False},
            after={"revoked": True},
            event_payload={"grant_id": grant_id, "role": row[1], "person_id": row[0]},
        )

    mutation(
        conn, ctx, operation="role_grant.revoke", object_type="role_grant", event_type="identity.role_revoked",
        apply=apply, reason=reason,
    )  # fmt: skip
    return {"grant_id": str(grant_id), "revoked": True}


def list_grants(conn: Connection, *, after: uuid.UUID | None, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, person_id, role, scope, issued_by, reason, issued_at, not_before, expires_at, revoked_at,"
            " revoke_reason FROM role_grants WHERE (CAST(:after AS uuid) IS NULL OR id > CAST(:after AS uuid))"
            " ORDER BY id LIMIT :limit"
        ),
        {"after": after, "limit": limit},
    ).mappings()
    out: list[dict[str, Any]] = []
    for r in rows:
        item: dict[str, Any] = {}
        for key, value in dict(r).items():
            if isinstance(value, uuid.UUID):
                item[key] = str(value)
            elif isinstance(value, datetime):
                item[key] = value.isoformat()
            else:
                item[key] = value
        out.append(item)
    return out
