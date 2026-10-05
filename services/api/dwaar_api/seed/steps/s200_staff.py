"""Identity and access: staff and committee role grants, and the synthetic MFA enrolment of elevated-role holders.

REQ: IAM-02 (grants carry issuer, reason and expiry), IAM-03 (elevated roles need MFA; no self-grant), IAM-13 (the first
secretary of a society is issued out of band by the platform operator; everyone else by that secretary through the same
``identity.grants.issue_grant`` the API route calls).

Elevated holders (secretary, treasurer, committee, estate manager, guard supervisor, auditor) get a CONFIRMED TOTP factor
whose secret is derived from their fictional phone number (``people.totp_secret``), so the local demo can complete the
step-up. Guards are not elevated (PRD 5.1: guards use device login, IAM-10 is a later slice) and get no factor.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import text

from dwaar_common.timeutil import utc_now

from ...core.audit import record_audit
from ...core.db import RequestContext
from ...modules.identity import crypto, grants, store
from ..dataset import AUDITOR_DAYS, ELEVATED, STAFF_GRANTS, StaffGrant
from ..ids import scoped_uuid
from ..people import by_key, totp_secret
from ..runtime import SeedContext

NAME = "staff"
ORDER = 200


def _has_grant(ctx: SeedContext, sid: uuid.UUID, pid: uuid.UUID, role: str) -> bool:
    with ctx.tx(f"grant-read:{sid}:{pid}:{role}", society=sid, role="seed") as (conn, _c):
        return bool(
            conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM role_grants WHERE person_id = :p AND role = :r AND revoked_at IS NULL)"
                ),
                {"p": pid, "r": role},
            ).scalar_one()
        )


def _issue(ctx: SeedContext, g: StaffGrant) -> None:
    sid = ctx.society_id(g.society)
    pid = ctx.person(g.person)
    if _has_grant(ctx, sid, pid, g.role):
        ctx.count("grants_existing")
        return
    first = g.role == "secretary"
    issuer_key = "operator" if first else f"{g.society}.secretary"
    issuer = ctx.person(issuer_key)
    issuer_role = "platform_admin" if first else "secretary"
    expires = utc_now() + timedelta(days=AUDITOR_DAYS) if g.role == "auditor" else None
    with ctx.tx(
        f"grant:{g.society}:{g.person}:{g.role}", society=sid, person=issuer, role=issuer_role
    ) as (
        conn,
        rctx,
    ):
        grants.issue_grant(
            conn,
            rctx,
            person_id=pid,
            role=g.role,
            reason=g.reason,
            expires_at=expires,
            not_before=None,
            unit_id=None,
            introduced_by_phone=True,  # the person was introduced by phone number (iam.ensure_person), as in the route
        )
    ctx.count("grants_issued")


def ensure_mfa(ctx: SeedContext, person_key: str) -> bool:
    """Confirmed synthetic TOTP factor; True if it was created now."""
    pid = ctx.person(person_key)
    spec = by_key()[person_key]
    secret = totp_secret(crypto.normalise_phone(spec.phone))
    factor_id = scoped_uuid(f"mfa:{person_key}")
    rctx = RequestContext(
        person_id=pid, actor_role="seed", request_id=scoped_uuid(f"mfa-req:{person_key}")
    )
    with ctx.db.app_tx(rctx) as conn:
        current = store.mfa_get(conn, pid)
        if current is not None and current.confirmed_at is not None:
            return False
        enc = ctx.cipher.encrypt(secret, crypto.mfa_aad(pid))
        if not store.mfa_enrol(conn, pid, factor_id, enc):
            return False
        factor = store.mfa_get(conn, pid)
        assert factor is not None  # noqa: S101
        # step 1 is far in the past (1970): the first real code (a current step) is always newer, so it is accepted once
        store.mfa_use_step(conn, pid, factor.id, 1, confirm=True)
        record_audit(
            conn,
            rctx,
            operation="auth.mfa_seeded",
            object_type="mfa_factor",
            object_id=factor.id,
            diff={"seeded": True, "simulation": True, "kind": "totp"},
            platform_level=True,
        )
    return True


def run(ctx: SeedContext) -> None:
    ctx.person("operator")
    for g in STAFF_GRANTS:  # secretaries come first in the data, so later grants have their issuer
        _issue(ctx, g)
    enrolled = 0
    for g in STAFF_GRANTS:
        if g.role in ELEVATED and ensure_mfa(ctx, g.person):
            enrolled += 1
    ctx.count("mfa_enrolled", enrolled)
    ctx.say(f"  staff: {len(STAFF_GRANTS)} role grants, {enrolled} new synthetic MFA enrolments")
