"""HTTP routes: invitations (visitor passes) and their redemption at the gate.

REQ: GATE-01 (signed QR without personal data, windows, max uses, rate-limited codes, versioned revocation), GATE-08 (a
phone-free host-issued pass), PRD 12.1 (``POST /v1/societies/{id}/invitations`` -> signed pass; ``DELETE
/v1/invitations/{id}`` -> revocation version), INV-01, GATE-13.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from dwaar_common.errors import InvalidSchema, NotFound

from ...core import ratelimit
from ...core.authz import AuthContext, idempotency_exempt, require
from ...core.idempotency import IdempotentCall, idempotency_required
from . import invitations
from . import policy as policy_mod
from .config import VisitsConfig
from .deps import covered, visits_config
from .schemas import InvitationCreate, InvitationRedeem

router = APIRouter(prefix="/v1", tags=["invitations"])


# REQ: GATE-01, GATE-08
@router.post("/societies/{society_id}/invitations", status_code=201)
def create_invitation(
    society_id: uuid.UUID,
    body: InvitationCreate,
    auth: Annotated[AuthContext, Depends(require("gate.invitation.create"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[VisitsConfig, Depends(visits_config)],
) -> JSONResponse:
    """Host, unit, purpose, people, gate, EXPLICIT windows, max uses, vehicle -> a signed pass (QR text) and, unless
    ``with_code`` is false, a 6-digit code shown once. No raw visitor number is stored; the QR holds no personal data."""
    covered(auth, body.unit_id)
    return idem.run(
        auth,
        lambda conn: invitations.create_invitation(
            conn, auth.ctx, cfg, auth.scope.society_id, body
        ),
        status_code=201,
    )


@router.get("/societies/{society_id}/invitations")
def list_invitations(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.invitation.create"))],
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[
        Literal["draft", "active", "consumed", "expired", "revoked"] | None, Query()
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    """The household's own passes (every unit the caller's grants cover, or the one named)."""
    if unit_id is not None:
        covered(auth, unit_id)
        units = [unit_id]
    else:
        units = sorted(auth.scope.unit_ids, key=lambda u: u.int)
    with auth.tx() as conn:
        invitations.expire_invitations(conn, auth.ctx)
        items = invitations.list_invitations(
            conn, units, viewer=auth.principal.person_id, state=state, limit=limit
        )
    return {"items": items}


@router.get("/societies/{society_id}/invitations/{invitation_id}")
def get_invitation(
    society_id: uuid.UUID,
    invitation_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.invitation.create"))],
    cfg: Annotated[VisitsConfig, Depends(visits_config)],
) -> dict[str, Any]:
    """One pass of the caller's household, with its QR text again (the code is never re-shown: only its hash exists)."""
    from . import tokens

    with auth.tx() as conn:
        unit = invitations.invitation_unit(conn, invitation_id)
        if unit is None or not auth.scope.covers_unit(unit):
            raise NotFound()
        invitations.expire_invitations(conn, auth.ctx)
        view = invitations.get_invitation(conn, invitation_id, viewer=auth.principal.person_id)
        nonce = conn.execute(
            text(
                "SELECT token_nonce, gate_id, window_start, window_end FROM invitations WHERE id = :id"
            ),
            {"id": invitation_id},
        ).one()
    if view is None:
        raise NotFound()
    if view["state"] == "active":
        view["qr"] = tokens.build_qr(
            cfg, invitation_id=invitation_id, society_id=auth.scope.society_id, nonce=nonce[0],
            not_before=nonce[2], expires=nonce[3], gate_id=nonce[1],
        )  # fmt: skip
    return view


# REQ: GATE-01
@router.delete(
    "/invitations/{invitation_id}",
    dependencies=[
        Depends(
            idempotency_exempt(
                "revoking is naturally idempotent: a second DELETE answers with the first revocation version"
            )
        )
    ],
)
def revoke_invitation(
    invitation_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("gate.invitation.create"))],
) -> dict[str, Any]:
    """Revoke a pass (society chosen by ``X-Society-Id``). The answer carries the society's monotonic REVOCATION VERSION,
    which the next policy snapshot publishes; visits authorised from the pass and not yet entered are cancelled."""
    with auth.tx() as conn:
        unit = invitations.invitation_unit(conn, invitation_id)
        if unit is None or not auth.scope.covers_unit(unit):
            raise NotFound()
        return invitations.revoke_invitation(conn, auth.ctx, auth.scope.society_id, invitation_id)


# REQ: GATE-01
@router.post("/societies/{society_id}/invitations/redeem", status_code=201)
def redeem_invitation(
    society_id: uuid.UUID,
    body: InvitationRedeem,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("gate.invitation.redeem"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[VisitsConfig, Depends(visits_config)],
) -> JSONResponse:
    """The guard presents a pass. QR: signature, nonce, windows, revocation, uses and gate are checked. A 6-digit code needs
    the destination unit and is rate-limited per unit and per guard BEFORE anything is looked up (10^6 codes must not be
    guessable). Result: an AUTHORISED visit; entry is a separate observation (INV-07)."""
    if body.qr is None and (body.code is None or body.unit_id is None):
        raise InvalidSchema.for_fields([("code", "qr_or_code_with_unit_required")])
    if body.qr is None:
        db = request.app.state.db
        sid = auth.scope.society_id
        ratelimit.enforce(
            db, f"visits:code:unit:{sid}:{body.unit_id}", capacity=cfg.code_unit_capacity,
            refill_per_second=cfg.code_unit_capacity / cfg.code_unit_refill_seconds,
        )  # fmt: skip
        ratelimit.enforce(
            db, f"visits:code:actor:{sid}:{auth.principal.person_id}", capacity=cfg.code_actor_capacity,
            refill_per_second=cfg.code_actor_capacity / cfg.code_actor_refill_seconds,
        )  # fmt: skip

    def work(conn: Any) -> dict[str, Any]:
        policy = policy_mod.load_policy(conn)
        return invitations.redeem(conn, auth.ctx, cfg, auth.scope.society_id, body, policy)

    return idem.run(auth, work, status_code=201)
