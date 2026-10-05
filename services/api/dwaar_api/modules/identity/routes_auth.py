"""``/v1/auth`` endpoints: OTP, refresh, sessions, logout, MFA, number change.

REQ: IAM-06, IAM-08, IAM-03, IAM-11, IAM-14, PRD 12.1 (``POST /v1/auth/otp/request, /verify``: rate-limited, no
membership disclosure).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Connection

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, Unauthenticated

from ...core.authn import Principal, current_principal
from ...core.authz import idempotency_exempt, public_route
from ...core.db import RequestContext
from . import members
from .access import client_ip, request_id_of
from .auth_service import DeviceInfo, TokenPair
from .runtime import Runtime

router = APIRouter(prefix="/v1/auth", tags=["auth"])
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OtpRequestIn(Strict):
    phone: str = Field(min_length=8, max_length=24)


class DeviceIn(Strict):
    device_id: str = Field(min_length=1, max_length=128)
    label: str = Field(default="Unknown device", min_length=1, max_length=120)
    platform: str | None = Field(default=None, max_length=32)


class OtpVerifyIn(Strict):
    phone: str = Field(min_length=8, max_length=24)
    code: str = Field(min_length=6, max_length=6)
    device: DeviceIn


class RefreshIn(Strict):
    refresh_token: str = Field(min_length=10, max_length=200)


class CodeIn(Strict):
    code: str = Field(min_length=6, max_length=6)


class PhoneIn(Strict):
    phone: str = Field(min_length=8, max_length=24)


class PhoneConfirmIn(Strict):
    phone: str = Field(min_length=8, max_length=24)
    code: str = Field(min_length=6, max_length=6)


def _tokens(pair: TokenPair) -> JSONResponse:
    return JSONResponse(
        {
            "token_type": "Bearer",
            "access_token": pair.access_token,
            "expires_in": pair.expires_in,
            "refresh_token": pair.refresh_token,
            "session_id": str(pair.session_id),
            "simulation": pair.simulation,
        },
        headers=NO_STORE,
    )


Principal_ = Annotated[Principal, Depends(current_principal)]


@router.post(
    "/otp/request",
    status_code=202,
    dependencies=[Depends(public_route("sign-in starts before any identity exists"))],
)
def otp_request(body: OtpRequestIn, request: Request, rt: Runtime) -> JSONResponse:
    """Send a one-time code to a phone number. The answer is identical for every valid number (IAM-06)."""
    out = rt.auth.otp_request(body.phone, client_ip(request), request_id_of(request))
    return JSONResponse(out, status_code=202, headers=NO_STORE)


@router.post(
    "/otp/verify",
    dependencies=[Depends(public_route("exchanges a one-time code for tokens"))],
)
def otp_verify(body: OtpVerifyIn, request: Request, rt: Runtime) -> JSONResponse:
    pair = rt.auth.otp_verify(
        body.phone, body.code,
        DeviceInfo(body.device.device_id, body.device.label, body.device.platform),
        client_ip(request), request_id_of(request),
    )  # fmt: skip
    return _tokens(pair)


@router.post(
    "/refresh",
    dependencies=[
        Depends(
            public_route("the refresh token itself is the credential (rotating, reuse-detecting)")
        )
    ],
)
def refresh(body: RefreshIn, request: Request, rt: Runtime) -> JSONResponse:
    return _tokens(rt.auth.refresh(body.refresh_token, client_ip(request), request_id_of(request)))


@router.post(
    "/logout",
    status_code=204,
    dependencies=[Depends(idempotency_exempt("logout is naturally idempotent"))],
)
def logout(principal: Principal_, request: Request, rt: Runtime) -> Response:
    sid = _session(principal)
    rt.auth.revoke_session(principal, sid, request_id_of(request))
    return Response(status_code=204, headers=NO_STORE)


def _session(principal: Principal) -> uuid.UUID:
    try:
        return uuid.UUID(principal.session_id or "")
    except ValueError:
        raise Unauthenticated() from None


@router.get("/sessions")
def list_sessions(principal: Principal_, rt: Runtime) -> dict[str, Any]:
    current = principal.session_id
    return {
        "sessions": [
            {
                "id": str(s.id),
                "device_id": s.device_id,
                "device_label": s.device_label,
                "platform": s.platform,
                "created_at": s.created_at.isoformat(),
                "last_seen_at": s.last_seen_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "mfa_verified_at": s.mfa_verified_at.isoformat() if s.mfa_verified_at else None,
                "current": str(s.id) == current,
            }
            for s in rt.auth.list_sessions(principal)
        ]
    }


@router.delete(
    "/sessions/{session_id}",
    status_code=204,
    dependencies=[Depends(idempotency_exempt("revocation is naturally idempotent"))],
)
def revoke_session(
    session_id: uuid.UUID, principal: Principal_, request: Request, rt: Runtime
) -> Response:
    if not rt.auth.revoke_session(principal, session_id, request_id_of(request)):
        raise NotFound()  # someone else's session and an unknown one look the same
    return Response(status_code=204, headers=NO_STORE)


@router.delete(
    "/sessions",
    dependencies=[Depends(idempotency_exempt("revoke-all-others is naturally idempotent"))],
)
def revoke_other_sessions(principal: Principal_, request: Request, rt: Runtime) -> dict[str, int]:
    return {"revoked": rt.auth.revoke_others(principal, request_id_of(request))}


# ------------------------------------------------------------------------------------------------- MFA
@router.post(
    "/mfa/totp/enrol",
    status_code=201,
    dependencies=[
        Depends(
            idempotency_exempt("a second call while unconfirmed simply replaces the pending factor")
        )
    ],
)
def mfa_enrol(principal: Principal_, rt: Runtime) -> JSONResponse:
    """Start TOTP enrolment: the secret is returned ONCE (to scan into an authenticator) and stored encrypted."""
    return JSONResponse(rt.auth.mfa_enrol(principal), status_code=201, headers=NO_STORE)


@router.post(
    "/mfa/totp/confirm",
    dependencies=[Depends(idempotency_exempt("a TOTP step can be used once; replay is refused"))],
)
def mfa_confirm(
    body: CodeIn, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, bool]:
    if not rt.auth.mfa_verify(
        principal, body.code, confirm=True, request_id=request_id_of(request)
    ):
        raise Unauthenticated()
    return {"confirmed": True, "session_elevated": True}


@router.post(
    "/mfa/verify",
    dependencies=[Depends(idempotency_exempt("a TOTP step can be used once; replay is refused"))],
)
def mfa_verify(
    body: CodeIn, principal: Principal_, request: Request, rt: Runtime
) -> dict[str, Any]:
    """Step-up: prove the second factor for THIS session so elevated roles take effect (IAM-03)."""
    if not rt.auth.mfa_verify(
        principal, body.code, confirm=False, request_id=request_id_of(request)
    ):
        raise Unauthenticated()
    return {"session_elevated": True, "valid_for_seconds": rt.config.mfa_ttl_seconds}


# ------------------------------------------------------------------------------------------------- number change (IAM-11)
@router.post(
    "/phone/change/request",
    status_code=202,
    dependencies=[Depends(idempotency_exempt("sends a code to the NEW number; rate-limited"))],
)
def phone_change_request(
    body: PhoneIn, principal: Principal_, request: Request, rt: Runtime
) -> JSONResponse:
    out = rt.auth.phone_change_request(principal, body.phone, request_id_of(request))
    return JSONResponse(out, status_code=202, headers=NO_STORE)


@router.post(
    "/phone/change/confirm",
    dependencies=[Depends(idempotency_exempt("the one-time code is single use"))],
)
def phone_change_confirm(
    body: PhoneConfirmIn, principal: Principal_, request: Request, rt: Runtime
) -> JSONResponse:
    """Swap the number: ALL sessions are revoked (sign in again with the new number) and verified memberships go back to
    review (re-verification) because a number is not proof of who holds it."""

    def reverify(conn: Connection, ctx: RequestContext, societies: list[uuid.UUID]) -> None:
        from ...core.db import apply_context

        for society in societies:
            sctx = RequestContext(society, ctx.person_id, "self", ctx.request_id)
            apply_context(conn, sctx)
            members.reopen_for_reverification(conn, sctx, person_id=principal.person_id)
        apply_context(conn, ctx)

    societies = rt.auth.phone_change_confirm(
        principal, body.phone, body.code, request_id_of(request), reverify
    )
    return JSONResponse(
        {
            "phone_changed": True,
            "sessions_revoked": True,
            "reverification_required_in": [str(s) for s in societies],
        },
        headers=NO_STORE,
    )


__all__ = ["InvalidSchema", "PolicyViolation", "router"]
