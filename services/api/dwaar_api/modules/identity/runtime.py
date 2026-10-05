"""The identity runtime object (``app.state.identity``) and its dev-only simulator surface.

REQ: IAM-06 (in local simulator mode the OTP is exposed ONLY through a clearly labelled dev-only endpoint),
IAM-14, BUILD_BRIEF section 3 (simulators only in local/test, labelled simulation=true).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from dwaar_common.crypto import DecryptionError
from dwaar_common.errors import NotFound

from ...core.authz import public_route
from ...core.db import Database
from . import crypto, store
from .auth_service import AuthService
from .config import IdentityConfig
from .issuer import SimulatorIssuer, TokenIssuer


@dataclass
class IdentityRuntime:
    db: Database
    config: IdentityConfig
    auth: AuthService
    issuer: TokenIssuer | None


def runtime(request: Request) -> IdentityRuntime:
    rt: IdentityRuntime = request.app.state.identity
    return rt


Runtime = Annotated[IdentityRuntime, Depends(runtime)]

sim_router = APIRouter(tags=["simulator"])


class DevOtpOut(BaseModel):
    simulation: bool = True
    warning: str = "DEV-ONLY SIMULATOR ENDPOINT: exposes a one-time code that a real SMS gateway would deliver by SMS."
    phone_masked: str
    template_id: str
    otp: str = Field(repr=False)
    created_at: str


@sim_router.get(
    "/v1/dev/otp",
    response_model=DevOtpOut,
    dependencies=[Depends(public_route("dev-only simulator endpoint, mounted only when DWAAR_ENV is local or test"))],
)
def dev_latest_otp(phone: str, rt: Runtime) -> DevOtpOut:
    """The latest live OTP for a number, from the labelled simulator delivery queue (never mounted elsewhere)."""
    from dwaar_common.crypto import InvalidPhoneError
    from dwaar_common.errors import InvalidSchema
    from dwaar_common.masking import mask_phone

    try:
        e164 = crypto.normalise_phone(phone)
    except InvalidPhoneError:
        raise InvalidSchema.for_fields([("phone", "invalid_phone")]) from None
    token = crypto.phone_token(rt.config, e164)
    with rt.db.app_tx() as conn:
        found = store.dev_otp_latest(conn, token)
    if found is None:
        raise NotFound()
    delivery_id, enc, template_id, created = found
    try:
        payload: dict[str, Any] = json.loads(rt.config.cipher.decrypt(enc, crypto.delivery_aad(delivery_id)))
    except (DecryptionError, ValueError):
        raise NotFound() from None
    return DevOtpOut(
        phone_masked=mask_phone(e164), template_id=template_id, otp=str(payload["params"]["otp"]),
        created_at=created.isoformat(),
    )  # fmt: skip


oidc_router = APIRouter(tags=["simulator"])


@oidc_router.get(
    "/.well-known/openid-configuration",
    dependencies=[Depends(public_route("OIDC discovery of the labelled local simulator issuer (local/test only)"))],
)
def discovery(request: Request, rt: Runtime) -> dict[str, Any]:
    issuer = rt.issuer
    if not isinstance(issuer, SimulatorIssuer):
        raise NotFound()
    return issuer.discovery(str(request.base_url))


@oidc_router.get(
    "/.well-known/jwks.json",
    dependencies=[Depends(public_route("public signing keys of the labelled local simulator issuer (local/test only)"))],
)
def jwks(rt: Runtime) -> dict[str, Any]:
    issuer = rt.issuer
    if not isinstance(issuer, SimulatorIssuer):
        raise NotFound()
    return issuer.jwks
