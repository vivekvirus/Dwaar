"""HTTP routes of the resident side: devices, diagnostic, preferences, household settings, inbox, deep link, receipt, action.

REQ: NOTIF-02, NOTIF-04, NOTIF-05, NOTIF-06, NOTIF-09, IAM-11, INV-01 (the society comes from the validated path; every id is looked up under the
caller's RLS context and unit coverage: another society's, another person's and a made-up id are the SAME ``not_found``), INV-03 (an action goes
through the visits service, never around it), PRD 12 (Idempotency-Key on writes; receipts are naturally idempotent and say so).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from ...core.authz import AuthContext, idempotency_exempt, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import (
    PageParams,
    Paginator,
    SortColumn,
    get_paginator,
    page_params,
    parse_filters,
)
from ..visits import approvals, common
from ..visits import policy as policy_mod
from . import catalog, devices, households, service, views
from .schemas import (
    ActionIn,
    DiagnosticIn,
    PreferencesIn,
    PushTokenIn,
    ReceiptIn,
    UnitSettingsIn,
)

router = APIRouter(prefix="/v1/societies/{society_id}", tags=["notifications"])


# ------------------------------------------------------------------------------------------------------------ devices (IAM-11, NOTIF-06)
# REQ: NOTIF-07
@router.post("/push-tokens", status_code=201)
def register_push_token(
    society_id: uuid.UUID,
    body: PushTokenIn,
    auth: Annotated[AuthContext, Depends(require("notification.device.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Register (or refresh) the caller's own device. The token is stored as a hash and a short reference only (simulated FCM / APNs)."""

    def work(conn: Any) -> dict[str, Any]:
        return devices.register_token(
            conn, auth.ctx, auth.principal.person_id, platform=body.platform, token=body.token, device_label=body.device_label,
            device_model=body.device_model, manufacturer=body.manufacturer, os_name=body.os_name, os_version=body.os_version,
            app_version=body.app_version, notification_permission=body.notification_permission, simulation=body.simulation,
        )  # fmt: skip

    return idem.run(auth, work, status_code=201)


@router.get("/push-tokens")
def list_push_tokens(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.device.manage"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return {"items": devices.list_tokens(conn, auth.principal.person_id)}


@router.delete("/push-tokens/{token_id}")
def revoke_push_token(
    society_id: uuid.UUID,
    token_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.device.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Revoke one of the caller's own devices. Somebody else's token looks exactly like an unknown one."""

    def work(conn: Any) -> dict[str, Any]:
        return devices.revoke_own(conn, auth.ctx, auth.principal.person_id, token_id)

    return idem.run(auth, work)


# REQ: NOTIF-06
@router.get("/device-diagnostics/guidance")
def diagnostic_guidance(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.device.manage"))],
    manufacturer: Annotated[str | None, Query(max_length=40)] = None,
) -> dict[str, Any]:
    """Manufacturer-specific steps for the on-device onboarding diagnostic (Xiaomi/HyperOS, Oppo/ColorOS, Vivo/Funtouch, Samsung, iOS Focus).
    Keys of the i18n catalogue, never prose. States, in every answer, that a battery exemption does not guarantee delivery and that there is no
    fake incoming-call screen."""
    if manufacturer:
        return {
            "guidance": [catalog.guidance_for(manufacturer)],
            "rules": dict(catalog.GUIDANCE_RULES),
        }
    return {"guidance": catalog.all_guidance(), "rules": dict(catalog.GUIDANCE_RULES)}


@router.post("/device-diagnostics", status_code=201)
def submit_diagnostic(
    society_id: uuid.UUID,
    body: DiagnosticIn,
    auth: Annotated[AuthContext, Depends(require("notification.device.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Store the on-device diagnostic result; answer with the steps for what is wrong. Never "delivery guaranteed"."""

    def work(conn: Any) -> dict[str, Any]:
        return devices.submit_diagnostic(
            conn, auth.ctx, auth.principal.person_id, token_id=body.token_id, manufacturer=body.manufacturer,
            device_model=body.device_model, os_name=body.os_name, os_version=body.os_version,
            notification_permission=body.notification_permission, battery_optimisation=body.battery_optimisation,
            focus_mode_blocks=body.focus_mode_blocks, test_push=body.test_push, simulation=body.simulation,
        )  # fmt: skip

    return idem.run(auth, work, status_code=201)


# ------------------------------------------------------------------------------------------------------------ preferences (NOTIF-09)
@router.get("/notification-preferences/me")
def get_my_preferences(
    society_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.preferences.manage"))],
) -> dict[str, Any]:
    with auth.tx() as conn:
        return households.get_preferences(conn, auth.principal.person_id).view()


@router.put("/notification-preferences/me")
def put_my_preferences(
    society_id: uuid.UUID,
    body: PreferencesIn,
    auth: Annotated[AuthContext, Depends(require("notification.preferences.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The lock-screen identity opt-in and the WhatsApp / SMS opt-ins are the resident's own choice, nobody else's (NOTIF-09)."""

    def work(conn: Any) -> dict[str, Any]:
        return households.put_preferences(
            conn, auth.ctx, auth.principal.person_id, show_identity_on_lockscreen=body.show_identity_on_lockscreen,
            whatsapp_opt_in=body.whatsapp_opt_in, sms_opt_in=body.sms_opt_in, language=body.language,
        )  # fmt: skip

    return idem.run(auth, work)


# ------------------------------------------------------------------------------------------------------------ household settings (NOTIF-03, AT-11)
@router.get("/units/{unit_id}/notification-settings")
def get_unit_settings(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    auth: Annotated[
        AuthContext, Depends(require("notification.settings.read", unit_param="unit_id"))
    ],
) -> dict[str, Any]:
    """The household's primary approver, selected approvers, alternate adult and fallback; defaults when nothing was set."""
    with auth.tx() as conn:
        common.require_unit(conn, unit_id)
        stored = households.get_unit_settings(conn, unit_id)
        resolved = households.resolve_household(conn, unit_id)
    view = (
        stored.view()
        if stored
        else {"unit_id": unit_id, "primary_person_id": None, "approver_person_ids": [], "alternate_person_id": None,
              "fallback_mode": "call", "version": 0}
    )  # fmt: skip
    view["effective"] = {
        "approver_count": len(resolved.approvers),
        "has_alternate": resolved.alternate is not None,
        "fallback_mode": resolved.fallback_mode,
        "defaults_in_use": stored is None,
    }
    return view


@router.put("/units/{unit_id}/notification-settings")
def put_unit_settings(
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    body: UnitSettingsIn,
    auth: Annotated[
        AuthContext, Depends(require("notification.settings.manage", unit_param="unit_id"))
    ],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Everyone named must be someone who may decide for the unit right now, and an adult; the alternate differs from the primary."""

    def work(conn: Any) -> dict[str, Any]:
        return households.put_unit_settings(
            conn, auth.ctx, unit_id, primary_person_id=body.primary_person_id, approver_person_ids=body.approver_person_ids,
            alternate_person_id=body.alternate_person_id, fallback_mode=body.fallback_mode, expected_version=body.expected_version,
        )  # fmt: skip

    return idem.run(auth, work)


# ------------------------------------------------------------------------------------------------------------ inbox (NOTIF-02, NOTIF-05)
@router.get("/notifications")
def list_my_notifications(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("notification.inbox.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    """The caller's own notifications, newest first, only about units they currently belong to. A provider's acceptance is
    ``provider_accepted``; ``person_reached`` needs the app's own receipt."""
    parse_filters(dict(request.query_params), {})
    where = ["n.recipient_person_id = :p"]
    params: dict[str, Any] = {"p": auth.principal.person_id}
    filters: dict[str, Any] = {"p": auth.principal.person_id}
    if not auth.scope.society_wide:
        units = sorted(auth.scope.unit_ids, key=lambda u: u.int) or [uuid.UUID(int=0)]
        where.append("(n.request_id IS NULL OR r.unit_id = ANY(:units))")
        params["units"] = units
        filters["units"] = ",".join(str(u) for u in units)
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql=f"SELECT {views.N_COLUMNS} FROM notifications n"  # noqa: S608
            " LEFT JOIN approval_requests r ON r.society_id = n.society_id AND r.id = n.request_id",
            where=where,
            params=params,
            sort=[
                SortColumn("n.created_at", "timestamptz", nullable=False),
                SortColumn("n.id", "uuid", nullable=False),
            ],
            page=page,
            society_id=auth.scope.society_id,
            filters=filters,
            descending=True,
        )
    return {
        "items": [views.notification_view(r, audience="resident") for r in result.items],
        "next_cursor": result.next_cursor,
    }


@router.get("/notifications/{notification_id}")
def open_notification(
    society_id: uuid.UUID,
    notification_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("notification.inbox.read"))],
) -> dict[str, Any]:
    """The deep link of a notification (NOTIF-05): the exact request, with its CURRENT state (expired and decided requests say so), whether
    an action is still possible, and nothing from the state at send time. The first fetch by the recipient is the app's own receipt."""
    with auth.tx() as conn:
        return service.deep_link(
            conn, auth.ctx, auth.scope, auth.principal.person_id, notification_id
        )


@router.post(
    "/notifications/{notification_id}/receipt",
    dependencies=[
        Depends(
            idempotency_exempt(
                "a receipt is naturally idempotent: the first report of each fact wins and a repeat changes nothing"
            )
        )
    ],
)
def report_receipt(
    society_id: uuid.UUID,
    notification_id: uuid.UUID,
    body: ReceiptIn,
    auth: Annotated[AuthContext, Depends(require("notification.inbox.read"))],
) -> dict[str, Any]:
    """The recipient's app reports ``app_received`` or ``displayed``. Only the recipient can: no one else's report moves a state."""
    with auth.tx() as conn:
        return service.receipt(
            conn,
            auth.ctx,
            auth.scope,
            auth.principal.person_id,
            notification_id,
            body.event,
            body.observed_at,
        )


@router.post("/notifications/{notification_id}/action")
def act_on_notification(
    society_id: uuid.UUID,
    notification_id: uuid.UUID,
    body: ActionIn,
    auth: Annotated[AuthContext, Depends(require("notification.action"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Approve or deny from the lock screen or a deep link. Membership is re-checked and the decision is made by the visits service: after
    expiry the answer is 409 ``request_expired`` and no permission exists; after an earlier decision, 409 ``already_decided`` with the
    canonical state (NOTIF-04, NOTIF-05, INV-03)."""
    with auth.tx() as conn:
        row = service.fetch_own(conn, auth.scope, auth.principal.person_id, notification_id)
        if row["request_id"] is not None:
            # an expiry that is due is persisted first, so a late action reports the expiry truthfully and the 409 below cannot roll it back
            approvals.expire_due_requests(conn, auth.ctx, request_id=row["request_id"])

    def work(conn: Any) -> dict[str, Any]:
        policy = policy_mod.load_policy(conn)
        return service.act(
            conn, auth.ctx, auth.scope, auth.principal.person_id, notification_id, action=body.action,
            client_action_id=body.client_action_id, expected_version=body.expected_version, policy=policy,
        )  # fmt: skip

    return idem.run(auth, work)
