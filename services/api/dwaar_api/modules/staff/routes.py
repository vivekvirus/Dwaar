"""HTTP routes of the staff module (PRD 9.6, STAFF-01..STAFF-05).

REQ: STAFF-01 (a guard sees only currently authorised destinations; the register is not visible to unrelated households), STAFF-02, STAFF-03,
STAFF-04 (consent first), STAFF-05 (code or card; no face-matching route exists), PRIV-03/04, INV-01 (society from ``X-Society-Id``; a unit in a
body is checked against the caller's coverage; another society's id answers exactly like a random one), PRD 12.2 errors, cursor pagination.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from dwaar_common.errors import NotFound
from dwaar_common.timeutil import utc_now

from ...core import ratelimit
from ...core.authz import AuthContext, require
from ...core.idempotency import IdempotentCall, idempotency_required
from ...core.pagination import (
    DateRange,
    PageParams,
    Paginator,
    date_range_params,
    get_paginator,
    page_params,
)
from ..identity.config import IdentityConfig
from . import attendance, payroll, service
from .permissions import GUARD, HOUSEHOLD_MANAGERS
from .schemas import (
    AttendanceCorrection,
    AttendanceCreate,
    ConsentCapture,
    ConsentWithdraw,
    CredentialIssue,
    EngagementCreate,
    EngagementEnd,
    EngagementUpdate,
    PayrollDecision,
    PayrollPropose,
    StaffRegister,
    StaffUpdate,
)

router = APIRouter(prefix="/v1", tags=["staff"])


def identity_config(request: Request) -> IdentityConfig:
    cfg: IdentityConfig = request.app.state.identity.config
    return cfg


def _audience(role: str) -> str:
    if role == GUARD:
        return "guard"
    if role in HOUSEHOLD_MANAGERS or role == "family":
        return "household"
    return "full"


def _covered(auth: AuthContext, unit_id: uuid.UUID) -> None:
    if not auth.scope.covers_unit(unit_id):
        raise NotFound()


# ------------------------------------------------------------------------------------------ consent (STAFF-04)
# REQ: STAFF-04, PRIV-03, PRIV-04
@router.post("/staff-consents", status_code=201)
def capture_consent(
    body: ConsentCapture,
    auth: Annotated[AuthContext, Depends(require("staff.consent.capture"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The consent_receipt, captured on the assisted tablet in the staff member's language BEFORE any data capture. Carries no personal data."""
    return idem.run(
        auth, lambda conn: service.capture_consent(conn, auth.ctx, body), status_code=201
    )


# REQ: STAFF-04
@router.post("/staff-consents/{consent_id}/withdraw")
def withdraw_consent(
    consent_id: uuid.UUID,
    body: ConsentWithdraw,
    auth: Annotated[AuthContext, Depends(require("staff.register.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Withdrawal blocks every further capture for that person (registration, ID, photo, attendance). It deletes nothing by itself."""
    return idem.run(auth, lambda conn: service.withdraw_consent(conn, auth.ctx, consent_id, body))


# ------------------------------------------------------------------------------------------ register
# REQ: STAFF-01, STAFF-04, PRIV-04
@router.post("/staff", status_code=201)
def register_staff(
    body: StaffRegister,
    auth: Annotated[AuthContext, Depends(require("staff.register.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[IdentityConfig, Depends(identity_config)],
) -> JSONResponse:
    """Register a person. A usable consent receipt covering every captured datum is REQUIRED (422 ``consent_scope_missing`` otherwise); an
    ID number is masked to its last 4 characters at once (never stored); police verification is a status only."""
    return idem.run(
        auth, lambda conn: service.register_staff(conn, auth.ctx, cfg, body), status_code=201
    )


@router.get("/staff")
def list_staff(
    auth: Annotated[AuthContext, Depends(require("staff.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    """Society roles: the register. A household: the staff its own units engage. A guard: only staff authorised NOW, with destinations only."""
    with auth.tx() as conn:
        return service.list_staff(
            conn, paginator, page, society_id=auth.scope.society_id, scope=auth.scope,
            audience=_audience(auth.scope.role), at=utc_now(),
        )  # fmt: skip


@router.get("/staff/{staff_id}")
def get_staff(
    staff_id: uuid.UUID, auth: Annotated[AuthContext, Depends(require("staff.read"))]
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.get_staff_for(
            conn, staff_id, scope=auth.scope, audience=_audience(auth.scope.role), at=utc_now()
        )


# REQ: STAFF-04, PRIV-04
@router.patch("/staff/{staff_id}")
def update_staff(
    staff_id: uuid.UUID,
    body: StaffUpdate,
    auth: Annotated[AuthContext, Depends(require("staff.register.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """ID capture (masked), photo reference, police-verification STATUS: each needs its purpose in the consent receipt."""
    return idem.run(auth, lambda conn: service.update_staff(conn, auth.ctx, staff_id, body))


# REQ: STAFF-05
@router.post("/staff/{staff_id}/credentials", status_code=201)
def issue_credential(
    staff_id: uuid.UUID,
    body: CredentialIssue,
    auth: Annotated[AuthContext, Depends(require("staff.register.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[IdentityConfig, Depends(identity_config)],
) -> JSONResponse:
    """A check-in CODE (shown once) or a CARD. There is no face or biometric credential, and none can be added through this API."""
    return idem.run(
        auth,
        lambda conn: service.issue_credential(conn, auth.ctx, cfg, staff_id, body),
        status_code=201,
    )


# ------------------------------------------------------------------------------------------ engagements
# REQ: STAFF-01
@router.post("/staff-engagements", status_code=201)
def create_engagement(
    body: EngagementCreate,
    auth: Annotated[AuthContext, Depends(require("staff.engagement.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """One engagement for one household with valid hours. The unit must be one the caller's grants cover (404 otherwise)."""
    _covered(auth, body.unit_id)
    return idem.run(
        auth,
        lambda conn: service.create_engagement(conn, auth.ctx, body, at=utc_now()),
        status_code=201,
    )


@router.get("/staff-engagements")
def list_engagements(
    auth: Annotated[AuthContext, Depends(require("staff.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    staff_id: Annotated[uuid.UUID | None, Query()] = None,
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[Literal["live", "ended"] | None, Query()] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return service.list_engagements(
            conn, paginator, page, society_id=auth.scope.society_id, scope=auth.scope,
            audience=_audience(auth.scope.role), at=utc_now(), staff_id=staff_id, unit_id=unit_id, state=state,
        )  # fmt: skip


def _engagement_unit_covered(auth: AuthContext, conn: Any, engagement_id: uuid.UUID) -> None:
    unit = service.engagement_unit(conn, engagement_id)
    if unit is None or not auth.scope.covers_unit(unit):
        raise NotFound()


@router.patch("/staff-engagements/{engagement_id}")
def update_engagement(
    engagement_id: uuid.UUID,
    body: EngagementUpdate,
    auth: Annotated[AuthContext, Depends(require("staff.engagement.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    return idem.run(
        auth,
        lambda conn: service.update_engagement(
            conn, auth.ctx, auth.scope, engagement_id, body, at=utc_now()
        ),
    )


# REQ: STAFF-03, AT-12
@router.post("/staff-engagements/{engagement_id}/end")
def end_engagement(
    engagement_id: uuid.UUID,
    body: EngagementEnd,
    auth: Annotated[AuthContext, Depends(require("staff.engagement.manage"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """End ONE engagement. The person's other engagements, with other households, are not touched (STAFF-03)."""
    return idem.run(
        auth,
        lambda conn: service.end_engagement(
            conn, auth.ctx, auth.scope, engagement_id, body, at=utc_now()
        ),
    )


# ------------------------------------------------------------------------------------------ attendance
# REQ: STAFF-02, STAFF-05
@router.post("/attendance", status_code=201)
def record_attendance(
    request: Request,
    body: AttendanceCreate,
    auth: Annotated[AuthContext, Depends(require("staff.attendance.record"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    cfg: Annotated[IdentityConfig, Depends(identity_config)],
) -> JSONResponse:
    """Check-in/out by code or card. An OBSERVATION: it neither grants nor removes entry. A code that matches nobody is a plain 404, and
    attempts are rate-limited per guard BEFORE the lookup."""
    sid = auth.scope.society_id
    ratelimit.enforce(
        request.app.state.db,
        f"staff:credential:{sid}:{auth.principal.person_id}",
        capacity=60,
        refill_per_second=1.0,
    )
    return idem.run(
        auth,
        lambda conn: attendance.record(conn, auth.ctx, cfg, body, now=utc_now()),
        status_code=201,
    )


@router.get("/attendance")
def list_attendance(
    auth: Annotated[AuthContext, Depends(require("staff.attendance.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    window: Annotated[DateRange, Depends(date_range_params)],
    staff_id: Annotated[uuid.UUID | None, Query()] = None,
    unit_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict[str, Any]:
    """Observations with their appended corrections and the effective values; a household sees its own engagements only."""
    with auth.tx() as conn:
        return attendance.list_attendance(
            conn, paginator, page, society_id=auth.scope.society_id, scope=auth.scope, window=window,
            staff_id=staff_id, unit_id=unit_id,
        )  # fmt: skip


# REQ: STAFF-02
@router.post("/attendance/{attendance_id}/corrections", status_code=201)
def correct_attendance(
    attendance_id: uuid.UUID,
    body: AttendanceCorrection,
    auth: Annotated[AuthContext, Depends(require("staff.attendance.correct"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Append a correction with who, why and when. The original observation is never edited."""
    return idem.run(
        auth,
        lambda conn: attendance.correct(conn, auth.ctx, auth.scope, attendance_id, body),
        status_code=201,
    )


# ------------------------------------------------------------------------------------------ payroll
# REQ: STAFF-02
@router.post("/payroll-adjustments", status_code=201)
def propose_payroll(
    body: PayrollPropose,
    auth: Annotated[AuthContext, Depends(require("staff.payroll.propose"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """Proposed (integer paise). It takes effect only when the household approves."""
    return idem.run(
        auth, lambda conn: payroll.propose(conn, auth.ctx, auth.scope, body), status_code=201
    )


@router.get("/payroll-adjustments")
def list_payroll(
    auth: Annotated[AuthContext, Depends(require("staff.payroll.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
    engagement_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[Literal["proposed", "approved", "rejected"] | None, Query()] = None,
) -> dict[str, Any]:
    with auth.tx() as conn:
        return payroll.list_adjustments(
            conn, paginator, page, society_id=auth.scope.society_id, ctx=auth.ctx, scope=auth.scope,
            engagement_id=engagement_id, state=state,
        )  # fmt: skip


# REQ: STAFF-02
@router.post("/payroll-adjustments/{adjustment_id}/decision")
def decide_payroll(
    adjustment_id: uuid.UUID,
    body: PayrollDecision,
    auth: Annotated[AuthContext, Depends(require("staff.payroll.decide"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> JSONResponse:
    """The household's approval (first valid decision wins; 409 ``already_decided`` afterwards)."""
    return idem.run(
        auth, lambda conn: payroll.decide(conn, auth.ctx, auth.scope, adjustment_id, body)
    )
