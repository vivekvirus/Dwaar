"""Permission declarations of the notifications module (PRD 5.2 has no "notifications" row: declared HERE, module-locally).

REQ: PRD 5.1 / 5.2, NOTIF-01..09, CALL-01, IAM-08, INV-01.

The role sets reuse the visits module's, which are DERIVED from the identity matrix (gate operations): the household that decides an approval is
the household that receives it; gate staff see the status board; society roles read the metrics. Matrix gaps (no column for GUARD_SUP, no row for
notification settings, provider registry, budgets or templates) are recorded as requests in the slice 4 report.
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix
from ..visits.permissions import GATE_READERS, GATE_STAFF, GUARD_SUP, HOUSEHOLD, SECRETARY

RESIDENTS: Final = frozenset(matrix.RESIDENT_ROLES)
OPS_READERS: Final = GATE_READERS | {GUARD_SUP}

permissions: Final = (
    # ------------------------------------------------------------------------------------------ the resident's own device and inbox
    Permission(
        "notification.device.manage",
        RESIDENTS,
        scope=ScopeKind.UNIT,
        description="Register, list and revoke the caller's own push devices; submit the on-device diagnostic (NOTIF-06)",
    ),
    Permission(
        "notification.inbox.read",
        RESIDENTS,
        scope=ScopeKind.UNIT,
        description="Read the caller's own notifications, deep-link to one (the CURRENT request state is fetched, NOTIF-05) and report receipt",
    ),
    Permission(
        "notification.action",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Act on an approval from a notification (lock-screen action or deep link): membership is re-checked and the decision is "
        "made by the visits service (NOTIF-05)",
    ),
    Permission(
        "notification.preferences.manage",
        RESIDENTS,
        scope=ScopeKind.UNIT,
        description="Read and set the caller's own lock-screen identity opt-in and WhatsApp / SMS opt-ins (NOTIF-09)",
    ),
    Permission(
        "notification.settings.manage",
        HOUSEHOLD,
        scope=ScopeKind.UNIT,
        description="Set the household's primary approver, selected approvers, alternate adult and fallback (call or intercom); NOTIF-03, AT-11",
    ),
    Permission(
        "notification.settings.read",
        HOUSEHOLD | GATE_READERS,
        scope=ScopeKind.UNIT,
        description="Read the household's notification settings: the household of the unit, or a society role",
    ),
    # ------------------------------------------------------------------------------------------ gate staff
    Permission(
        "notification.status.read",
        GATE_STAFF | GATE_READERS,
        description="The status board of one approval request: cascade steps, honest notification states, fallback and guard options (no numbers)",
    ),
    Permission(
        "notification.call.start",
        GATE_STAFF,
        description="Start a TTL-bound masked call to the household's primary or alternate approver for a request (CALL-01); at most one per role "
        "per attempt",
    ),
    Permission(
        "notification.call.read",
        GATE_STAFF | GATE_READERS,
        description="Read a proxy-call session: state, dial outcome and duration (never audio, never a number)",
    ),
    Permission(
        "notification.cascade.restart",
        frozenset({GUARD_SUP}),
        description="Start a new notification attempt for a still-pending request (the only way past one primary and one alternate call)",
        sensitive=True,
    ),
    # ------------------------------------------------------------------------------------------ administrators
    Permission(
        "notification.provider.read",
        frozenset({SECRETARY, matrix.ESTATE_MGR}),
        description="The provider adapter registry, including what is NOT configured and the specific missing dependency (administrators only)",
    ),
    Permission(
        "notification.metrics.read",
        OPS_READERS,
        description="Budget metrics: notifications and calls per 1,000 arrivals, failed calls, fallback share, acknowledgement rate (PRD 9.4, 18.1)",
    ),
    Permission(
        "notification.health.read",
        OPS_READERS,
        description="Delivery telemetry by phone model and OS version (NOTIF-07)",
    ),
    Permission(
        "notification.budget.read",
        OPS_READERS,
        description="Read the society's monthly notification, call and SMS caps and counters",
    ),
    Permission(
        "notification.budget.manage",
        frozenset({SECRETARY}),
        description="Set the monthly caps (they never block security or emergency sends)",
        sensitive=True,
    ),
    Permission(
        "notification.template.read",
        frozenset({SECRETARY, matrix.COMMITTEE, matrix.ESTATE_MGR}),
        description="Read the notification templates, DLT placeholders and whitelisted URLs",
    ),
    Permission(
        "notification.template.manage",
        frozenset({SECRETARY}),
        description="Register a notification template (content-class validator; DLT ids; whitelisted URLs only)",
        sensitive=True,
    ),
)
