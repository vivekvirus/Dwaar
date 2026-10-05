"""Database-backed SessionStore and GrantResolver (the concrete implementations of core.authn / core.authz protocols).

REQ: IAM-08 (revocation is immediate; sensitive actions re-check CURRENT grants from the database, never JWT claims),
IAM-02 (validity dates, expiry, verification state), IAM-03 (MFA enforced for elevated roles), INV-01.

How MFA is enforced without touching the core: when a person holds an elevated role but the session has no fresh
MFA step-up, the resolver returns that grant under the role name ``<role>_mfa_pending``. No permission lists such a
role, so the core ``decide()`` answers 403 ``not_authorised`` (the person has standing in the society but may not do
this), and ``GET /v1/me`` tells the client a step-up is needed. Nothing about the token is consulted.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from datetime import datetime

from ...core.authn import Principal
from ...core.authz import Grant
from ...core.db import Database, RequestContext
from . import store
from .config import IdentityConfig
from .matrix import ELEVATED_ROLES

log = logging.getLogger("dwaar_api.identity.glue")
MFA_PENDING_SUFFIX = "_mfa_pending"


class PgSessionStore:
    """``SessionStore`` backed by ``iam.auth_sessions``: a revoked session stops working on the very next request."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def is_active(self, *, session_id: str | None, subject: str, issued_at: datetime | None) -> bool:
        if session_id is None:
            return False  # every token this platform issues carries a sid; none means nothing to check against
        try:
            sid, pid = uuid.UUID(session_id), uuid.UUID(subject)
        except ValueError:
            return False
        with self._db.app_tx(RequestContext(person_id=pid)) as conn:
            return store.session_is_active(conn, sid, pid)


class PgGrantResolver:
    """``GrantResolver`` over memberships + role grants (via the access index), re-read on EVERY call."""

    def __init__(self, database: Database, config: IdentityConfig) -> None:
        self._db = database
        self._config = config

    def resolve(
        self, principal: Principal, *, society_hint: uuid.UUID | None, fresh: bool
    ) -> Sequence[Grant]:
        pid = principal.person_id
        with self._db.app_tx(RequestContext(person_id=pid)) as conn:
            rows = store.effective_grants(conn, pid)
            mfa_ok = False
            if principal.session_id and any(r.role in ELEVATED_ROLES for r in rows):
                try:
                    mfa_ok = store.session_mfa_fresh(
                        conn, pid, uuid.UUID(principal.session_id), self._config.mfa_ttl_seconds
                    )
                except ValueError:
                    mfa_ok = False
        grants: list[Grant] = []
        for r in rows:
            if society_hint is not None and r.society_id != society_hint:
                continue  # the hint only narrows, it never widens
            role = r.role
            if role in ELEVATED_ROLES and not mfa_ok:
                role = role + MFA_PENDING_SUFFIX
            if r.source_kind == "membership":
                # a membership grant covers the member's own unit and own person (self-service scope)
                grants.append(
                    Grant(role, r.society_id, unit_id=r.unit_id, person_id=pid,
                          not_before=r.not_before, expires_at=r.expires_at)
                )  # fmt: skip
            else:
                grants.append(
                    Grant(role, r.society_id, unit_id=r.unit_id,
                          not_before=r.not_before, expires_at=r.expires_at)
                )  # fmt: skip
        return grants
