"""Authentication flows: phone OTP, tokens, rotating refresh, session list/revoke, TOTP step-up, number change.

REQ: IAM-06 (OTP: rate limits, expiry, attempt lock, DLT template, no membership disclosure, plaintext never stored or
logged, proves control of a number NOT ownership), IAM-08 (short access tokens, rotating refresh with reuse detection,
device list, revocation), IAM-03 (MFA), IAM-11 (recycled numbers / number change), IAM-14.

Uniform failure: every way an OTP can be wrong (no challenge, wrong code, expired, locked, replayed) is the same bare
401 ``unauthenticated``; a phone number that is unknown to the platform behaves exactly like a known one up to and
including the response body of ``/otp/request`` (OTPs are issued, rate-limited and delivered for ANY valid number).
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pyotp
from sqlalchemy import Connection

from dwaar_common.crypto import DecryptionError, InvalidPhoneError
from dwaar_common.errors import (
    DependencyUnavailable,
    InvalidSchema,
    NotAuthorised,
    PolicyViolation,
    RateLimited,
    StaleVersion,
    Unauthenticated,
)
from dwaar_common.ids import uuid7

from ...core import ratelimit
from ...core.audit import record_audit
from ...core.authn import Principal
from ...core.db import Database, RequestContext
from . import crypto, store
from .config import IdentityConfig
from .issuer import SimulatorIssuer, TokenIssuer

log = logging.getLogger("dwaar_api.identity.auth")
MAX_DEVICE_ID = 128


@dataclass(frozen=True)
class DeviceInfo:
    device_id: str
    label: str = "Unknown device"
    platform: str | None = None


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int
    session_id: uuid.UUID
    person_id: uuid.UUID
    simulation: bool


class AuthService:
    def __init__(self, db: Database, config: IdentityConfig, issuer: TokenIssuer | None) -> None:
        self.db = db
        self.config = config
        self.issuer = issuer

    # ------------------------------------------------------------------------------------ helpers
    def _phone(self, raw: str) -> tuple[str, str]:
        try:
            e164 = crypto.normalise_phone(raw)
        except InvalidPhoneError:
            raise InvalidSchema.for_fields([("phone", "invalid_phone")]) from None
        return e164, crypto.phone_token(self.config, e164)

    def _limit(self, scope: str, value: str, capacity: int, refill_seconds: int) -> None:
        ratelimit.enforce(
            self.db,
            crypto.rate_key(self.config, scope, value),
            capacity=capacity,
            refill_per_second=capacity / max(1, refill_seconds),
        )

    def _audit(
        self, conn: Connection, operation: str, *, person: uuid.UUID | None, obj: uuid.UUID | None,
        object_type: str, diff: dict[str, Any] | None = None, request_id: uuid.UUID | None = None,
    ) -> None:  # fmt: skip
        record_audit(
            conn,
            RequestContext(person_id=person, actor_role="auth", request_id=request_id),
            operation=operation,
            object_type=object_type,
            object_id=obj,
            diff=diff or {},
            platform_level=True,
        )

    def _issue_pair(
        self, person_id: uuid.UUID, session_id: uuid.UUID, refresh_secret: str
    ) -> TokenPair:
        if self.issuer is None:
            # blocked-external: a production deployment mints access tokens through its OIDC provider's token endpoint
            log.error("no token issuer configured; cannot complete sign-in")
            raise DependencyUnavailable(retry_after=30)
        access = self.issuer.mint(person_id, session_id, ttl_seconds=self.config.access_ttl_seconds)
        return TokenPair(
            access, refresh_secret, self.config.access_ttl_seconds, session_id, person_id,
            self.issuer.simulation,
        )  # fmt: skip

    # ------------------------------------------------------------------------------------ OTP request
    def otp_request(self, raw_phone: str, client_ip: str, request_id: uuid.UUID) -> dict[str, Any]:
        cfg = self.config
        e164, token = self._phone(raw_phone)
        self._limit("otp_req_ip", client_ip, cfg.ip_capacity, cfg.ip_refill_seconds)
        self._limit(
            "otp_req_phone", token, cfg.otp_request_capacity, cfg.otp_request_refill_seconds
        )
        self._issue_challenge(token, e164, purpose="login", person_id=None, request_id=request_id)
        return self._accepted()

    def _accepted(self) -> dict[str, Any]:
        return {
            "status": "accepted",
            "expires_in_seconds": self.config.otp_ttl_seconds,
            "resend_after_seconds": self.config.otp_request_refill_seconds
            // self.config.otp_request_capacity,
            "simulation": self.config.simulation,
        }

    def _issue_challenge(
        self,
        token: str,
        e164: str,
        *,
        purpose: str,
        person_id: uuid.UUID | None,
        request_id: uuid.UUID,
    ) -> None:
        cfg = self.config
        cid, did = uuid7(), uuid7()
        code = crypto.new_otp_code()
        # The delivery message: DLT template id + parameters. ENCRYPTED, bound to the delivery id, cleared on use.
        payload = json.dumps(
            {
                "to": e164,
                "template_id": cfg.dlt_template_id,
                "template_key": cfg.dlt_template_text_key,
                "params": {"otp": code, "valid_minutes": cfg.otp_ttl_seconds // 60},
            },
            separators=(",", ":"),
        )
        enc = cfg.cipher.encrypt(payload, crypto.delivery_aad(did))
        with self.db.app_tx(RequestContext(person_id=person_id)) as conn:
            store.otp_issue(
                conn, challenge_id=cid, token=token, purpose=purpose, person_id=person_id,
                code_hash=crypto.otp_hash(cfg, token, cid, code), ttl_seconds=cfg.otp_ttl_seconds,
                max_attempts=cfg.otp_max_attempts, delivery_id=did, template_id=cfg.dlt_template_id,
                payload_enc=enc, simulation=cfg.simulation,
            )  # fmt: skip
            self._audit(
                conn, f"auth.otp_{purpose}_issued", person=person_id, obj=cid, object_type="otp_challenge",
                request_id=request_id,
            )  # fmt: skip

    # ------------------------------------------------------------------------------------ OTP verify
    def otp_verify(
        self, raw_phone: str, code: str, device: DeviceInfo, client_ip: str, request_id: uuid.UUID
    ) -> TokenPair:
        cfg = self.config
        e164, token = self._phone(raw_phone)
        self._limit("otp_ver_ip", client_ip, cfg.ip_capacity, cfg.ip_refill_seconds)
        self._limit("otp_ver_phone", token, cfg.otp_verify_capacity, cfg.otp_verify_refill_seconds)
        challenge_id, consumed = self._verify_and_consume(token, "login", code, request_id)
        if consumed.purpose != "login":
            raise Unauthenticated()
        person_id = uuid7()
        enc = cfg.cipher.encrypt(e164, crypto.vault_aad(person_id, "phone"))
        session_id, refresh_id = uuid7(), uuid7()
        secret = crypto.new_refresh_secret()
        with self.db.app_tx() as conn:
            login = store.login_person(
                conn, new_id=person_id, token=token, phone_enc=enc, display_name="Resident",
                dormancy_days=cfg.phone_dormancy_days,
            )  # fmt: skip
            store.session_create(
                conn, session_id=session_id, person_id=login.person_id, challenge_id=challenge_id,
                device_id=device.device_id[:MAX_DEVICE_ID], label=device.label[:120] or "Unknown device",
                platform=device.platform, refresh_id=refresh_id, refresh_hash=crypto.refresh_hash(cfg, secret),
                ttl_seconds=cfg.refresh_ttl_seconds, max_sessions=cfg.max_sessions_per_person,
            )  # fmt: skip
            self._audit(
                conn, "auth.login", person=login.person_id, obj=session_id, object_type="auth_session",
                diff={"recycled_number_detected": login.recycled, "new_person": login.created},
                request_id=request_id,
            )  # fmt: skip
            if login.recycled:
                self._audit(
                    conn, "auth.phone_recycled", person=login.person_id, obj=login.person_id,
                    object_type="person", request_id=request_id,
                )  # fmt: skip
        return self._issue_pair(login.person_id, session_id, secret)

    def _verify_and_consume(
        self, token: str, purpose: str, code: str, request_id: uuid.UUID
    ) -> tuple[uuid.UUID, store.OtpConsumed]:
        cfg = self.config
        code = code.strip()
        with self.db.app_tx() as conn:
            attempt = store.otp_attempt(conn, token, purpose)
            if attempt.status == "locked":
                self._audit(
                    conn, "auth.otp_locked", person=None, obj=attempt.challenge_id,
                    object_type="otp_challenge", request_id=request_id,
                )  # fmt: skip
        if attempt.status != "ok" or attempt.challenge_id is None:
            raise Unauthenticated()
        expected = crypto.otp_hash(cfg, token, attempt.challenge_id, code)
        if not (
            code.isdigit() and len(code) == 6 and crypto.hashes_equal(expected, attempt.code_hash)
        ):
            raise Unauthenticated()
        with self.db.app_tx() as conn:
            consumed = store.otp_consume(conn, attempt.challenge_id)
        if consumed is None:
            raise Unauthenticated()
        return attempt.challenge_id, consumed

    # ------------------------------------------------------------------------------------ refresh / sessions
    def refresh(self, refresh_token: str, client_ip: str, request_id: uuid.UUID) -> TokenPair:
        cfg = self.config
        if not refresh_token or len(refresh_token) > 200:
            raise Unauthenticated()
        self._limit("refresh_ip", client_ip, cfg.ip_capacity * 2, cfg.ip_refill_seconds)
        secret = crypto.new_refresh_secret()
        with self.db.app_tx() as conn:
            rotation = store.session_rotate(
                conn, old_hash=crypto.refresh_hash(cfg, refresh_token), new_id=uuid7(),
                new_hash=crypto.refresh_hash(cfg, secret), ttl_seconds=cfg.refresh_ttl_seconds,
            )  # fmt: skip
            if rotation.outcome == "reuse":
                self._audit(
                    conn, "auth.refresh_reuse_detected", person=rotation.person_id, obj=rotation.session_id,
                    object_type="auth_session", request_id=request_id,
                )  # fmt: skip
        # (the revocation inside session_rotate is committed above, before the 401 below)
        if rotation.outcome != "ok" or rotation.session_id is None or rotation.person_id is None:
            raise Unauthenticated()
        return self._issue_pair(rotation.person_id, rotation.session_id, secret)

    def list_sessions(self, principal: Principal) -> list[store.SessionRow]:
        with self.db.app_tx(RequestContext(person_id=principal.person_id)) as conn:
            return store.session_list(conn, principal.person_id)

    def revoke_session(
        self, principal: Principal, session_id: uuid.UUID, request_id: uuid.UUID
    ) -> bool:
        with self.db.app_tx(
            RequestContext(person_id=principal.person_id, request_id=request_id)
        ) as conn:
            done = store.session_revoke(conn, principal.person_id, session_id, "user_revoked")
            if done:
                self._audit(
                    conn, "auth.session_revoked", person=principal.person_id, obj=session_id,
                    object_type="auth_session", request_id=request_id,
                )  # fmt: skip
            return done

    def revoke_others(self, principal: Principal, request_id: uuid.UUID) -> int:
        keep = _sid(principal)
        with self.db.app_tx(
            RequestContext(person_id=principal.person_id, request_id=request_id)
        ) as conn:
            n = store.session_revoke_others(conn, principal.person_id, keep, "user_revoked_others")
            self._audit(
                conn, "auth.sessions_revoked", person=principal.person_id, obj=None,
                object_type="auth_session", diff={"count": n}, request_id=request_id,
            )  # fmt: skip
            return n

    # ------------------------------------------------------------------------------------ MFA (TOTP)
    def mfa_enrol(self, principal: Principal) -> dict[str, str]:
        cfg = self.config
        secret = pyotp.random_base32()
        factor_id = uuid7()
        enc = cfg.cipher.encrypt(secret, crypto.mfa_aad(principal.person_id))
        with self.db.app_tx(RequestContext(person_id=principal.person_id)) as conn:
            if not store.mfa_enrol(conn, principal.person_id, factor_id, enc):
                raise PolicyViolation(details={"reason": "mfa_already_enrolled"})
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=str(principal.person_id), issuer_name="Dwaar"
        )
        return {"factor_id": str(factor_id), "secret": secret, "otpauth_uri": uri, "kind": "totp"}

    def _factor(self, conn: Connection, principal: Principal) -> tuple[store.MfaFactor, str]:
        factor = store.mfa_get(conn, principal.person_id)
        if factor is None:
            raise PolicyViolation(details={"reason": "mfa_not_enrolled"})
        try:
            secret = self.config.cipher.decrypt(
                factor.secret_enc, crypto.mfa_aad(principal.person_id)
            )
        except DecryptionError:
            log.error("mfa secret undecryptable")
            raise DependencyUnavailable(retry_after=30) from None
        return factor, secret

    def _check_totp(self, secret: str, last_step: int, code: str) -> int | None:
        """The TOTP step the code matches (within +-1 step), only if newer than the last accepted one."""
        totp = pyotp.TOTP(secret)
        now = totp.timecode(datetime.now(UTC))
        for step in (now - 1, now, now + 1):
            if (
                step > last_step
                and code.isdigit()
                and len(code) == 6
                and totp.at(step * totp.interval) == code
            ):
                return int(step)
        return None

    def mfa_verify(
        self, principal: Principal, code: str, *, confirm: bool, request_id: uuid.UUID
    ) -> bool:
        self._limit("mfa", str(principal.person_id), 5, 300)
        sid = _sid(principal)
        with self.db.app_tx(
            RequestContext(person_id=principal.person_id, request_id=request_id)
        ) as conn:
            factor, secret = self._factor(conn, principal)
            if confirm and factor.confirmed_at is not None:
                raise PolicyViolation(details={"reason": "mfa_already_confirmed"})
            if not confirm and factor.confirmed_at is None:
                raise PolicyViolation(details={"reason": "mfa_not_confirmed"})
            step = self._check_totp(secret, factor.last_used_step, code.strip())
            if step is None or not store.mfa_use_step(
                conn, principal.person_id, factor.id, step, confirm=confirm
            ):
                self._audit(
                    conn, "auth.mfa_failed", person=principal.person_id, obj=factor.id,
                    object_type="mfa_factor", request_id=request_id,
                )  # fmt: skip
                return False
            store.session_mark_mfa(conn, principal.person_id, sid)
            self._audit(
                conn, "auth.mfa_confirmed" if confirm else "auth.mfa_verified", person=principal.person_id,
                obj=sid, object_type="auth_session", request_id=request_id,
            )  # fmt: skip
        return True

    # ------------------------------------------------------------------------------------ number change (IAM-11)
    def phone_change_request(
        self, principal: Principal, raw_phone: str, request_id: uuid.UUID
    ) -> dict[str, Any]:
        cfg = self.config
        e164, token = self._phone(raw_phone)
        self._limit(
            "otp_req_phone", token, cfg.otp_request_capacity, cfg.otp_request_refill_seconds
        )
        self._limit("phone_change", str(principal.person_id), 5, 3600)
        self._issue_challenge(
            token,
            e164,
            purpose="phone_change",
            person_id=principal.person_id,
            request_id=request_id,
        )
        return self._accepted()

    def phone_change_confirm(
        self,
        principal: Principal,
        raw_phone: str,
        code: str,
        request_id: uuid.UUID,
        reverify: Callable[[Connection, RequestContext, list[uuid.UUID]], None],
    ) -> list[uuid.UUID]:
        """Verify the NEW number, swap it in, revoke every session and re-open the memberships, in ONE transaction.

        ``reverify`` runs inside that transaction with the societies where the person holds verified memberships.
        """
        cfg = self.config
        e164, token = self._phone(raw_phone)
        self._limit("otp_ver_phone", token, cfg.otp_verify_capacity, cfg.otp_verify_refill_seconds)
        challenge_id, consumed = self._verify_and_consume(token, "phone_change", code, request_id)
        if consumed.person_id != principal.person_id:
            raise Unauthenticated()
        enc = cfg.cipher.encrypt(e164, crypto.vault_aad(principal.person_id, "phone"))
        ctx = RequestContext(
            person_id=principal.person_id, actor_role="resident", request_id=request_id
        )
        with self.db.app_tx(ctx) as conn:
            result = store.change_phone(conn, principal.person_id, challenge_id, token, enc)
            if result == "conflict":
                raise StaleVersion()  # generic: never says whether the number exists
            if result != "ok":
                raise NotAuthorised()
            self._audit(
                conn, "auth.phone_changed", person=principal.person_id, obj=principal.person_id,
                object_type="person", request_id=request_id,
            )  # fmt: skip
            overview = store.access_overview(conn, principal.person_id)
            societies = sorted(
                {r.society_id for r in overview
                 if r.source_kind == "membership" and r.verification in ("verified", "disputed")},
                key=str,
            )  # fmt: skip
            reverify(conn, ctx, societies)
        return societies


def _sid(principal: Principal) -> uuid.UUID:
    try:
        return uuid.UUID(principal.session_id or "")
    except ValueError:
        raise Unauthenticated() from None


def make_service(db: Database, config: IdentityConfig, issuer: TokenIssuer | None) -> AuthService:
    return AuthService(db, config, issuer)


__all__ = [
    "AuthService",
    "DeviceInfo",
    "RateLimited",
    "SimulatorIssuer",
    "TokenPair",
    "make_service",
]
