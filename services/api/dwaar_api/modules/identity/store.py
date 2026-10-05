"""Thin, typed access to the ``iam`` SQL surface (migrations 0130-0135).

REQ: ARCH-02, ARCH-03, IAM-06, IAM-08, IAM-11, INV-01.

The runtime roles hold no table privilege in schema ``iam``; every call below goes through a reviewed SECURITY
DEFINER function that checks the transaction context itself. Callers pass a connection from
``Database.app_tx(RequestContext(...))``: pre-auth flows use an empty context, authenticated ones set
``person_id`` (and ``society_id`` for society-scoped reads). Nothing here logs a phone number, OTP or token.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text


@dataclass(frozen=True)
class GrantRow:
    source_kind: str
    source_id: uuid.UUID
    role: str
    society_id: uuid.UUID
    unit_id: uuid.UUID | None
    not_before: datetime | None
    expires_at: datetime | None


@dataclass(frozen=True)
class OverviewRow:
    source_kind: str
    source_id: uuid.UUID
    role: str
    society_id: uuid.UUID
    unit_id: uuid.UUID | None
    membership_kind: str | None
    verification: str | None
    effective: bool
    not_before: datetime | None
    expires_at: datetime | None


def _rows(conn: Connection, sql: str, params: dict[str, Any]) -> list[Any]:
    return list(conn.execute(text(sql), params).all())


# ------------------------------------------------------------------------------------------------- OTP
def otp_issue(
    conn: Connection,
    *,
    challenge_id: uuid.UUID,
    token: str,
    purpose: str,
    person_id: uuid.UUID | None,
    code_hash: str,
    ttl_seconds: int,
    max_attempts: int,
    delivery_id: uuid.UUID,
    template_id: str,
    payload_enc: str,
    simulation: bool,
) -> None:
    conn.execute(
        text(
            "SELECT iam.otp_issue(:id, :tok, :purpose, :person, :hash, :ttl, :max, :did, :tpl, :payload, :sim)"
        ),
        {
            "id": challenge_id, "tok": token, "purpose": purpose, "person": person_id, "hash": code_hash,
            "ttl": ttl_seconds, "max": max_attempts, "did": delivery_id, "tpl": template_id,
            "payload": payload_enc, "sim": simulation,
        },
    )  # fmt: skip


@dataclass(frozen=True)
class OtpAttempt:
    challenge_id: uuid.UUID | None
    code_hash: str
    status: str
    person_id: uuid.UUID | None


def otp_attempt(conn: Connection, token: str, purpose: str) -> OtpAttempt:
    row = conn.execute(
        text("SELECT challenge_id, code_hash, status, person_id FROM iam.otp_attempt(:t, :p)"),
        {"t": token, "p": purpose},
    ).one()
    return OtpAttempt(row[0], row[1] or "", row[2], row[3])


@dataclass(frozen=True)
class OtpConsumed:
    token: str
    purpose: str
    person_id: uuid.UUID | None


def otp_consume(conn: Connection, challenge_id: uuid.UUID) -> OtpConsumed | None:
    row = conn.execute(
        text("SELECT phone_token, purpose, person_id FROM iam.otp_consume(:c)"), {"c": challenge_id}
    ).first()
    return None if row is None else OtpConsumed(row[0], row[1], row[2])


def dev_otp_latest(conn: Connection, token: str) -> tuple[uuid.UUID, str, str, datetime] | None:
    row = conn.execute(
        text(
            "SELECT delivery_id, payload_enc, template_id, created_at FROM iam.dev_otp_latest(:t)"
        ),
        {"t": token},
    ).first()
    return None if row is None else (row[0], row[1], row[2], row[3])


# ------------------------------------------------------------------------------------------------- persons
@dataclass(frozen=True)
class LoginPerson:
    person_id: uuid.UUID
    created: bool
    recycled: bool


def login_person(
    conn: Connection,
    *,
    new_id: uuid.UUID,
    token: str,
    phone_enc: str,
    display_name: str,
    dormancy_days: int,
) -> LoginPerson:
    row = conn.execute(
        text(
            "SELECT person_id, created, recycled FROM iam.login_person(:id, :tok, :enc, :name,"
            " make_interval(days => :days))"
        ),
        {"id": new_id, "tok": token, "enc": phone_enc, "name": display_name, "days": dormancy_days},
    ).one()
    return LoginPerson(row[0], bool(row[1]), bool(row[2]))


def ensure_person(
    conn: Connection, *, new_id: uuid.UUID, token: str, phone_enc: str, display_name: str
) -> uuid.UUID:
    value = conn.execute(
        text("SELECT iam.ensure_person(:id, :tok, :enc, :name)"),
        {"id": new_id, "tok": token, "enc": phone_enc, "name": display_name},
    ).scalar_one()
    return uuid.UUID(str(value))


@dataclass(frozen=True)
class Profile:
    id: uuid.UUID
    display_name: str
    preferred_language: str
    is_minor: bool
    status: str
    phone_verified_at: datetime | None


def person_profile(conn: Connection, person_id: uuid.UUID) -> Profile | None:
    row = conn.execute(
        text(
            "SELECT id, display_name, preferred_language, is_minor, status, phone_verified_at"
            " FROM iam.person_profile(:p)"
        ),
        {"p": person_id},
    ).first()
    return None if row is None else Profile(*row)


def update_profile(
    conn: Connection, person_id: uuid.UUID, display_name: str | None, language: str | None
) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.update_profile(:p, :n, :l)"),
            {"p": person_id, "n": display_name, "l": language},
        ).scalar_one()
    )


def society_people(
    conn: Connection, ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, str, bool]]:
    rows = _rows(
        conn,
        "SELECT id, display_name, preferred_language, is_minor FROM iam.society_people(:ids)",
        {"ids": ids},
    )
    return {r[0]: (r[1], r[2], bool(r[3])) for r in rows}


def vault_get(conn: Connection, person_id: uuid.UUID) -> tuple[str, str | None, str | None] | None:
    row = conn.execute(
        text("SELECT phone_enc, email_enc, id_doc_masked FROM iam.vault_get(:p)"), {"p": person_id}
    ).first()
    return None if row is None else (row[0], row[1], row[2])


def vault_put(
    conn: Connection, person_id: uuid.UUID, email_enc: str | None, id_doc_masked: str | None
) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.vault_put(:p, :e, :m)"),
            {"p": person_id, "e": email_enc, "m": id_doc_masked},
        ).scalar_one()
    )


def change_phone(
    conn: Connection, person_id: uuid.UUID, challenge_id: uuid.UUID, token: str, phone_enc: str
) -> str:
    return str(
        conn.execute(
            text("SELECT iam.change_phone(:p, :c, :t, :e)"),
            {"p": person_id, "c": challenge_id, "t": token, "e": phone_enc},
        ).scalar_one()
    )


# ------------------------------------------------------------------------------------------------- sessions
def session_create(
    conn: Connection,
    *,
    session_id: uuid.UUID,
    person_id: uuid.UUID,
    challenge_id: uuid.UUID,
    device_id: str,
    label: str,
    platform: str | None,
    refresh_id: uuid.UUID,
    refresh_hash: str,
    ttl_seconds: int,
    max_sessions: int,
) -> None:
    conn.execute(
        text("SELECT iam.session_create(:s, :p, :c, :d, :l, :pl, :rid, :rh, :ttl, :max)"),
        {
            "s": session_id, "p": person_id, "c": challenge_id, "d": device_id, "l": label, "pl": platform,
            "rid": refresh_id, "rh": refresh_hash, "ttl": ttl_seconds, "max": max_sessions,
        },
    )  # fmt: skip


@dataclass(frozen=True)
class Rotation:
    outcome: str
    session_id: uuid.UUID | None
    person_id: uuid.UUID | None


def session_rotate(
    conn: Connection, *, old_hash: str, new_id: uuid.UUID, new_hash: str, ttl_seconds: int
) -> Rotation:
    row = conn.execute(
        text("SELECT outcome, session_id, person_id FROM iam.session_rotate(:o, :i, :h, :ttl)"),
        {"o": old_hash, "i": new_id, "h": new_hash, "ttl": ttl_seconds},
    ).one()
    return Rotation(row[0], row[1], row[2])


@dataclass(frozen=True)
class SessionRow:
    id: uuid.UUID
    device_id: str
    device_label: str
    platform: str | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    mfa_verified_at: datetime | None


def session_list(conn: Connection, person_id: uuid.UUID) -> list[SessionRow]:
    rows = _rows(
        conn,
        "SELECT id, device_id, device_label, platform, created_at, last_seen_at, expires_at, mfa_verified_at"
        " FROM iam.session_list(:p)",
        {"p": person_id},
    )
    return [SessionRow(*r) for r in rows]


def session_revoke(
    conn: Connection, person_id: uuid.UUID, session_id: uuid.UUID, reason: str
) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.session_revoke(:p, :s, :r)"),
            {"p": person_id, "s": session_id, "r": reason},
        ).scalar_one()
    )


def session_revoke_others(
    conn: Connection, person_id: uuid.UUID, keep: uuid.UUID, reason: str
) -> int:
    return int(
        conn.execute(
            text("SELECT iam.session_revoke_others(:p, :k, :r)"),
            {"p": person_id, "k": keep, "r": reason},
        ).scalar_one()
    )


def session_is_active(conn: Connection, session_id: uuid.UUID, person_id: uuid.UUID) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.session_is_active(:s, :p)"), {"s": session_id, "p": person_id}
        ).scalar_one()
    )


def session_mfa_fresh(
    conn: Connection, person_id: uuid.UUID, session_id: uuid.UUID, ttl_seconds: int
) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.session_mfa_fresh(:p, :s, :ttl)"),
            {"p": person_id, "s": session_id, "ttl": ttl_seconds},
        ).scalar_one()
    )


def session_mark_mfa(conn: Connection, person_id: uuid.UUID, session_id: uuid.UUID) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.session_mark_mfa(:p, :s)"), {"p": person_id, "s": session_id}
        ).scalar_one()
    )


# ------------------------------------------------------------------------------------------------- MFA
def mfa_enrol(
    conn: Connection, person_id: uuid.UUID, factor_id: uuid.UUID, secret_enc: str
) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.mfa_enrol(:p, :f, :s)"),
            {"p": person_id, "f": factor_id, "s": secret_enc},
        ).scalar_one()
    )


@dataclass(frozen=True)
class MfaFactor:
    id: uuid.UUID
    secret_enc: str
    confirmed_at: datetime | None
    last_used_step: int


def mfa_get(conn: Connection, person_id: uuid.UUID) -> MfaFactor | None:
    row = conn.execute(
        text("SELECT id, secret_enc, confirmed_at, last_used_step FROM iam.mfa_get(:p)"),
        {"p": person_id},
    ).first()
    return None if row is None else MfaFactor(row[0], row[1], row[2], int(row[3]))


def mfa_use_step(
    conn: Connection, person_id: uuid.UUID, factor_id: uuid.UUID, step: int, *, confirm: bool
) -> bool:
    return bool(
        conn.execute(
            text("SELECT iam.mfa_use_step(:p, :f, :s, :c)"),
            {"p": person_id, "f": factor_id, "s": step, "c": confirm},
        ).scalar_one()
    )


# ------------------------------------------------------------------------------------------------- access
def effective_grants(conn: Connection, person_id: uuid.UUID) -> list[GrantRow]:
    rows = _rows(
        conn,
        "SELECT source_kind, source_id, role, society_ref, unit_ref, not_before, expires_at"
        " FROM iam.effective_grants(:p)",
        {"p": person_id},
    )
    return [GrantRow(*r) for r in rows]


def access_overview(conn: Connection, person_id: uuid.UUID) -> list[OverviewRow]:
    rows = _rows(
        conn,
        "SELECT source_kind, source_id, role, society_ref, unit_ref, membership_kind, verification,"
        " effective, not_before, expires_at FROM iam.access_overview(:p)",
        {"p": person_id},
    )
    return [OverviewRow(*r) for r in rows]


def locate_membership(
    conn: Connection, membership_id: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID | None] | None:
    row = conn.execute(
        text("SELECT society_ref, unit_ref FROM iam.locate_membership(:m)"), {"m": membership_id}
    ).first()
    return None if row is None else (row[0], row[1])
