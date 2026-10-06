"""Who the cascade may reach: the household resolved from CURRENT memberships, the household's own settings and preferences.

REQ: NOTIF-03 (selected household approvers, configured alternate adult, opted-in recipients), NOTIF-05 (lock-screen actions re-check membership:
every send re-resolves the household, a person who left is never notified), INV-04 (a non-resident owner is not part of the household that
decides), GATE-13, AT-11 (the household's configured fallback: a masked call, or the intercom).

An approver is someone the visits module would let decide (``visits.common.deciders``): the same rule, not a copy of it. The alternate and
every selected approver must be among them, or the push would offer an action the decision would refuse.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.errors import (
    InvalidSchema,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    StaleVersion,
)
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from ..identity import store as identity_store
from ..visits import common
from .planner import SMS, WHATSAPP, Household


@dataclass(frozen=True)
class Preferences:
    show_identity_on_lockscreen: bool = False
    whatsapp_opt_in: bool = False
    sms_opt_in: bool = False
    language: str = "en"
    version: int = 0

    def view(self) -> dict[str, Any]:
        return {
            "show_identity_on_lockscreen": self.show_identity_on_lockscreen,
            "whatsapp_opt_in": self.whatsapp_opt_in,
            "sms_opt_in": self.sms_opt_in,
            "language": self.language,
            "version": self.version,
        }


def get_preferences(conn: Connection, person_id: uuid.UUID) -> Preferences:
    row = conn.execute(
        text(
            "SELECT show_identity_on_lockscreen, whatsapp_opt_in, sms_opt_in, language, version"
            " FROM notification_preferences WHERE person_id = :p"
        ),
        {"p": person_id},
    ).first()
    if row is None:
        return Preferences()
    return Preferences(bool(row[0]), bool(row[1]), bool(row[2]), str(row[3]), int(row[4]))


def put_preferences(
    conn: Connection,
    ctx: RequestContext,
    person_id: uuid.UUID,
    *,
    show_identity_on_lockscreen: bool,
    whatsapp_opt_in: bool,
    sms_opt_in: bool,
    language: str,
) -> dict[str, Any]:
    """Upsert the caller's own preferences. Opt-ins are choices of the resident only: nobody else can set them (NOTIF-09)."""
    assert ctx.society_id is not None  # noqa: S101
    existing = conn.execute(
        text("SELECT id, version FROM notification_preferences WHERE person_id = :p FOR UPDATE"),
        {"p": person_id},
    ).first()
    before = get_preferences(conn, person_id)

    def apply(c: Connection) -> MutationResult:
        if existing is None:
            pid = uuid7()
            c.execute(
                text(
                    "INSERT INTO notification_preferences (id, society_id, person_id, show_identity_on_lockscreen,"
                    " whatsapp_opt_in, sms_opt_in, language) VALUES (:id, :s, :p, :i, :w, :m, :l)"
                ),
                {"id": pid, "s": ctx.society_id, "p": person_id, "i": show_identity_on_lockscreen,
                 "w": whatsapp_opt_in, "m": sms_opt_in, "l": language},
            )  # fmt: skip
            version = 1
        else:
            pid = existing[0]
            version = int(existing[1]) + 1
            c.execute(
                text(
                    "UPDATE notification_preferences SET show_identity_on_lockscreen = :i, whatsapp_opt_in = :w,"
                    " sms_opt_in = :m, language = :l, updated_at = clock_timestamp(), version = :v WHERE id = :id"
                ),
                {"i": show_identity_on_lockscreen, "w": whatsapp_opt_in, "m": sms_opt_in, "l": language,
                 "v": version, "id": pid},
            )  # fmt: skip
        return MutationResult(
            pid,
            version,
            before=before.view() if existing is not None else None,
            after={
                "show_identity_on_lockscreen": show_identity_on_lockscreen,
                "whatsapp_opt_in": whatsapp_opt_in,
                "sms_opt_in": sms_opt_in,
                "language": language,
            },
            event_payload={
                "show_identity_on_lockscreen": show_identity_on_lockscreen,
                "whatsapp_opt_in": whatsapp_opt_in,
                "sms_opt_in": sms_opt_in,
            },
        )

    mutation(
        conn, ctx, operation="notification.preferences.put", object_type="notification_preference",
        event_type="notification.preferences_changed", apply=apply,
    )  # fmt: skip
    return get_preferences(conn, person_id).view()


# ------------------------------------------------------------------------------------------------------------ unit settings
@dataclass(frozen=True)
class UnitSettings:
    unit_id: uuid.UUID
    primary_person_id: uuid.UUID | None
    approver_person_ids: tuple[uuid.UUID, ...]
    alternate_person_id: uuid.UUID | None
    fallback_mode: str
    version: int

    def view(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "primary_person_id": self.primary_person_id,
            "approver_person_ids": list(self.approver_person_ids),
            "alternate_person_id": self.alternate_person_id,
            "fallback_mode": self.fallback_mode,
            "version": self.version,
        }


def get_unit_settings(conn: Connection, unit_id: uuid.UUID) -> UnitSettings | None:
    row = conn.execute(
        text(
            "SELECT primary_person_id, approver_person_ids, alternate_person_id, fallback_mode, version"
            " FROM unit_notification_settings WHERE unit_id = :u"
        ),
        {"u": unit_id},
    ).first()
    if row is None:
        return None
    return UnitSettings(unit_id, row[0], tuple(row[1] or ()), row[2], str(row[3]), int(row[4]))


def put_unit_settings(
    conn: Connection,
    ctx: RequestContext,
    unit_id: uuid.UUID,
    *,
    primary_person_id: uuid.UUID | None,
    approver_person_ids: list[uuid.UUID],
    alternate_person_id: uuid.UUID | None,
    fallback_mode: str,
    expected_version: int | None,
) -> dict[str, Any]:
    """Set the household's primary, selected approvers, alternate adult and fallback. Every named person must be someone who may decide for the
    unit right now and an adult; the alternate must differ from the primary."""
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    common.require_unit(conn, unit_id)
    standing = common.member_standing(conn, ctx.person_id, unit_id)
    if standing is None:
        raise NotFound()  # not a member of this unit: indistinguishable from an unknown unit
    if not standing.can_decide:
        raise NotAuthorised()  # a household member without the delegation (only those who may decide set who is notified)
    deciders = {m.person_id for m in common.deciders(conn, unit_id)}
    problems: list[tuple[str, str]] = []
    named = {
        "primary_person_id": primary_person_id,
        "alternate_person_id": alternate_person_id,
    }
    for field_name, person in named.items():
        if person is not None and person not in deciders:
            problems.append((field_name, "must_be_an_approver_of_this_unit"))
    for person in approver_person_ids:
        if person not in deciders:
            problems.append(("approver_person_ids", "must_be_an_approver_of_this_unit"))
            break
    if primary_person_id is not None and primary_person_id == alternate_person_id:
        problems.append(("alternate_person_id", "must_differ_from_primary"))
    if problems:
        raise InvalidSchema.for_fields(problems)
    adults = identity_store.society_people(
        conn, [p for p in {primary_person_id, alternate_person_id, *approver_person_ids} if p]
    )
    for field_name, person in named.items():
        if person is not None and adults.get(person, ("", "", False))[2]:
            raise InvalidSchema.for_fields([(field_name, "must_be_an_adult")])
    existing = get_unit_settings(conn, unit_id)
    if (
        existing is not None
        and expected_version is not None
        and existing.version != expected_version
    ):
        raise StaleVersion(details={"version": existing.version})
    if existing is None and expected_version not in (None, 0):
        raise PolicyViolation(details={"reason": "no_settings_to_update"})
    distinct = list(dict.fromkeys(approver_person_ids))

    def apply(c: Connection) -> MutationResult:
        if existing is None:
            sid = uuid7()
            c.execute(
                text(
                    "INSERT INTO unit_notification_settings (id, society_id, unit_id, primary_person_id,"
                    " approver_person_ids, alternate_person_id, fallback_mode, updated_by)"
                    " VALUES (:id, :s, :u, :p, :a, :alt, :fb, :by)"
                ),
                {"id": sid, "s": ctx.society_id, "u": unit_id, "p": primary_person_id, "a": distinct,
                 "alt": alternate_person_id, "fb": fallback_mode, "by": ctx.person_id},
            )  # fmt: skip
            version = 1
        else:
            version = existing.version + 1
            row = c.execute(
                text(
                    "UPDATE unit_notification_settings SET primary_person_id = :p, approver_person_ids = :a,"
                    " alternate_person_id = :alt, fallback_mode = :fb, updated_by = :by,"
                    " updated_at = clock_timestamp(), version = :v WHERE unit_id = :u RETURNING id"
                ),
                {"p": primary_person_id, "a": distinct, "alt": alternate_person_id, "fb": fallback_mode,
                 "by": ctx.person_id, "v": version, "u": unit_id},
            ).one()  # fmt: skip
            sid = row[0]
        return MutationResult(
            sid,
            version,
            before=existing.view() if existing else None,
            after={
                "unit_id": unit_id,
                "approvers": len(distinct),
                "has_alternate": alternate_person_id is not None,
                "fallback_mode": fallback_mode,
            },
            event_payload={"unit_id": unit_id, "fallback_mode": fallback_mode, "version": version},
        )

    mutation(
        conn, ctx, operation="notification.unit_settings.put", object_type="unit_notification_settings",
        event_type="notification.unit_settings_changed", apply=apply,
    )  # fmt: skip
    fresh = get_unit_settings(conn, unit_id)
    assert fresh is not None  # noqa: S101
    return fresh.view()


# ------------------------------------------------------------------------------------------------------------ resolution
def resolve_household(conn: Connection, unit_id: uuid.UUID) -> Household:
    """The cascade audience of a unit, from CURRENT memberships and the household's settings (defaults: the longest-standing approver is the
    primary and the only t=0 recipient; the next approver is the alternate; the fallback is a masked call)."""
    ordered = list(dict.fromkeys(m.person_id for m in common.deciders(conn, unit_id)))
    settings = get_unit_settings(conn, unit_id)
    primary: uuid.UUID | None = ordered[0] if ordered else None
    alternate: uuid.UUID | None = ordered[1] if len(ordered) > 1 else None
    approvers: list[uuid.UUID] = [primary] if primary else []
    fallback = "call"
    if settings is not None:
        fallback = settings.fallback_mode
        if settings.primary_person_id in ordered:
            primary = settings.primary_person_id
        alternate = (
            settings.alternate_person_id if settings.alternate_person_id in ordered else None
        )
        if alternate == primary:
            alternate = None
        chosen = [p for p in settings.approver_person_ids if p in ordered]
        approvers = list(dict.fromkeys(([primary] if primary else []) + chosen))
    prefs = {
        pid: Preferences(bool(a), bool(b), bool(c))
        for pid, a, b, c in conn.execute(
            text(
                "SELECT person_id, show_identity_on_lockscreen, whatsapp_opt_in, sms_opt_in"
                " FROM notification_preferences WHERE person_id = ANY(:ids)"
            ),
            {"ids": ordered or [uuid.UUID(int=0)]},
        ).all()
    }
    opted: list[tuple[uuid.UUID, str]] = []
    for person in ordered:
        p = prefs.get(person)
        if p is None:
            continue
        if p.whatsapp_opt_in:
            opted.append((person, WHATSAPP))
        elif p.sms_opt_in:
            opted.append((person, SMS))
    return Household(tuple(approvers), primary, alternate, tuple(opted), fallback)
