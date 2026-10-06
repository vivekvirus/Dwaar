"""Push-token registry (FCM / APNs simulated) and the on-device diagnostic.

REQ: IAM-11 (a phone-number change revokes push tokens: ``revoke_all_for_person``), NOTIF-06 (on-device diagnostic at onboarding; manufacturer
guidance; no claim that a battery exemption guarantees delivery), NOTIF-07 (delivery telemetry by phone model and OS), D-21, INV-01.

Only a keyed-free SHA-256 of the token and a short reference are stored: the registry is a simulation (real FCM/APNs adapters need the token
itself, envelope-encrypted; not built, see ADR-0020). The token itself never appears in an audit row, an event, a log or a response.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound, PolicyViolation
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import catalog

MAX_ACTIVE_PER_PERSON: Final = 6
_COLUMNS: Final = (
    "id, person_id, platform, token_ref, device_label, phone_model, manufacturer, os_name, os_version, app_version,"
    " notification_permission, simulation, registered_at, last_seen_at, revoked_at, revoked_reason, version"
)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_ref_for(token: str) -> str:
    """The short, non-reversible handle by which simulators and logs identify a device (``tk_`` + 12 hex of the hash)."""
    return "tk_" + token_hash(token)[:12]


def token_view(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "platform": row["platform"],
        "token_ref": row["token_ref"],
        "device_label": row["device_label"],
        "device_model": row["phone_model"],
        "manufacturer": row["manufacturer"],
        "os_name": row["os_name"],
        "os_version": row["os_version"],
        "app_version": row["app_version"],
        "notification_permission": row["notification_permission"],
        "simulation": row["simulation"],
        "registered_at": row["registered_at"],
        "last_seen_at": row["last_seen_at"],
        "revoked_at": row["revoked_at"],
        "revoked_reason": row["revoked_reason"],
        "version": row["version"],
    }


def list_tokens(
    conn: Connection, person_id: uuid.UUID, *, include_revoked: bool = False
) -> list[dict[str, Any]]:
    sql = f"SELECT {_COLUMNS} FROM device_push_tokens WHERE person_id = :p"  # noqa: S608
    if not include_revoked:
        sql += " AND revoked_at IS NULL"
    rows = conn.execute(
        text(sql + " ORDER BY registered_at DESC, id DESC"), {"p": person_id}
    ).mappings()
    return [token_view(r) for r in rows]


def register_token(
    conn: Connection,
    ctx: RequestContext,
    person_id: uuid.UUID,
    *,
    platform: str,
    token: str,
    device_label: str | None,
    device_model: str | None,
    manufacturer: str | None,
    os_name: str | None,
    os_version: str | None,
    app_version: str | None,
    notification_permission: str,
    simulation: bool,
) -> dict[str, Any]:
    """Register (or refresh) the caller's own device. The same token for the same person is a refresh (idempotent); a token that was
    registered to someone else is revoked for them first: a handed-over phone never keeps notifying the old owner."""
    assert ctx.society_id is not None  # noqa: S101
    digest = token_hash(token)
    ref = token_ref_for(token)
    family = catalog.normalise_manufacturer(manufacturer) if manufacturer else None
    existing = (
        conn.execute(
            text(
                "SELECT id, person_id, version FROM device_push_tokens WHERE token_hash = :h AND revoked_at IS NULL FOR UPDATE"
            ),
            {"h": digest},
        )
        .mappings()
        .first()
    )
    if existing is not None and existing["person_id"] == person_id:
        tid = existing["id"]

        def refresh(c: Connection) -> MutationResult:
            version = int(existing["version"]) + 1
            c.execute(
                text(
                    "UPDATE device_push_tokens SET last_seen_at = clock_timestamp(), notification_permission = :perm,"
                    " phone_model = COALESCE(:model, phone_model), manufacturer = COALESCE(:man, manufacturer),"
                    " os_name = COALESCE(:os, os_name), os_version = COALESCE(:osv, os_version),"
                    " app_version = COALESCE(:app, app_version), version = :v WHERE id = :id"
                ),
                {"perm": notification_permission, "model": device_model, "man": family, "os": os_name,
                 "osv": os_version, "app": app_version, "v": version, "id": tid},
            )  # fmt: skip
            return MutationResult(
                tid,
                version,
                after={"refreshed": True, "notification_permission": notification_permission},
                event_payload={
                    "handset_id": tid,
                    "notification_permission": notification_permission,
                },
            )

        mutation(
            conn, ctx, operation="notification.token.refresh", object_type="push_token",
            event_type="notification.token_refreshed", apply=refresh,
        )  # fmt: skip
        return _fetch(conn, tid)
    active = conn.execute(
        text("SELECT count(*) FROM device_push_tokens WHERE person_id = :p AND revoked_at IS NULL"),
        {"p": person_id},
    ).scalar_one()
    if int(active) >= MAX_ACTIVE_PER_PERSON:
        raise PolicyViolation(details={"reason": "too_many_devices", "max": MAX_ACTIVE_PER_PERSON})
    if existing is not None:
        _revoke_row(conn, ctx, existing["id"], reason="reassigned_to_another_person")
    new_id = uuid7()

    def create(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO device_push_tokens (id, society_id, person_id, platform, token_hash, token_ref, device_label,"
                " phone_model, manufacturer, os_name, os_version, app_version, notification_permission, simulation)"
                " VALUES (:id, :s, :p, :pl, :h, :r, :lab, :model, :man, :os, :osv, :app, :perm, :sim)"
            ),
            {"id": new_id, "s": ctx.society_id, "p": person_id, "pl": platform, "h": digest, "r": ref,
             "lab": device_label, "model": device_model, "man": family, "os": os_name, "osv": os_version,
             "app": app_version, "perm": notification_permission, "sim": simulation},
        )  # fmt: skip
        return MutationResult(
            new_id,
            1,
            after={
                "platform": platform,
                "device_model": device_model,
                "notification_permission": notification_permission,
            },
            event_payload={
                "handset_id": new_id,
                "platform": platform,
                "notification_permission": notification_permission,
            },
        )

    mutation(
        conn, ctx, operation="notification.token.register", object_type="push_token",
        event_type="notification.token_registered", apply=create,
    )  # fmt: skip
    return _fetch(conn, new_id)


def _fetch(conn: Connection, token_id: uuid.UUID) -> dict[str, Any]:
    row = conn.execute(
        text(f"SELECT {_COLUMNS} FROM device_push_tokens WHERE id = :id"),  # noqa: S608
        {"id": token_id},
    ).mappings().first()  # fmt: skip
    if row is None:
        raise NotFound()
    return token_view(row)


def _revoke_row(conn: Connection, ctx: RequestContext, token_id: uuid.UUID, *, reason: str) -> bool:
    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE device_push_tokens SET revoked_at = clock_timestamp(), revoked_reason = :why, version = version + 1"
                " WHERE id = :id AND revoked_at IS NULL RETURNING version"
            ),
            {"id": token_id, "why": reason},
        ).first()
        if row is None:
            raise _Nothing
        return MutationResult(
            token_id,
            int(row[0]),
            before={"revoked": False},
            after={"revoked": True, "reason": reason},
            event_payload={"handset_id": token_id, "reason": reason},
        )

    try:
        mutation(
            conn, ctx, operation="notification.token.revoke", object_type="push_token",
            event_type="notification.token_revoked", apply=apply,
        )  # fmt: skip
    except _Nothing:
        return False
    return True


class _Nothing(Exception):
    """Nothing to revoke (already revoked): not an error."""


def revoke_own(
    conn: Connection, ctx: RequestContext, person_id: uuid.UUID, token_id: uuid.UUID
) -> dict[str, Any]:
    """Revoke one of the caller's own devices. Somebody else's token looks exactly like an unknown one."""
    row = conn.execute(
        text("SELECT person_id FROM device_push_tokens WHERE id = :id"), {"id": token_id}
    ).first()
    if row is None or row[0] != person_id:
        raise NotFound()
    _revoke_row(conn, ctx, token_id, reason="revoked_by_owner")
    return _fetch(conn, token_id)


def revoke_all_for_person(
    conn: Connection, ctx: RequestContext, person_id: uuid.UUID, *, reason: str
) -> int:
    """IAM-11: revoke every active token of a person in this society (phone number changed, membership ended ...). Idempotent."""
    rows = conn.execute(
        text(
            "SELECT id FROM device_push_tokens WHERE person_id = :p AND revoked_at IS NULL ORDER BY id FOR UPDATE"
        ),
        {"p": person_id},
    ).all()
    n = 0
    for (tid,) in rows:
        if _revoke_row(conn, ctx, tid, reason=reason):
            n += 1
    return n


# ------------------------------------------------------------------------------------------------------------ diagnostic (NOTIF-06)
def submit_diagnostic(
    conn: Connection,
    ctx: RequestContext,
    person_id: uuid.UUID,
    *,
    token_id: uuid.UUID | None,
    manufacturer: str,
    device_model: str | None,
    os_name: str | None,
    os_version: str | None,
    notification_permission: str,
    battery_optimisation: str,
    focus_mode_blocks: str,
    test_push: str,
    simulation: bool,
) -> dict[str, Any]:
    """Store the on-device diagnostic result and answer with the manufacturer's steps for what went wrong.

    The verdict is never "delivery guaranteed": at best ``no_problem_found`` for this test. A battery exemption is reported as a setting,
    never as a guarantee (NOTIF-06). The permission seen by the device is copied onto the token so the cascade does not push to a phone
    that cannot show it (AT-11)."""
    assert ctx.society_id is not None  # noqa: S101
    family = catalog.normalise_manufacturer(manufacturer)
    if token_id is not None:
        owner = conn.execute(
            text("SELECT person_id FROM device_push_tokens WHERE id = :id"), {"id": token_id}
        ).first()
        if owner is None or owner[0] != person_id:
            raise NotFound()
    verdict, problems = catalog.verdict(
        permission=notification_permission,
        battery=battery_optimisation,
        focus=focus_mode_blocks,
        test_push=test_push,
    )
    report_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO device_health_reports (id, society_id, person_id, token_id, manufacturer, phone_model, os_name,"
                " os_version, notification_permission, battery_optimisation, focus_mode_blocks, test_push, verdict, simulation)"
                " VALUES (:id, :s, :p, :t, :man, :model, :os, :osv, :perm, :bat, :focus, :test, :verdict, :sim)"
            ),
            {"id": report_id, "s": ctx.society_id, "p": person_id, "t": token_id, "man": family, "model": device_model,
             "os": os_name, "osv": os_version, "perm": notification_permission, "bat": battery_optimisation,
             "focus": focus_mode_blocks, "test": test_push, "verdict": verdict, "sim": simulation},
        )  # fmt: skip
        if token_id is not None:
            c.execute(
                text(
                    "UPDATE device_push_tokens SET notification_permission = :perm, last_seen_at = clock_timestamp(),"
                    " phone_model = COALESCE(:model, phone_model), manufacturer = :man,"
                    " os_name = COALESCE(:os, os_name), os_version = COALESCE(:osv, os_version), version = version + 1"
                    " WHERE id = :id AND revoked_at IS NULL"
                ),
                {"perm": notification_permission, "model": device_model, "man": family, "os": os_name, "osv": os_version,
                 "id": token_id},
            )  # fmt: skip
        return MutationResult(
            report_id,
            1,
            after={"manufacturer": family, "verdict": verdict, "problems": len(problems)},
            event_payload={"report_id": report_id, "manufacturer": family, "verdict": verdict},
        )

    mutation(
        conn, ctx, operation="notification.diagnostic.submit", object_type="device_health_report",
        event_type="notification.diagnostic_reported", apply=apply,
    )  # fmt: skip
    guide = catalog.guidance_for(family)
    steps = [s for s in guide["steps"] if s["id"] in problems] if problems else []
    return {
        "report_id": report_id,
        "verdict": verdict,
        "verdict_text_key": f"diag.verdict.{verdict}",
        "problem_steps": steps,
        "guidance": guide,
        "delivery_guaranteed": False,
        "disclaimer_key": catalog.GUARD_RULES_KEY,
    }
