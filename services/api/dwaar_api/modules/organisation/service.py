"""Organisation domain operations. Every write goes through ``core.audit.mutation`` (domain row + audit row +
outbox row in one SAVEPOINT of the caller's transaction, PRD 12.4).

REQ: SOC-01 (society + legal entity, encrypted/masked PAN/TAN/GSTIN, pack selection, binding governance stays
disabled on an unapproved legal pack), SOC-02 (blocks/units), ARCH-01/ARCH-05, INV-01 (every query runs under the RLS
context of the validated scope; ids in bodies are only ever resolved INSIDE that society).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from dwaar_common.crypto import EnvelopeCipher, build_aad
from dwaar_common.errors import (
    InvalidSchema,
    LegalPackNotApproved,
    NotFound,
    PolicyViolation,
    StaleVersion,
)
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import masking
from .schemas import (
    BlockCreate,
    BlockPatch,
    FlagPut,
    QuotasPut,
    SocietyCreate,
    SocietyPatch,
    UnitCreate,
    UnitPatch,
)
from .views import (
    audit_unit,
    block_view,
    legal_entity_view,
    society_basic,
    unit_view,
)

BINDING_FLAG: Final = "binding_governance"
_CONSTRAINT_REASONS: Final = {
    "units_block_label_uq": "duplicate_unit_label",
    "units_block_label_ci_uq": "duplicate_unit_label",
    "blocks_society_name_uq": "duplicate_block_name",
    "blocks_society_name_ci_uq": "duplicate_block_name",
    "units_block_fk": "unknown_block",
    "units_builtup_ge_carpet": "builtup_area_below_carpet_area",
}


def _need[T](value: T | None) -> T:
    """A row this transaction just wrote must be readable under the same RLS context; otherwise fail closed."""
    if value is None:
        raise NotFound()
    return value


def translate_integrity(exc: IntegrityError) -> PolicyViolation | None:
    """Friendly 422 for the constraints this module owns; anything else falls through to the core handler."""
    name = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
    reason = _CONSTRAINT_REASONS.get(name or "")
    return PolicyViolation(details={"reason": reason}) if reason else None


# ------------------------------------------------------------------------------------------ packs
def legal_pack_info(conn: Connection, pack_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(text("SELECT * FROM legal_pack_catalog WHERE id = :id"), {"id": pack_id})
        .mappings()
        .first()
    )
    return dict(row) if row else None


def tax_pack_info(conn: Connection, pack_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(text("SELECT * FROM tax_pack_catalog WHERE id = :id"), {"id": pack_id})
        .mappings()
        .first()
    )
    return dict(row) if row else None


def check_selectable_legal_pack(
    conn: Connection, pack_id: uuid.UUID, entity_type: str | None
) -> dict[str, Any]:
    """Selection rule (SOC-01): any existing, enabled, non-retired pack (approved OR draft/unapproved) whose entity
    type fits. Approval is NOT required to select; it is required to enable binding governance."""
    info = legal_pack_info(conn, pack_id)
    if info is None:
        raise InvalidSchema.for_fields([("legal_pack_id", "unknown_pack")])
    if info["pack_status"] == "retired":
        raise PolicyViolation(details={"reason": "pack_retired", "field": "legal_pack_id"})
    if not info["enabled"]:
        raise PolicyViolation(details={"reason": "pack_disabled", "field": "legal_pack_id"})
    if entity_type is not None and info["entity_type"] not in ("any", entity_type):
        raise PolicyViolation(
            details={"reason": "pack_entity_type_mismatch", "field": "legal_pack_id"}
        )
    return info


def check_selectable_tax_pack(conn: Connection, pack_id: uuid.UUID) -> dict[str, Any]:
    info = tax_pack_info(conn, pack_id)
    if info is None:
        raise InvalidSchema.for_fields([("tax_pack_id", "unknown_pack")])
    if info["pack_status"] == "retired":
        raise PolicyViolation(details={"reason": "pack_retired", "field": "tax_pack_id"})
    if not info["enabled"]:
        raise PolicyViolation(details={"reason": "pack_disabled", "field": "tax_pack_id"})
    return info


def _pack_view(info: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if info is None:
        return None
    keep = ("id", "pack_key", "version", "title", "pack_status", "approved", "enabled")
    out = {k: info[k] for k in keep if k in info}
    for extra in ("jurisdiction", "entity_type", "pack_type"):
        if extra in info:
            out[extra] = info[extra]
    return out


# ------------------------------------------------------------------------------------------ societies
_SOCIETY_SQL: Final = (
    "SELECT id, org_id, name, legal_entity_id, legal_pack_id, tax_pack_id, city, state, timezone,"
    " settings, ai_budget_paise, status, version FROM societies WHERE id = :id"
)


def fetch_society(conn: Connection, society_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(text(_SOCIETY_SQL), {"id": society_id}).mappings().first()
    return dict(row) if row else None


def fetch_basic(conn: Connection, society_id: uuid.UUID) -> dict[str, Any] | None:
    row = fetch_society(conn, society_id)
    return society_basic(row) if row else None


def fetch_flags(conn: Connection, society_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT flag_key, enabled, version FROM society_feature_flags"
            " WHERE society_id = :s AND status = 'active' ORDER BY flag_key"
        ),
        {"s": society_id},
    ).mappings()
    return [dict(r) for r in rows]


def fetch_quotas(conn: Connection, society_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT rate_per_minute, rate_burst, queue_quota, ai_requests_per_day, version"
                " FROM society_quotas WHERE society_id = :s"
            ),
            {"s": society_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def binding_status(legal: Mapping[str, Any] | None, flags: list[dict[str, Any]]) -> dict[str, Any]:
    """D-24 / GOV-01: binding governance is on only if the legal pack is approved AND in effect AND the society's
    flag is on. The blockers say why not (shown to authorised admins only, never to residents)."""
    blockers: list[str] = []
    if legal is None or not legal["approved"]:
        blockers.append("legal_pack_not_approved")
    elif not legal["binding_allowed"]:
        blockers.append("legal_pack_not_in_effect")
    if not any(f["flag_key"] == BINDING_FLAG and f["enabled"] for f in flags):
        blockers.append("feature_flag_disabled")
    return {"enabled": not blockers, "blockers": blockers}


def society_configuration(conn: Connection, society_id: uuid.UUID) -> dict[str, Any] | None:
    soc = fetch_society(conn, society_id)
    if soc is None:
        return None
    entity = (
        conn.execute(
            text(
                "SELECT id, name, entity_type, registration_no, pan_masked, tan_masked, gstin_masked,"
                " gst_registered, version FROM legal_entities WHERE id = :id"
            ),
            {"id": soc["legal_entity_id"]},
        )
        .mappings()
        .one()
    )
    legal = legal_pack_info(conn, soc["legal_pack_id"])
    tax = tax_pack_info(conn, soc["tax_pack_id"]) if soc["tax_pack_id"] else None
    flags = fetch_flags(conn, society_id)
    return {
        **society_basic(soc),
        "org_id": soc["org_id"],
        "settings": soc["settings"],
        "ai_budget_paise": soc["ai_budget_paise"],
        "legal_entity": legal_entity_view(dict(entity)),
        "legal_pack": _pack_view(legal),
        "tax_pack": _pack_view(tax),
        "tax_configured": tax is not None,
        "binding_governance": binding_status(legal, flags),
        "feature_flags": flags,
        "quotas": fetch_quotas(conn, society_id),
    }


def _enc(
    cipher: EnvelopeCipher,
    value: str | None,
    society_id: uuid.UUID,
    entity_id: uuid.UUID,
    field: str,
) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    token = cipher.encrypt(value, build_aad(society_id, "legal_entities", field, entity_id))
    return token, masking.mask(value)


def create_society(
    conn: Connection,
    ctx: RequestContext,
    society_id: uuid.UUID,
    body: SocietyCreate,
    cipher: EnvelopeCipher,
) -> dict[str, Any]:
    """``ctx.society_id`` MUST be the new ``society_id`` (the RLS context of the creation transaction)."""
    if ctx.society_id != society_id:
        raise ValueError("society creation runs under the context of the new society")
    entity_id = uuid7()
    legal = check_selectable_legal_pack(conn, body.legal_pack_id, body.legal_entity.entity_type)
    if body.tax_pack_id is not None:
        check_selectable_tax_pack(conn, body.tax_pack_id)
    if body.org_id is not None:
        exists = conn.execute(
            text("SELECT EXISTS (SELECT 1 FROM org_catalog WHERE id = :o AND status = 'active')"),
            {"o": body.org_id},
        ).scalar_one()
        if not exists:
            raise InvalidSchema.for_fields([("org_id", "unknown_org")])
    le = body.legal_entity

    def apply(c: Connection) -> MutationResult:
        pan_enc, pan_masked = _enc(cipher, le.pan, society_id, entity_id, "pan")
        tan_enc, tan_masked = _enc(cipher, le.tan, society_id, entity_id, "tan")
        gstin_enc, gstin_masked = _enc(cipher, le.gstin, society_id, entity_id, "gstin")
        c.execute(
            text(
                "INSERT INTO legal_entities (id, society_id, name, entity_type, registration_no, pan_enc,"
                " pan_masked, tan_enc, tan_masked, gstin_enc, gstin_masked, gst_registered, created_by)"
                " VALUES (:id, :s, :name, :etype, :reg, :pan_enc, :pan_masked, :tan_enc, :tan_masked,"
                " :gstin_enc, :gstin_masked, :gst, :by)"
            ),
            {
                "id": entity_id,
                "s": society_id,
                "name": le.name,
                "etype": le.entity_type,
                "reg": le.registration_no,
                "pan_enc": pan_enc,
                "pan_masked": pan_masked,
                "tan_enc": tan_enc,
                "tan_masked": tan_masked,
                "gstin_enc": gstin_enc,
                "gstin_masked": gstin_masked,
                "gst": bool(le.gst_registered) or le.gstin is not None,
                "by": ctx.person_id,
            },
        )
        c.execute(
            text(
                "INSERT INTO societies (id, org_id, name, legal_entity_id, legal_pack_id, tax_pack_id, city,"
                " state, timezone, settings, ai_budget_paise, created_by) VALUES (:id, :org, :name, :le,"
                " :lp, :tp, :city, :state, :tz, CAST(:settings AS jsonb), :ai, :by)"
            ),
            {
                "id": society_id,
                "org": body.org_id,
                "name": body.name,
                "le": entity_id,
                "lp": body.legal_pack_id,
                "tp": body.tax_pack_id,
                "city": body.city,
                "state": body.state,
                "tz": body.timezone,
                "settings": json.dumps(body.settings, separators=(",", ":"), sort_keys=True),
                "ai": body.ai_budget_paise,
                "by": ctx.person_id,
            },
        )
        # ARCH-05: the binding-governance flag starts OFF (D-24); quotas start at the platform defaults.
        c.execute(
            text(
                "INSERT INTO society_feature_flags (society_id, flag_key, enabled, created_by)"
                " VALUES (:s, :k, false, :by)"
            ),
            {"s": society_id, "k": BINDING_FLAG, "by": ctx.person_id},
        )
        c.execute(
            text("INSERT INTO society_quotas (society_id, created_by) VALUES (:s, :by)"),
            {"s": society_id, "by": ctx.person_id},
        )
        after = {
            "name": body.name,
            "org_id": body.org_id,
            "city": body.city,
            "state": body.state,
            "timezone": body.timezone,
            "legal_pack_id": body.legal_pack_id,
            "tax_pack_id": body.tax_pack_id,
            "legal_entity_id": entity_id,
            "legal_entity_type": le.entity_type,
            "legal_pack_status": legal["pack_status"],
            "identifiers_supplied": [
                n
                for n, v in (("pan", le.pan), ("tan", le.tan), ("gstin", le.gstin))
                if v is not None
            ],
        }
        return MutationResult(
            object_id=society_id,
            object_version=1,
            after=after,
            event_payload={
                "legal_pack_id": body.legal_pack_id,
                "legal_pack_approved": bool(legal["approved"]),
                "org_id": body.org_id,
            },
        )

    mutation(
        conn,
        ctx,
        operation="society.create",
        object_type="society",
        event_type="SocietyCreated",
        apply=apply,
    )
    config = _need(society_configuration(conn, society_id))
    return config


def update_society(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: SocietyPatch
) -> dict[str, Any]:
    current = fetch_society(conn, society_id)
    if current is None:
        raise NotFound()
    if current["version"] != body.expected_version:
        raise StaleVersion(details={"current_version": current["version"]})
    changes: dict[str, Any] = {}
    provided = body.model_fields_set - {"expected_version"}
    for name in provided:
        value = getattr(body, name)
        if value is None and name not in {"tax_pack_id"}:
            raise InvalidSchema.for_fields([(name, "must_not_be_null")])
        changes[name] = value
    if "legal_pack_id" in changes:
        entity_type = conn.execute(
            text("SELECT entity_type FROM legal_entities WHERE id = :id"),
            {"id": current["legal_entity_id"]},
        ).scalar_one()
        check_selectable_legal_pack(conn, changes["legal_pack_id"], entity_type)
    if changes.get("tax_pack_id") is not None:
        check_selectable_tax_pack(conn, changes["tax_pack_id"])

    def apply(c: Connection) -> MutationResult:
        assignments = ["version = version + 1"]
        params: dict[str, Any] = {"id": society_id, "v": body.expected_version}
        for name, value in changes.items():
            if name == "settings":
                assignments.append("settings = CAST(:settings AS jsonb)")
                params["settings"] = json.dumps(value, separators=(",", ":"), sort_keys=True)
            else:
                assignments.append(f"{name} = :{name}")
                params[name] = value
        updated = c.execute(
            text(
                f"UPDATE societies SET {', '.join(assignments)} WHERE id = :id AND version = :v"  # noqa: S608
                " RETURNING version"
            ),
            params,
        ).first()
        if updated is None:
            raise StaleVersion()
        before = {k: current[k] for k in changes}
        return MutationResult(
            object_id=society_id,
            object_version=updated[0],
            before=before,
            after=changes,
            event_payload={"changed": sorted(changes)},
        )

    mutation(
        conn,
        ctx,
        operation="society.update",
        object_type="society",
        event_type="SocietyUpdated",
        apply=apply,
    )
    config = _need(society_configuration(conn, society_id))
    return config


# ------------------------------------------------------------------------------------------ flags, quotas
def put_flag(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, key: str, body: FlagPut
) -> dict[str, Any]:
    if body.enabled and key == BINDING_FLAG:
        soc = fetch_society(conn, society_id)
        if soc is None:
            raise NotFound()
        legal = legal_pack_info(conn, soc["legal_pack_id"])
        if legal is None or not legal["binding_allowed"]:
            # D-24: an unapproved (or not yet effective) legal pack keeps binding governance OFF.
            raise LegalPackNotApproved(details={"flag": key})
    existing = (
        conn.execute(
            text(
                "SELECT id, enabled, version FROM society_feature_flags WHERE society_id = :s AND flag_key = :k"
            ),
            {"s": society_id, "k": key},
        )
        .mappings()
        .first()
    )
    if existing is not None and body.expected_version not in (None, existing["version"]):
        raise StaleVersion(details={"current_version": existing["version"]})

    def apply(c: Connection) -> MutationResult:
        if existing is None:
            row = c.execute(
                text(
                    "INSERT INTO society_feature_flags (society_id, flag_key, enabled, created_by)"
                    " VALUES (:s, :k, :e, :by) RETURNING id, version"
                ),
                {"s": society_id, "k": key, "e": body.enabled, "by": ctx.person_id},
            ).one()
            return MutationResult(
                object_id=row[0],
                object_version=row[1],
                after={"flag_key": key, "enabled": body.enabled},
                event_payload={"flag_key": key, "enabled": body.enabled},
            )
        bumped = c.execute(
            text(
                "UPDATE society_feature_flags SET enabled = :e, version = version + 1"
                " WHERE id = :id AND version = :v RETURNING version"
            ),
            {"e": body.enabled, "id": existing["id"], "v": existing["version"]},
        ).first()
        if bumped is None:
            raise StaleVersion()
        return MutationResult(
            object_id=existing["id"],
            object_version=bumped[0],
            before={"flag_key": key, "enabled": existing["enabled"]},
            after={"flag_key": key, "enabled": body.enabled},
            event_payload={"flag_key": key, "enabled": body.enabled},
        )

    mutation(
        conn,
        ctx,
        operation="society.feature_flag.set",
        object_type="society_feature_flag",
        event_type="FeatureFlagChanged",
        apply=apply,
    )
    return next(f for f in fetch_flags(conn, society_id) if f["flag_key"] == key)


def put_quotas(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: QuotasPut
) -> dict[str, Any]:
    current = fetch_quotas(conn, society_id)
    if current is None:
        raise NotFound()
    if body.expected_version not in (None, current["version"]):
        raise StaleVersion(details={"current_version": current["version"]})
    changes = {k: getattr(body, k) for k in body.model_fields_set - {"expected_version"}}
    if any(v is None for v in changes.values()):
        raise InvalidSchema.for_fields(
            [(k, "must_not_be_null") for k, v in changes.items() if v is None]
        )
    if not changes:
        return current
    merged_burst = changes.get("rate_burst", current["rate_burst"])
    merged_rate = changes.get("rate_per_minute", current["rate_per_minute"])
    if merged_burst > merged_rate * 10:
        raise PolicyViolation(details={"reason": "burst_exceeds_ten_minutes_of_rate"})

    def apply(c: Connection) -> MutationResult:
        sets = ", ".join(f"{k} = :{k}" for k in sorted(changes))
        row = c.execute(
            text(
                f"UPDATE society_quotas SET {sets}, version = version + 1"  # noqa: S608
                " WHERE society_id = :s AND version = :v RETURNING id, version"
            ),
            {**changes, "s": society_id, "v": current["version"]},
        ).first()
        if row is None:
            raise StaleVersion()
        return MutationResult(
            object_id=row[0],
            object_version=row[1],
            before={k: current[k] for k in changes},
            after=dict(changes),
            event_payload={"changed": sorted(changes)},
        )

    mutation(
        conn,
        ctx,
        operation="society.quotas.set",
        object_type="society_quota",
        event_type="SocietyQuotasChanged",
        apply=apply,
    )
    result = _need(fetch_quotas(conn, society_id))
    return result


# ------------------------------------------------------------------------------------------ blocks
_BLOCK_SQL: Final = "SELECT id, name, floors, has_lift, status, version FROM blocks WHERE id = :id"


def fetch_block(conn: Connection, block_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(text(_BLOCK_SQL), {"id": block_id}).mappings().first()
    return dict(row) if row else None


def create_block(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: BlockCreate
) -> dict[str, Any]:
    block_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO blocks (id, society_id, name, floors, has_lift, created_by)"
                " VALUES (:id, :s, :name, :floors, :lift, :by)"
            ),
            {
                "id": block_id,
                "s": society_id,
                "name": body.name,
                "floors": body.floors,
                "lift": body.has_lift,
                "by": ctx.person_id,
            },
        )
        return MutationResult(
            object_id=block_id,
            object_version=1,
            after={"name": body.name, "floors": body.floors, "has_lift": body.has_lift},
            event_payload={"floors": body.floors, "has_lift": body.has_lift},
        )

    try:
        mutation(
            conn,
            ctx,
            operation="block.create",
            object_type="block",
            event_type="BlockCreated",
            apply=apply,
        )
    except IntegrityError as exc:
        raise translate_integrity(exc) or exc from None
    block = _need(fetch_block(conn, block_id))
    return block_view(block)


def update_block(
    conn: Connection, ctx: RequestContext, block_id: uuid.UUID, body: BlockPatch
) -> dict[str, Any]:
    current = fetch_block(conn, block_id)
    if current is None:
        raise NotFound()
    if current["version"] != body.expected_version:
        raise StaleVersion(details={"current_version": current["version"]})
    changes = {k: getattr(body, k) for k in body.model_fields_set - {"expected_version"}}
    if any(v is None for v in changes.values()):
        raise InvalidSchema.for_fields(
            [(k, "must_not_be_null") for k, v in changes.items() if v is None]
        )
    if "floors" in changes:
        top = conn.execute(
            text("SELECT max(floor) FROM units WHERE block_id = :b AND status = 'active'"),
            {"b": block_id},
        ).scalar_one()
        if top is not None and changes["floors"] < top:
            raise PolicyViolation(details={"reason": "units_above_block_floors"})

    def apply(c: Connection) -> MutationResult:
        sets = ", ".join(f"{k} = :{k}" for k in sorted(changes))
        row = c.execute(
            text(
                f"UPDATE blocks SET {sets}{', ' if sets else ''}version = version + 1"  # noqa: S608
                " WHERE id = :id AND version = :v RETURNING version"
            ),
            {**changes, "id": block_id, "v": body.expected_version},
        ).first()
        if row is None:
            raise StaleVersion()
        return MutationResult(
            object_id=block_id,
            object_version=row[0],
            before={k: current[k] for k in changes},
            after=dict(changes),
            event_payload={"changed": sorted(changes)},
        )

    try:
        mutation(
            conn,
            ctx,
            operation="block.update",
            object_type="block",
            event_type="BlockUpdated",
            apply=apply,
        )
    except IntegrityError as exc:
        raise translate_integrity(exc) or exc from None
    block = _need(fetch_block(conn, block_id))
    return block_view(block)


def archive_block(
    conn: Connection, ctx: RequestContext, block_id: uuid.UUID, expected_version: int | None
) -> dict[str, Any]:
    current = fetch_block(conn, block_id)
    if current is None:
        raise NotFound()
    if current["status"] == "archived":
        return block_view(current)  # idempotent
    if expected_version not in (None, current["version"]):
        raise StaleVersion(details={"current_version": current["version"]})
    live = conn.execute(
        text("SELECT count(*) FROM units WHERE block_id = :b AND status = 'active'"),
        {"b": block_id},
    ).scalar_one()
    if live:
        raise PolicyViolation(details={"reason": "block_has_active_units", "units": int(live)})

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE blocks SET status = 'archived', version = version + 1"
                " WHERE id = :id AND version = :v RETURNING version"
            ),
            {"id": block_id, "v": current["version"]},
        ).first()
        if row is None:
            raise StaleVersion()
        return MutationResult(
            object_id=block_id,
            object_version=row[0],
            before={"status": "active"},
            after={"status": "archived"},
            event_payload={"status": "archived"},
        )

    mutation(
        conn,
        ctx,
        operation="block.archive",
        object_type="block",
        event_type="BlockArchived",
        apply=apply,
    )
    block = _need(fetch_block(conn, block_id))
    return block_view(block)


# ------------------------------------------------------------------------------------------ units
UNIT_SELECT: Final = (
    "SELECT u.id AS id, u.block_id, b.name AS block_name, u.label, u.floor, u.carpet_area_sqft,"
    " u.builtup_area_sqft, u.undivided_interest_pct, u.construction_cost_paise, u.status, u.version"
    " FROM units u JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
)


def fetch_unit(conn: Connection, unit_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(text(UNIT_SELECT + " WHERE u.id = :id"), {"id": unit_id}).mappings().first()
    return dict(row) if row else None


def _check_floor(block: Mapping[str, Any], floor: int) -> None:
    if floor > block["floors"]:
        raise PolicyViolation(details={"reason": "floor_exceeds_block_floors", "field": "floor"})


def create_unit(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: UnitCreate
) -> dict[str, Any]:
    block = fetch_block(conn, body.block_id)  # RLS: another society's block is simply absent
    if block is None or block["status"] != "active":
        raise InvalidSchema.for_fields([("block_id", "unknown_block")])
    _check_floor(block, body.floor)
    unit_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO units (id, society_id, block_id, label, floor, carpet_area_sqft,"
                " builtup_area_sqft, undivided_interest_pct, construction_cost_paise, created_by)"
                " VALUES (:id, :s, :b, :label, :floor, :carpet, :builtup, :pct, :cost, :by)"
            ),
            {
                "id": unit_id,
                "s": society_id,
                "b": body.block_id,
                "label": body.label,
                "floor": body.floor,
                "carpet": body.carpet_area_sqft,
                "builtup": body.builtup_area_sqft,
                "pct": body.undivided_interest_pct,
                "cost": body.construction_cost_paise,
                "by": ctx.person_id,
            },
        )
        created = _need(fetch_unit(c, unit_id))
        return MutationResult(
            object_id=unit_id,
            object_version=1,
            after=audit_unit(created),
            event_payload={"block_id": body.block_id, "label": body.label},
        )

    try:
        mutation(
            conn,
            ctx,
            operation="unit.create",
            object_type="unit",
            event_type="UnitCreated",
            apply=apply,
        )
    except IntegrityError as exc:
        raise translate_integrity(exc) or exc from None
    unit = _need(fetch_unit(conn, unit_id))
    return unit_view(unit)


_UNIT_NULLABLE: Final = frozenset(
    {"carpet_area_sqft", "builtup_area_sqft", "undivided_interest_pct", "construction_cost_paise"}
)


def update_unit(
    conn: Connection, ctx: RequestContext, unit_id: uuid.UUID, body: UnitPatch
) -> dict[str, Any]:
    current = fetch_unit(conn, unit_id)
    if current is None:
        raise NotFound()
    if current["version"] != body.expected_version:
        raise StaleVersion(details={"current_version": current["version"]})
    changes = {k: getattr(body, k) for k in body.model_fields_set - {"expected_version"}}
    bad = [k for k, v in changes.items() if v is None and k not in _UNIT_NULLABLE]
    if bad:
        raise InvalidSchema.for_fields([(k, "must_not_be_null") for k in bad])
    if "floor" in changes:
        block = _need(fetch_block(conn, current["block_id"]))
        _check_floor(block, changes["floor"])

    def apply(c: Connection) -> MutationResult:
        sets = ", ".join(f"{k} = :{k}" for k in sorted(changes))
        row = c.execute(
            text(
                f"UPDATE units SET {sets}{', ' if sets else ''}version = version + 1"  # noqa: S608
                " WHERE id = :id AND version = :v RETURNING version"
            ),
            {**changes, "id": unit_id, "v": body.expected_version},
        ).first()
        if row is None:
            raise StaleVersion()
        updated = _need(fetch_unit(c, unit_id))
        before_all, after_all = audit_unit(current), audit_unit(updated)
        return MutationResult(
            object_id=unit_id,
            object_version=row[0],
            before={k: before_all[k] for k in changes},
            after={k: after_all[k] for k in changes},
            event_payload={"changed": sorted(changes)},
        )

    try:
        mutation(
            conn,
            ctx,
            operation="unit.update",
            object_type="unit",
            event_type="UnitUpdated",
            apply=apply,
        )
    except IntegrityError as exc:
        raise translate_integrity(exc) or exc from None
    unit = _need(fetch_unit(conn, unit_id))
    return unit_view(unit)


def archive_unit(
    conn: Connection, ctx: RequestContext, unit_id: uuid.UUID, expected_version: int | None
) -> dict[str, Any]:
    current = fetch_unit(conn, unit_id)
    if current is None:
        raise NotFound()
    if current["status"] == "archived":
        return unit_view(current)
    if expected_version not in (None, current["version"]):
        raise StaleVersion(details={"current_version": current["version"]})

    def apply(c: Connection) -> MutationResult:
        row = c.execute(
            text(
                "UPDATE units SET status = 'archived', version = version + 1"
                " WHERE id = :id AND version = :v RETURNING version"
            ),
            {"id": unit_id, "v": current["version"]},
        ).first()
        if row is None:
            raise StaleVersion()
        return MutationResult(
            object_id=unit_id,
            object_version=row[0],
            before={"status": "active"},
            after={"status": "archived"},
            event_payload={"status": "archived"},
        )

    mutation(
        conn,
        ctx,
        operation="unit.archive",
        object_type="unit",
        event_type="UnitArchived",
        apply=apply,
    )
    unit = _need(fetch_unit(conn, unit_id))
    return unit_view(unit)
