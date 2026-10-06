"""Staff register, consent receipts, engagements and check-in credentials.

REQ: STAFF-01 (one person, separate engagements per household), STAFF-03 (ending one engagement never touches another's), STAFF-04 (consent
BEFORE any data capture; no global blacklist), STAFF-05 (check-in by code or card; there is NO face-matching surface), PRIV-03/PRIV-04 (ID
numbers masked at once to the last 4; police verification as a status only), INV-01, PRD 12.4 (audit + outbox via ``mutation``).

Every capture function checks the consent receipt's PURPOSES first: ``engagement_record`` for the record itself, ``id_capture`` for an ID,
``photo`` for a photo reference, ``police_verification_status`` for that status. A withdrawn receipt blocks further capture.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import secrets
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.crypto import InvalidPhoneError, keyed_hash
from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ...core.pagination import PageParams, Paginator, SortColumn
from ..identity import crypto as identity_crypto
from ..identity import store as identity_store
from ..identity.config import IdentityConfig
from ..visits import common as visits_common
from . import authorisation
from .schemas import (
    ConsentCapture,
    ConsentWithdraw,
    CredentialIssue,
    EngagementCreate,
    EngagementEnd,
    EngagementUpdate,
    StaffRegister,
    StaffUpdate,
)

_REF_ALPHABET: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_CODE_ALPHABET: Final = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_AADHAAR_MASKED: Final = re.compile(r"^[Xx*]{4}[ -]?[Xx*]{4}[ -]?([0-9]{4})\Z")


# ------------------------------------------------------------------------------------------ masking (PRIV-04)
def mask_id_number(kind: str, number: str) -> str:
    """Reduce an ID number to its last four characters and nothing else: ``XXXX XXXX 1234`` for an Aadhaar, ``XXXX AB12`` for others.

    The full number is never stored, audited, evented or logged; the caller drops it right after this call.
    """
    raw = number.strip()
    if kind == "aadhaar":
        already = _AADHAAR_MASKED.match(raw)
        if already:
            return f"XXXX XXXX {already.group(1)}"
        digits = re.sub(r"[\s-]", "", raw)
        if not re.fullmatch(r"[0-9]{12}", digits):
            raise InvalidSchema.for_fields([("id_document.number", "invalid_aadhaar")])
        return f"XXXX XXXX {digits[-4:]}"
    cleaned = re.sub(r"[^0-9A-Za-z]", "", raw)
    if len(cleaned) < 6:
        raise InvalidSchema.for_fields([("id_document.number", "too_short")])
    return f"XXXX {cleaned[-4:].upper()}"


def new_staff_ref() -> str:
    return "".join(secrets.choice(_REF_ALPHABET) for _ in range(10))


def new_check_in_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))


def credential_hash(cfg: IdentityConfig, society_id: uuid.UUID, kind: str, value: str) -> str:
    """Keyed, society-bound hash of a code or card UID (a code is only ever looked up inside one society)."""
    return keyed_hash(
        f"{society_id}|{value.strip().upper()}", cfg.hmac_key, purpose=f"staff.credential.{kind}"
    )


def _check_version(row: Mapping[Any, Any], expected: int) -> None:
    if int(row["version"]) != expected:
        raise StaleVersion(details={"current_version": int(row["version"])})


# ------------------------------------------------------------------------------------------ consent (STAFF-04)
def consent_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "language": row["language"],
        "notice_version": row["notice_version"],
        "channel": row["channel"],
        "purposes": list(row["purposes"]),
        "staff_action_recorded": row["staff_action_recorded"],
        "notice_read_aloud": row["notice_read_aloud"],
        "captured_by": row["captured_by"],
        "given_at": row["given_at"],
        "simulation": row["simulation"],
        "withdrawn_at": row["withdrawn_at"],
        "version": row["version"],
    }


_CONSENT_COLS: Final = (
    "id, language, notice_version, channel, purposes, staff_action_recorded, notice_read_aloud, captured_by, given_at,"
    " simulation, withdrawn_at, version"
)


def capture_consent(
    conn: Connection,
    ctx: RequestContext,
    body: ConsentCapture,
    *,
    channel: str = "assisted_tablet",
    simulation: bool = False,
) -> dict[str, Any]:
    """The consent_receipt (PRIV-03/04). It carries NO personal data: language, notice version, purposes, who assisted, when."""
    if not body.staff_action_recorded:
        # a guard tap is not consent evidence; the staff member's own affirmative action is
        raise PolicyViolation(details={"reason": "staff_action_required"})
    if "engagement_record" not in body.purposes:
        raise InvalidSchema.for_fields([("purposes", "engagement_record_required")])
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    consent_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO staff_consents (id, society_id, language, notice_version, channel, purposes, staff_action_recorded,"
                " notice_read_aloud, captured_by, simulation) VALUES (:id, :s, :lang, :nv, :ch, CAST(:p AS text[]), true, :aloud, :by, :sim)"
            ),
            {
                "id": consent_id, "s": ctx.society_id, "lang": body.language, "nv": body.notice_version, "ch": channel,
                "p": list(body.purposes), "aloud": body.notice_read_aloud, "by": ctx.person_id, "sim": simulation,
            },
        )  # fmt: skip
        return MutationResult(
            consent_id, 1,
            after={"language": body.language, "notice_version": body.notice_version, "purposes": list(body.purposes), "channel": channel},
            event_payload={"consent_id": consent_id, "language": body.language, "purposes": list(body.purposes), "channel": channel},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="staff.consent_capture",
        object_type="staff_consent",
        event_type="StaffConsentCaptured",
        apply=apply,
    )
    return get_consent(conn, consent_id)


def get_consent(conn: Connection, consent_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text(f"SELECT {_CONSENT_COLS} FROM staff_consents WHERE id = :id"),  # noqa: S608
            {"id": consent_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return consent_view(row)


def simulate_ivr_consent(
    conn: Connection, ctx: RequestContext, body: ConsentCapture
) -> dict[str, Any]:
    """STAFF-04: IVR assist is M2 (AI-D02). This is the labelled SIMULATOR HOOK only: it records ``channel=ivr_assisted`` with
    ``simulation=true``. No route calls it and no real IVR provider is reachable from here."""
    return capture_consent(conn, ctx, body, channel="ivr_assisted", simulation=True)


def withdraw_consent(
    conn: Connection, ctx: RequestContext, consent_id: uuid.UUID, body: ConsentWithdraw
) -> dict[str, Any]:
    row = (
        conn.execute(
            text("SELECT id, version, withdrawn_at FROM staff_consents WHERE id = :id FOR UPDATE"),
            {"id": consent_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    if row["withdrawn_at"] is not None:
        return get_consent(conn, consent_id)
    _check_version(row, body.expected_version)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE staff_consents SET withdrawn_at = clock_timestamp(), withdrawn_by = :by, withdrawn_reason = :why,"
                " version = version + 1 WHERE id = :id AND withdrawn_at IS NULL"
            ),
            {"id": consent_id, "by": ctx.person_id, "why": body.reason},
        )
        return MutationResult(
            consent_id, int(row["version"]) + 1, before={"withdrawn": False}, after={"withdrawn": True},
            event_payload={"consent_id": consent_id, "withdrawn": True},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.consent_withdraw", object_type="staff_consent", event_type="StaffConsentWithdrawn",
        apply=apply, reason=body.reason,
    )  # fmt: skip
    return get_consent(conn, consent_id)


def _usable_consent(conn: Connection, consent_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text("SELECT id, purposes, withdrawn_at, language FROM staff_consents WHERE id = :id"),
            {"id": consent_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    if row["withdrawn_at"] is not None:
        raise PolicyViolation(details={"reason": "consent_withdrawn"})
    return dict(row)


def _need_purpose(consent: Mapping[Any, Any], purpose: str) -> None:
    if purpose not in consent["purposes"]:
        # STAFF-04: nothing is captured that the staff member did not consent to
        raise PolicyViolation(details={"reason": "consent_scope_missing", "purpose": purpose})


# ------------------------------------------------------------------------------------------ register
_STAFF_COLS: Final = (
    "s.id, s.display_name, s.staff_ref, s.staff_type, s.consent_id, s.photo_ref, s.id_doc_kind, s.id_doc_masked,"
    " s.police_verification_status, s.police_verification_recorded_at, s.credential_code_hash IS NOT NULL AS has_code,"
    " s.credential_card_hash IS NOT NULL AS has_card, s.credential_issued_at, s.status, s.version, s.created_at,"
    " c.language AS consent_language, c.withdrawn_at AS consent_withdrawn_at"
)
_STAFF_FROM: Final = (
    " FROM staff s JOIN staff_consents c ON c.society_id = s.society_id AND c.id = s.consent_id"
)


def staff_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    """The register entry for society roles: masked ID, status only for police verification, credentials as booleans."""
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "staff_ref": row["staff_ref"],
        "staff_type": row["staff_type"],
        "photo_ref": row["photo_ref"],
        "id_document": None
        if row["id_doc_kind"] is None
        else {"kind": row["id_doc_kind"], "masked": row["id_doc_masked"]},
        "police_verification_status": row["police_verification_status"],
        "check_in": {
            "code": row["has_code"],
            "card": row["has_card"],
            "issued_at": row["credential_issued_at"],
        },
        "consent": {
            "id": row["consent_id"],
            "language": row["consent_language"],
            "withdrawn_at": row["consent_withdrawn_at"],
        },
        "status": row["status"],
        "version": row["version"],
        "created_at": row["created_at"],
    }


def household_staff_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    """What an employing household sees: who works for it. No ID, no police status, no credentials, no other employers."""
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "staff_ref": row["staff_ref"],
        "staff_type": row["staff_type"],
        "photo_ref": row["photo_ref"],
        "status": row["status"],
        "version": row["version"],
    }


def guard_staff_view(
    row: Mapping[Any, Any], destinations: Sequence[Mapping[Any, Any]]
) -> dict[str, Any]:
    """What a GUARD sees (STAFF-01): who it is and where they are authorised right now. Nothing else, and only if authorised."""
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "staff_type": row["staff_type"],
        "photo_ref": row["photo_ref"],
        "authorised_destinations": [authorisation.destination_view(d) for d in destinations],
    }


def register_staff(
    conn: Connection, ctx: RequestContext, cfg: IdentityConfig, body: StaffRegister
) -> dict[str, Any]:
    """Register one person in this society's staff register. The consent receipt must exist FIRST and cover every datum captured."""
    consent = _usable_consent(conn, body.consent_id)
    _need_purpose(consent, "engagement_record")
    if body.id_document is not None:
        _need_purpose(consent, "id_capture")
    if body.photo_ref is not None:
        _need_purpose(consent, "photo")
    if body.police_verification_status != "not_recorded":
        _need_purpose(consent, "police_verification_status")
    if conn.execute(
        text("SELECT 1 FROM staff WHERE consent_id = :c"), {"c": body.consent_id}
    ).first():
        raise PolicyViolation(details={"reason": "consent_already_used"})
    id_masked = (
        None
        if body.id_document is None
        else mask_id_number(body.id_document.kind, body.id_document.number)
    )
    try:
        e164 = identity_crypto.normalise_phone(body.phone)
    except InvalidPhoneError:
        raise InvalidSchema.for_fields([("phone", "invalid_phone")]) from None
    assert ctx.society_id is not None  # noqa: S101
    new_id = uuid7()
    person_id = identity_store.ensure_person(
        conn, new_id=new_id, token=identity_crypto.phone_token(cfg, e164),
        phone_enc=cfg.cipher.encrypt(e164, identity_crypto.vault_aad(new_id, "phone")), display_name=body.display_name,
    )  # fmt: skip
    if conn.execute(text("SELECT 1 FROM staff WHERE person_id = :p"), {"p": person_id}).first():
        raise PolicyViolation(details={"reason": "already_registered"})
    staff_id = uuid7()
    ref = new_staff_ref()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO staff (id, society_id, person_id, display_name, staff_ref, staff_type, consent_id, photo_ref,"
                " id_doc_kind, id_doc_masked, police_verification_status, police_verification_recorded_at, created_by)"
                " VALUES (:id, :s, :p, :name, :ref, :type, :consent, :photo, :kind, :masked, :pv,"
                " CASE WHEN :pv <> 'not_recorded' THEN clock_timestamp() END, :by)"
            ),
            {
                "id": staff_id, "s": ctx.society_id, "p": person_id, "name": body.display_name, "ref": ref,
                "type": body.staff_type, "consent": body.consent_id, "photo": body.photo_ref,
                "kind": body.id_document.kind if body.id_document else None, "masked": id_masked,
                "pv": body.police_verification_status, "by": ctx.person_id,
            },
        )  # fmt: skip
        return MutationResult(
            staff_id, 1,
            after={
                "staff_type": body.staff_type, "id_document_masked": id_masked,
                "police_verification_status": body.police_verification_status, "consent_id": body.consent_id,
            },
            event_payload={"staff_id": staff_id, "staff_type": body.staff_type, "consent_id": body.consent_id},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="staff.register",
        object_type="staff",
        event_type="StaffRegistered",
        apply=apply,
    )
    return get_staff(conn, staff_id)


def get_staff(conn: Connection, staff_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text(f"SELECT {_STAFF_COLS}{_STAFF_FROM} WHERE s.id = :id"),  # noqa: S608
            {"id": staff_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return staff_view(row)


def _locked_staff(conn: Connection, staff_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(text("SELECT * FROM staff WHERE id = :id FOR UPDATE"), {"id": staff_id})
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return dict(row)


def update_staff(
    conn: Connection, ctx: RequestContext, staff_id: uuid.UUID, body: StaffUpdate
) -> dict[str, Any]:
    row = _locked_staff(conn, staff_id)
    _check_version(row, body.expected_version)
    consent = _usable_consent(conn, row["consent_id"])
    sets: list[str] = []
    params: dict[str, Any] = {"id": staff_id}
    after: dict[str, Any] = {}
    if body.staff_type is not None:
        sets.append("staff_type = :type")
        params["type"] = body.staff_type
        after["staff_type"] = body.staff_type
    if body.id_document is not None:
        _need_purpose(consent, "id_capture")
        masked = mask_id_number(body.id_document.kind, body.id_document.number)
        sets += ["id_doc_kind = :kind", "id_doc_masked = :masked"]
        params.update(kind=body.id_document.kind, masked=masked)
        after["id_document_masked"] = masked
    if body.photo_ref is not None:
        _need_purpose(consent, "photo")
        sets.append("photo_ref = :photo")
        params["photo"] = body.photo_ref
        after["photo_ref"] = body.photo_ref
    if body.police_verification_status is not None:
        _need_purpose(consent, "police_verification_status")
        sets += [
            "police_verification_status = :pv",
            "police_verification_recorded_at = clock_timestamp()",
        ]
        params["pv"] = body.police_verification_status
        after["police_verification_status"] = body.police_verification_status
    if not sets:
        raise InvalidSchema.for_fields([("body", "nothing_to_change")])

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(f"UPDATE staff SET {', '.join(sets)}, version = version + 1 WHERE id = :id"),  # noqa: S608
            params,
        )
        return MutationResult(
            staff_id, int(row["version"]) + 1,
            before={"id_document_masked": row["id_doc_masked"], "police_verification_status": row["police_verification_status"]},
            after=after, event_payload={"staff_id": staff_id, "changed": sorted(after)},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="staff.update",
        object_type="staff",
        event_type="StaffUpdated",
        apply=apply,
    )
    return get_staff(conn, staff_id)


def issue_credential(
    conn: Connection,
    ctx: RequestContext,
    cfg: IdentityConfig,
    staff_id: uuid.UUID,
    body: CredentialIssue,
    *,
    fixed_secret: str | None = None,
) -> dict[str, Any]:
    """STAFF-05: a check-in CODE (shown once) or a CARD (UID reported by the reader; only a keyed hash is stored). No face, no biometric."""
    row = _locked_staff(conn, staff_id)
    _check_version(row, body.expected_version)
    _need_purpose(_usable_consent(conn, row["consent_id"]), "attendance")
    assert ctx.society_id is not None  # noqa: S101
    # ``fixed_secret`` exists for the local seed only (a documented demo code); no route passes it
    secret = fixed_secret or (new_check_in_code() if body.kind == "code" else (body.card_uid or ""))
    column = "credential_code_hash" if body.kind == "code" else "credential_card_hash"
    digest = credential_hash(cfg, ctx.society_id, body.kind, secret)
    taken = conn.execute(
        text(f"SELECT 1 FROM staff WHERE {column} = :h AND id <> :id"),  # noqa: S608
        {"h": digest, "id": staff_id},
    ).first()
    if taken:
        raise PolicyViolation(details={"reason": "credential_in_use"})

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                f"UPDATE staff SET {column} = :h, credential_issued_at = clock_timestamp(), version = version + 1 WHERE id = :id"  # noqa: S608
            ),
            {"h": digest, "id": staff_id},
        )
        return MutationResult(
            staff_id, int(row["version"]) + 1, after={"credential_kind": body.kind, "issued": True},
            event_payload={"staff_id": staff_id, "kind": body.kind},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="staff.credential_issue",
        object_type="staff",
        event_type="StaffCredentialIssued",
        apply=apply,
    )
    out: dict[str, Any] = {
        "staff_id": staff_id,
        "kind": body.kind,
        "version": int(row["version"]) + 1,
    }
    if body.kind == "code":
        out["code"] = secret  # shown ONCE: only its keyed hash is stored
    else:
        out["card_last4"] = secret[-4:]
    return out


def list_staff(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    scope: Scope,
    audience: str,
    at: dt.datetime,
) -> dict[str, Any]:
    """Society roles: the register. Household: staff engaged by its own units (own engagements only). Guard: only staff authorised NOW."""
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {"audience": audience}
    if audience == "guard":
        authorised = authorisation.authorised_engagements(conn, at)
        ids = sorted({a["staff_id"] for a in authorised}, key=lambda i: i.int)
        where.append("s.id = ANY(:ids)")
        params["ids"] = ids
        filters["ids"] = ",".join(str(i) for i in ids)
    elif audience == "household":
        units = sorted(scope.unit_ids, key=lambda u: u.int)
        where.append(
            "EXISTS (SELECT 1 FROM staff_engagements e WHERE e.society_id = s.society_id AND e.staff_id = s.id"
            " AND e.unit_id = ANY(:units))"
        )
        params["units"] = units
        filters["units"] = ",".join(str(u) for u in units)
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_STAFF_COLS}{_STAFF_FROM}",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("s.created_at", "timestamptz", nullable=False),
            SortColumn("s.id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    items = result.items
    if audience == "guard":
        by_staff: dict[uuid.UUID, list[dict[str, Any]]] = {}
        for a in authorisation.authorised_engagements(conn, at, staff_ids=[r["id"] for r in items]):
            by_staff.setdefault(a["staff_id"], []).append(a)
        out = [guard_staff_view(r, by_staff.get(r["id"], [])) for r in items]
    elif audience == "household":
        out = [household_staff_view(r) for r in items]
    else:
        out = [staff_view(r) for r in items]
    return {"items": out, "next_cursor": result.next_cursor}


def get_staff_for(
    conn: Connection, staff_id: uuid.UUID, *, scope: Scope, audience: str, at: dt.datetime
) -> dict[str, Any]:
    """One staff member for one audience; anything the audience may not see is a 404 (indistinguishable from an unknown id)."""
    row = (
        conn.execute(
            text(f"SELECT {_STAFF_COLS}{_STAFF_FROM} WHERE s.id = :id"),  # noqa: S608
            {"id": staff_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    if audience == "guard":
        dest = authorisation.authorised_engagements(conn, at, staff_ids=[staff_id])
        if not dest:
            raise NotFound()
        return guard_staff_view(row, dest)
    if audience == "household":
        engaged = conn.execute(
            text(
                "SELECT 1 FROM staff_engagements WHERE staff_id = :s AND unit_id = ANY(:u) LIMIT 1"
            ),
            {"s": staff_id, "u": list(scope.unit_ids)},
        ).first()
        if not engaged:
            raise NotFound()
        return household_staff_view(row)
    return staff_view(row)


# ------------------------------------------------------------------------------------------ engagements
_ENG_COLS: Final = (
    "e.id, e.staff_id, e.unit_id, e.duty, e.schedule, e.effective_from, e.effective_to, e.ended_at, e.ended_by, e.end_reason,"
    " e.version, e.created_at, u.label AS unit_label, b.name AS block_name, s.display_name AS staff_name, s.staff_ref"
)
_ENG_FROM: Final = (
    " FROM staff_engagements e JOIN units u ON u.society_id = e.society_id AND u.id = e.unit_id"
    " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
    " JOIN staff s ON s.society_id = e.society_id AND s.id = e.staff_id"
)


def engagement_view(row: Mapping[Any, Any], *, at: dt.datetime) -> dict[str, Any]:
    return {
        "id": row["id"],
        "staff_id": row["staff_id"],
        "staff_name": row["staff_name"],
        "staff_ref": row["staff_ref"],
        "unit_id": row["unit_id"],
        "block_name": row["block_name"],
        "unit_label": row["unit_label"],
        "duty": row["duty"],
        "schedule": row["schedule"],
        "effective_from": row["effective_from"],
        "effective_to": row["effective_to"],
        "ended_at": row["ended_at"],
        "end_reason": row["end_reason"],
        "authorised_now": row["ended_at"] is None and authorisation.authorised_now(row, at),
        "version": row["version"],
        "created_at": row["created_at"],
    }


def get_engagement(
    conn: Connection, engagement_id: uuid.UUID, *, at: dt.datetime
) -> dict[str, Any]:
    row = (
        conn.execute(
            text(f"SELECT {_ENG_COLS}{_ENG_FROM} WHERE e.id = :id"),  # noqa: S608
            {"id": engagement_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return engagement_view(row, at=at)


def engagement_unit(conn: Connection, engagement_id: uuid.UUID) -> uuid.UUID | None:
    row = conn.execute(
        text("SELECT unit_id FROM staff_engagements WHERE id = :id"), {"id": engagement_id}
    ).first()
    return None if row is None else uuid.UUID(str(row[0]))


def list_engagements(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    scope: Scope,
    audience: str,
    at: dt.datetime,
    staff_id: uuid.UUID | None,
    unit_id: uuid.UUID | None,
    state: str | None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {"audience": audience}
    if unit_id is not None:
        if not scope.covers_unit(unit_id):
            raise NotFound()
        where.append("e.unit_id = :unit")
        params["unit"] = unit_id
        filters["unit_id"] = unit_id
    elif not scope.society_wide:
        units = sorted(scope.unit_ids, key=lambda u: u.int)
        where.append("e.unit_id = ANY(:units)")
        params["units"] = units
        filters["units"] = ",".join(str(u) for u in units)
    if staff_id is not None:
        where.append("e.staff_id = :staff")
        params["staff"] = staff_id
        filters["staff_id"] = staff_id
    if state == "live":
        where.append("e.ended_at IS NULL")
    elif state == "ended":
        where.append("e.ended_at IS NOT NULL")
    if state:
        filters["state"] = state
    guard_ids: list[uuid.UUID] | None = None
    if audience == "guard":
        guard_ids = [a["id"] for a in authorisation.authorised_engagements(conn, at)]
        where.append("e.id = ANY(:authorised)")
        params["authorised"] = guard_ids
        filters["authorised"] = ",".join(str(i) for i in sorted(guard_ids, key=lambda i: i.int))
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_ENG_COLS}{_ENG_FROM}",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("e.created_at", "timestamptz", nullable=False),
            SortColumn("e.id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    if audience == "guard":
        # destinations only: no arrangement, no names of employers, nothing about other households
        items: list[dict[str, Any]] = [
            authorisation.destination_view(r) | {"staff_id": r["staff_id"]} for r in result.items
        ]
    else:
        items = [engagement_view(r, at=at) for r in result.items]
    return {"items": items, "next_cursor": result.next_cursor}


def create_engagement(
    conn: Connection, ctx: RequestContext, body: EngagementCreate, *, at: dt.datetime
) -> dict[str, Any]:
    visits_common.require_unit(conn, body.unit_id)
    found = (
        conn.execute(
            text(
                "SELECT id, status FROM staff WHERE (CAST(:ref AS text) IS NOT NULL AND staff_ref = :ref)"
                " OR (CAST(:sid AS uuid) IS NOT NULL AND id = :sid)"
            ),
            {"ref": body.staff_ref, "sid": body.staff_id},
        )
        .mappings()
        .first()
    )
    if found is None:
        raise NotFound()
    if found["status"] != "active":
        raise PolicyViolation(details={"reason": "staff_archived"})
    _need_purpose(
        _usable_consent(
            conn,
            conn.execute(
                text("SELECT consent_id FROM staff WHERE id = :i"), {"i": found["id"]}
            ).scalar_one(),
        ),
        "engagement_record",
    )
    staff_id = found["id"]
    engagement_id = uuid7()
    assert ctx.society_id is not None  # noqa: S101
    schedule = body.schedule.model_dump(by_alias=True)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO staff_engagements (id, society_id, staff_id, unit_id, duty, schedule, effective_from, effective_to,"
                " created_by) VALUES (:id, :s, :staff, :u, :duty, CAST(:sched AS jsonb),"
                " coalesce(:ef, (now() AT TIME ZONE 'Asia/Kolkata')::date), :et, :by)"
            ),
            {
                "id": engagement_id, "s": ctx.society_id, "staff": staff_id, "u": body.unit_id, "duty": body.duty,
                "sched": json.dumps(schedule, sort_keys=True), "ef": body.effective_from, "et": body.effective_to,
                "by": ctx.person_id,
            },
        )  # fmt: skip
        return MutationResult(
            engagement_id, 1, after={"unit_id": body.unit_id, "duty": body.duty, "schedule": schedule},
            event_payload={"engagement_id": engagement_id, "staff_id": staff_id, "unit_id": body.unit_id},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.engagement_create", object_type="staff_engagement",
        event_type="StaffEngagementCreated", apply=apply,
    )  # fmt: skip
    return get_engagement(conn, engagement_id, at=at)


def _locked_engagement(conn: Connection, engagement_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(
            text("SELECT * FROM staff_engagements WHERE id = :id FOR UPDATE"), {"id": engagement_id}
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return dict(row)


def update_engagement(
    conn: Connection, ctx: RequestContext, scope: Scope, engagement_id: uuid.UUID, body: EngagementUpdate,
    *, at: dt.datetime,
) -> dict[str, Any]:  # fmt: skip
    row = _locked_engagement(conn, engagement_id)
    if not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    _check_version(row, body.expected_version)
    if row["ended_at"] is not None:
        raise PolicyViolation(details={"reason": "engagement_ended"})
    if body.duty is None and body.schedule is None and body.effective_to is None:
        raise InvalidSchema.for_fields([("body", "nothing_to_change")])
    if body.effective_to is not None and body.effective_to < row["effective_from"]:
        raise InvalidSchema.for_fields([("effective_to", "end_before_start")])
    schedule = body.schedule.model_dump(by_alias=True) if body.schedule else row["schedule"]

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE staff_engagements SET duty = coalesce(:duty, duty), schedule = CAST(:sched AS jsonb),"
                " effective_to = coalesce(:et, effective_to), version = version + 1 WHERE id = :id AND ended_at IS NULL"
            ),
            {
                "id": engagement_id,
                "duty": body.duty,
                "sched": json.dumps(schedule, sort_keys=True),
                "et": body.effective_to,
            },
        )
        return MutationResult(
            engagement_id, int(row["version"]) + 1, before={"duty": row["duty"], "schedule": row["schedule"]},
            after={"duty": body.duty or row["duty"], "schedule": schedule},
            event_payload={"engagement_id": engagement_id, "staff_id": row["staff_id"], "unit_id": row["unit_id"]},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.engagement_update", object_type="staff_engagement",
        event_type="StaffEngagementUpdated", apply=apply,
    )  # fmt: skip
    return get_engagement(conn, engagement_id, at=at)


def end_engagement(
    conn: Connection, ctx: RequestContext, scope: Scope, engagement_id: uuid.UUID, body: EngagementEnd,
    *, at: dt.datetime,
) -> dict[str, Any]:  # fmt: skip
    """End ONE engagement (STAFF-03, AT-12). Exactly that row is updated: the person's other engagements are untouched by construction (the
    UPDATE names one id) and the event reports how many remain."""
    row = _locked_engagement(conn, engagement_id)
    if not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    if row["ended_at"] is not None:
        return get_engagement(conn, engagement_id, at=at)  # naturally idempotent
    _check_version(row, body.expected_version)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE staff_engagements SET ended_at = clock_timestamp(), ended_by = :by, end_reason = :why,"
                " version = version + 1 WHERE id = :id AND ended_at IS NULL"
            ),
            {"id": engagement_id, "by": ctx.person_id, "why": body.reason},
        )
        remaining = c.execute(
            text("SELECT count(*) FROM staff_engagements WHERE staff_id = :s AND ended_at IS NULL"),
            {"s": row["staff_id"]},
        ).scalar_one()
        return MutationResult(
            engagement_id, int(row["version"]) + 1, before={"ended": False}, after={"ended": True},
            event_payload={
                "engagement_id": engagement_id, "staff_id": row["staff_id"], "unit_id": row["unit_id"],
                "remaining_live_engagements": int(remaining),
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="staff.engagement_end", object_type="staff_engagement",
        event_type="StaffEngagementEnded", apply=apply, reason=body.reason,
    )  # fmt: skip
    return get_engagement(conn, engagement_id, at=at)
