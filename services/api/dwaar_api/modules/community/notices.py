"""Notices: lifecycle, versions, translations with a review gate, receipts, delivery records, emergency broadcast.

REQ: COM-01 (draft -> approved -> scheduled/published -> superseded/archived; recipient scope; delivery attempts and read
acknowledgements as records; revisions create new versions; a published version is IMMUTABLE), COM-02 (translations always show
the original; a legally or safety-significant translation needs RECORDED human review before it can be published or shown),
COM-03 (a drafted_by_ai notice cannot be published without an explicit human approval), COM-05 (emergency channel, privileged
roles, rate-limited, never carries ads), INV-05, INV-06 (a model drafts, a person approves, deterministic code publishes).

Dispatch (push, SMS, WhatsApp, IVR) belongs to the notifications module: this module emits ``NoticePublished`` /
``EmergencyBroadcastIssued`` through the outbox and stores the attempts it is told about (``record_delivery_attempt``).
Notice text never goes into an audit diff or an event payload: ids, kind, state, audience scope and languages only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation, record_audit
from ...core.db import RequestContext
from ..identity import matrix
from .actors import Actor
from .schemas import (
    ApproveIn,
    Audience,
    EmergencyBroadcastIn,
    NoticeCreate,
    NoticeEdit,
    PublishIn,
    RevisionCreate,
)

SIGNIFICANT: Final = frozenset({"legal", "safety", "emergency"})
_URL: Final = re.compile(r"(https?://|www\.|\.(com|in|net|org)(/|\s|$))", re.IGNORECASE)
ROLE_CHOICES: Final = matrix.ALL_ROLES - matrix.PLATFORM_ROLES
_NOTICE_UPDATABLE: Final = frozenset(
    {
        "audience", "audience_scope", "audience_block_ids", "audience_unit_ids", "audience_roles", "state",
        "target_languages", "latest_revision", "current_version_id", "superseded_by", "archived_at",
    }
)  # fmt: skip
NOTICE_SELECT: Final = (
    "SELECT n.id, n.kind, n.audience, n.audience_scope, n.state, n.target_languages, n.latest_revision,"
    " n.current_version_id, n.superseded_by, n.created_by, n.version, n.created_at, n.updated_at, n.archived_at,"
    " lv.id AS latest_version_id, lv.state AS latest_state, lv.language AS latest_language, lv.title AS latest_title,"
    " lv.body AS latest_body, lv.drafted_by_ai, lv.ai_run_ref, lv.approved_by, lv.approved_at, lv.publish_at,"
    " lv.published_at AS latest_published_at, lv.content_hash AS latest_hash, lv.created_by AS latest_created_by"
    " FROM notices n JOIN notice_versions lv ON lv.notice_id = n.id AND lv.revision = n.latest_revision"
)  # fmt: skip


def content_hash(language: str, title: str, body: str) -> str:
    raw = json.dumps(
        {"l": language, "t": title, "b": body},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------------------ reads
def fetch_notice(
    conn: Connection, notice_id: uuid.UUID, *, lock: bool = False
) -> dict[str, Any] | None:
    if (
        lock
        and conn.execute(
            text("SELECT id FROM notices WHERE id = :id FOR UPDATE"), {"id": notice_id}
        ).first()
        is None
    ):
        return None
    row = (
        conn.execute(text(f"{NOTICE_SELECT} WHERE n.id = :id"), {"id": notice_id})
        .mappings()
        .first()
    )  # noqa: S608
    return dict(row) if row else None


def versions_of(conn: Connection, notice_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, revision, language, state, drafted_by_ai, created_by, created_at, approved_by, approved_at,"
            " publish_at, published_at, content_hash FROM notice_versions WHERE notice_id = :id ORDER BY revision"
        ),
        {"id": notice_id},
    ).mappings()
    return [dict(r) for r in rows]


def version_row(conn: Connection, version_id: uuid.UUID) -> dict[str, Any] | None:
    row = conn.execute(
        text("SELECT id, notice_id, revision, language, title, body, state, published_at, content_hash FROM notice_versions WHERE id = :id"),
        {"id": version_id},
    ).mappings().first()  # fmt: skip
    return dict(row) if row else None


def translations_of(conn: Connection, version_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT id, language, title, body, origin, drafted_by_ai, translated_by, review_state, reviewed_by, reviewed_at,"
            " review_note, version FROM notice_translations WHERE notice_version_id = :v ORDER BY language"
        ),
        {"v": version_id},
    ).mappings()
    return [dict(r) for r in rows]


def my_blocks(conn: Connection, actor: Actor) -> list[uuid.UUID]:
    if not actor.unit_ids:
        return []
    rows = conn.execute(
        text("SELECT DISTINCT block_id FROM units WHERE id = ANY(:u)"),
        {"u": sorted(actor.unit_ids, key=lambda x: x.int)},
    ).all()
    return [r[0] for r in rows]


def reader_filter(conn: Connection, actor: Actor) -> tuple[list[str], dict[str, Any]]:
    """SQL fragments selecting the notices a reader may see: published history only, restricted to their audience."""
    where = ["n.state IN ('published', 'superseded', 'archived')"]
    params: dict[str, Any] = {}
    if actor.sees_everything:
        return where, params
    params["blocks"] = sorted(my_blocks(conn, actor), key=lambda x: x.int)
    params["units"] = sorted(actor.unit_ids, key=lambda x: x.int)
    params["roles"] = [actor.role]
    where.append(
        "(n.audience_scope = 'society'"
        " OR (n.audience_scope = 'block' AND n.audience_block_ids && CAST(:blocks AS uuid[]))"
        " OR (n.audience_scope = 'unit' AND n.audience_unit_ids && CAST(:units AS uuid[]))"
        " OR (n.audience_scope = 'role' AND n.audience_roles && CAST(:roles AS text[])))"
    )
    return where, params


def in_audience(conn: Connection, actor: Actor, n: dict[str, Any]) -> bool:
    if actor.sees_everything:
        return True
    scope = n["audience_scope"]
    if scope == "society":
        return True
    aud = n["audience"]
    if scope == "block":
        wanted = {uuid.UUID(x) for x in aud.get("block_ids", [])}
        return bool(wanted & set(my_blocks(conn, actor)))
    if scope == "unit":
        return bool({uuid.UUID(x) for x in aud.get("unit_ids", [])} & set(actor.unit_ids))
    return actor.role in aud.get("roles", [])


def viewer_audience(n: dict[str, Any], actor: Actor) -> str | None:
    """'staff' (drafts and all states) or 'reader' (published history only); None when the caller may not see it at all."""
    if actor.can_draft:
        return "staff"
    if n["state"] in {"published", "superseded", "archived"}:
        return "reader"
    return None


def notice_view(conn: Connection, n: dict[str, Any], aud: str, actor: Actor) -> dict[str, Any]:
    """Staff see every revision and the gates; readers see the CURRENT PUBLISHED revision, the original, and only the
    translations that may be shown (COM-02: always next to the original; legal/safety ones only after human review)."""
    significant = n["kind"] in SIGNIFICANT
    current = version_row(conn, n["current_version_id"]) if n["current_version_id"] else None
    base: dict[str, Any] = {
        "id": n["id"], "kind": n["kind"], "state": n["state"], "audience": n["audience"], "target_languages": list(n["target_languages"]),
        "version": n["version"], "created_at": n["created_at"], "updated_at": n["updated_at"], "significant": significant,
        "superseded_by": n["superseded_by"], "channel": "emergency" if n["kind"] == "emergency" else "notices",
    }  # fmt: skip
    if aud == "reader":
        if current is None:
            return {**base, "original": None, "translations": []}
        shown = [
            t for t in translations_of(conn, current["id"])
            if t["review_state"] == "reviewed" or (not significant and t["review_state"] != "rejected")
        ]  # fmt: skip
        mine = {
            r[0] for r in conn.execute(
                text("SELECT kind FROM notice_receipts WHERE notice_version_id = :v AND person_id = :p"),
                {"v": current["id"], "p": actor.person_id},
            ).all()
        }  # fmt: skip
        return {
            **base,
            "revision": current["revision"], "published_at": current["published_at"],
            "original": {"language": current["language"], "title": current["title"], "body": current["body"]},
            "translations": [_translation_view(t) for t in shown],
            "read": "read" in mine or "acknowledged" in mine, "acknowledged": "acknowledged" in mine,
        }  # fmt: skip
    latest = {
        "language": n["latest_language"],
        "title": n["latest_title"],
        "body": n["latest_body"],
    }
    out: dict[str, Any] = {
        **base,
        "latest_revision": n["latest_revision"], "latest_state": n["latest_state"], "latest": latest,
        "drafted_by_ai": n["drafted_by_ai"], "approved_by": n["approved_by"], "approved_at": n["approved_at"],
        "publish_at": n["publish_at"], "versions": versions_of(conn, n["id"]),
        "original": None if current is None else {"language": current["language"], "title": current["title"], "body": current["body"]},
        "translations": [_translation_view(t, staff=True) for t in translations_of(conn, n["latest_version_id"])],
        "gates": {
            "needs_human_approval": True,
            "ai_draft_requires_confirmation": bool(n["drafted_by_ai"]),
            "translation_review_required": significant,
        },
    }  # fmt: skip
    return out


def _translation_view(t: dict[str, Any], *, staff: bool = False) -> dict[str, Any]:
    view = {
        "language": t["language"], "title": t["title"], "body": t["body"], "origin": t["origin"],
        "machine_drafted": t["origin"] == "machine_draft", "review_state": t["review_state"],
        "human_reviewed": t["review_state"] == "reviewed", "reviewed_at": t["reviewed_at"],
    }  # fmt: skip
    if staff:
        view.update(
            {
                "reviewed_by": t["reviewed_by"],
                "translated_by": t["translated_by"],
                "review_note": t["review_note"],
                "version": t["version"],
            }
        )
    return view


# ------------------------------------------------------------------------------------------ internals
def _lock(conn: Connection, notice_id: uuid.UUID, expected: int | None) -> dict[str, Any]:
    n = fetch_notice(conn, notice_id, lock=True)
    if n is None:
        raise NotFound()
    if expected is not None and n["version"] != expected:
        raise StaleVersion()
    return n


def _bump(conn: Connection, n: dict[str, Any], changes: dict[str, Any], now: dt.datetime) -> int:
    bad = set(changes) - _NOTICE_UPDATABLE
    if bad:
        raise ValueError(f"not an updatable notice column: {sorted(bad)}")
    sets = "".join(f"{c} = :{c}, " for c in changes)
    sql = f"UPDATE notices SET {sets}version = version + 1, updated_at = :_now WHERE id = :_id AND version = :_v"  # noqa: S608
    params = {**changes, "_now": now, "_id": n["id"], "_v": n["version"]}
    if "audience" in params:
        params["audience"] = json.dumps(params["audience"])
        sql = sql.replace("audience = :audience", "audience = CAST(:audience AS jsonb)")
    if conn.execute(text(sql), params).rowcount != 1:
        raise StaleVersion()
    return int(n["version"]) + 1


def _payload(n: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "notice_id": n["id"], "kind": n["kind"], "audience_scope": n["audience_scope"],
        "target_languages": list(n["target_languages"]), **extra,
    }  # fmt: skip


def _mutate(
    conn: Connection, ctx: RequestContext, notice_id: uuid.UUID, *, expected: int | None, operation: str, event_type: str,
    plan: Any, now: dt.datetime, reason: str | None = None,
) -> dict[str, Any]:  # fmt: skip
    n = _lock(conn, notice_id, expected)

    def apply(c: Connection) -> MutationResult:
        changes, payload = plan(c, n, now)
        new_version = _bump(c, n, changes, now)
        keys = [
            k
            for k in ("state", "current_version_id", "superseded_by", "latest_revision")
            if k in changes
        ]
        return MutationResult(
            n["id"], new_version, before={k: n[k] for k in keys}, after={k: changes[k] for k in keys},
            event_payload=_payload({**n, **changes}, **payload),
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation=operation,
        object_type="notice",
        event_type=event_type,
        apply=apply,
        reason=reason,
    )
    fresh = fetch_notice(conn, notice_id)
    assert fresh is not None  # noqa: S101
    return fresh


def _audience_columns(conn: Connection, aud: Audience) -> dict[str, Any]:
    cols: dict[str, Any] = {
        "audience": aud.model_dump(mode="json"), "audience_scope": aud.scope, "audience_block_ids": [],
        "audience_unit_ids": [], "audience_roles": [],
    }  # fmt: skip
    if aud.scope == "society":
        if aud.block_ids or aud.unit_ids or aud.roles:
            raise InvalidSchema.for_fields([("audience", "society_scope_takes_no_targets")])
    elif aud.scope == "block":
        _only(aud, "block_ids")
        found = conn.execute(
            text("SELECT count(*) FROM blocks WHERE id = ANY(:i)"), {"i": aud.block_ids}
        ).scalar_one()
        if found != len(set(aud.block_ids)):
            raise InvalidSchema.for_fields([("audience.block_ids", "unknown_block")])
        cols["audience_block_ids"] = sorted(set(aud.block_ids), key=lambda x: x.int)
    elif aud.scope == "unit":
        _only(aud, "unit_ids")
        found = conn.execute(
            text("SELECT count(*) FROM units WHERE id = ANY(:i)"), {"i": aud.unit_ids}
        ).scalar_one()
        if found != len(set(aud.unit_ids)):
            raise InvalidSchema.for_fields([("audience.unit_ids", "unknown_unit")])
        cols["audience_unit_ids"] = sorted(set(aud.unit_ids), key=lambda x: x.int)
    else:
        _only(aud, "roles")
        if not set(aud.roles) <= ROLE_CHOICES:
            raise InvalidSchema.for_fields([("audience.roles", "unknown_role")])
        cols["audience_roles"] = sorted(set(aud.roles))
    return cols


def _only(aud: Audience, field: str) -> None:
    others = {"block_ids", "unit_ids", "roles"} - {field}
    if not getattr(aud, field) or any(getattr(aud, o) for o in others):
        raise InvalidSchema.for_fields([("audience", f"{aud.scope}_scope_needs_only_{field}")])


# ------------------------------------------------------------------------------------------ create / edit / revise
def create_notice(
    conn: Connection, ctx: RequestContext, actor: Actor, body: NoticeCreate, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    cols = _audience_columns(conn, body.audience)
    if body.ai_run_ref and not body.drafted_by_ai:
        raise InvalidSchema.for_fields([("ai_run_ref", "needs_drafted_by_ai")])
    notice_id, version_id = uuid7(), uuid7()
    targets = sorted({t for t in body.target_languages if t != body.language})

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO notices (id, society_id, kind, audience, audience_scope, audience_block_ids, audience_unit_ids,"
                " audience_roles, target_languages, created_by, created_at, updated_at) VALUES (:id, :s, :kind,"
                " CAST(:aud AS jsonb), :scope, :blocks, :units, :roles, :targets, :by, :now, :now)"
            ),
            {
                "id": notice_id, "s": ctx.society_id, "kind": body.kind, "aud": json.dumps(cols["audience"]),
                "scope": cols["audience_scope"], "blocks": cols["audience_block_ids"], "units": cols["audience_unit_ids"],
                "roles": cols["audience_roles"], "targets": targets, "by": ctx.person_id, "now": moment,
            },
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO notice_versions (id, society_id, notice_id, revision, language, title, body, content_hash,"
                " drafted_by_ai, ai_run_ref, created_by, created_at) VALUES (:id, :s, :n, 1, :lang, :title, :body, :h,"
                " :ai, :ref, :by, :now)"
            ),
            {
                "id": version_id, "s": ctx.society_id, "n": notice_id, "lang": body.language, "title": body.title,
                "body": body.body, "h": content_hash(body.language, body.title, body.body), "ai": body.drafted_by_ai,
                "ref": body.ai_run_ref, "by": ctx.person_id, "now": moment,
            },
        )  # fmt: skip
        return MutationResult(
            notice_id, 1, after={"state": "draft", "kind": body.kind},
            event_payload={
                "notice_id": notice_id, "kind": body.kind, "audience_scope": cols["audience_scope"], "state": "draft",
                "drafted_by_ai": body.drafted_by_ai, "target_languages": targets,
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="notice.create",
        object_type="notice",
        event_type="NoticeDrafted",
        apply=apply,
    )
    fresh = fetch_notice(conn, notice_id)
    assert fresh is not None  # noqa: S101
    return fresh


def _editable_latest(n: dict[str, Any], actor: Actor) -> None:
    if n["latest_state"] != "draft":
        raise StaleVersion(
            "Only a draft revision can be edited; start a new revision.",
            details={"reason": "revision_not_draft"},
        )
    if not (actor.can_manage or n["latest_created_by"] == actor.person_id):
        raise NotFound()


def edit_draft(
    conn: Connection, ctx: RequestContext, actor: Actor, notice_id: uuid.UUID, body: NoticeEdit, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    cols = _audience_columns(conn, body.audience) if body.audience is not None else {}

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        _editable_latest(n, actor)
        lang = body.language or n["latest_language"]
        title = body.title or n["latest_title"]
        text_body = body.body or n["latest_body"]
        c.execute(
            text("UPDATE notice_versions SET language = :l, title = :t, body = :b, content_hash = :h WHERE id = :id"),
            {"l": lang, "t": title, "b": text_body, "h": content_hash(lang, title, text_body), "id": n["latest_version_id"]},
        )  # fmt: skip
        changes: dict[str, Any] = dict(cols)
        if body.target_languages is not None:
            changes["target_languages"] = sorted({t for t in body.target_languages if t != lang})
        return changes, {"revision": n["latest_revision"], "state": "draft"}

    return _mutate(
        conn,
        ctx,
        notice_id,
        expected=body.expected_version,
        operation="notice.edit_draft",
        event_type="NoticeDraftEdited",
        plan=plan,
        now=moment,
    )


def new_revision(
    conn: Connection, ctx: RequestContext, actor: Actor, notice_id: uuid.UUID, body: RevisionCreate, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """COM-01: a change to anything past draft is a NEW revision. The published one stays exactly as it was until the new one
    is approved and published; it is then superseded."""
    moment = now or utc_now()

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if n["latest_state"] == "draft" or n["state"] in {"archived", "superseded"}:
            raise StaleVersion(
                "There is already a draft revision, or the notice is closed.",
                details={"reason": "revision_not_allowed"},
            )
        if n["latest_state"] in {"approved", "scheduled"} and n["current_version_id"] is None:
            raise StaleVersion(
                "An approved revision exists; publish or archive it first.",
                details={"reason": "revision_not_allowed"},
            )
        rev = n["latest_revision"] + 1
        lang = body.language or n["latest_language"]
        c.execute(
            text(
                "INSERT INTO notice_versions (society_id, notice_id, revision, language, title, body, content_hash, created_by,"
                " created_at) VALUES (:s, :n, :r, :l, :t, :b, :h, :by, :now)"
            ),
            {
                "s": ctx.society_id, "n": n["id"], "r": rev, "l": lang, "t": body.title, "b": body.body,
                "h": content_hash(lang, body.title, body.body), "by": ctx.person_id, "now": m,
            },
        )  # fmt: skip
        return {"latest_revision": rev}, {"revision": rev, "state": "draft"}

    return _mutate(
        conn,
        ctx,
        notice_id,
        expected=body.expected_version,
        operation="notice.revise",
        event_type="NoticeRevisionDrafted",
        plan=plan,
        now=moment,
    )


# ------------------------------------------------------------------------------------------ approve / publish / archive
def approve(
    conn: Connection, ctx: RequestContext, actor: Actor, notice_id: uuid.UUID, body: ApproveIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """COM-01/COM-03: a person approves the exact revision. An AI draft needs the explicit confirmation as well."""
    moment = now or utc_now()

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if n["latest_state"] != "draft":
            raise StaleVersion(
                "Only a draft revision can be approved.", details={"reason": "revision_not_draft"}
            )
        if n["drafted_by_ai"] and not body.confirm_ai_review:
            raise PolicyViolation(
                "An AI-drafted notice needs a person to confirm they reviewed the draft.",
                details={"reason": "ai_draft_needs_human_review"},
            )
        c.execute(
            text("UPDATE notice_versions SET state = 'approved', approved_by = :by, approved_at = :now WHERE id = :id"),
            {"by": ctx.person_id, "now": m, "id": n["latest_version_id"]},
        )  # fmt: skip
        changes: dict[str, Any] = {"state": "approved"} if n["current_version_id"] is None else {}
        return changes, {
            "revision": n["latest_revision"],
            "state": "approved",
            "drafted_by_ai": n["drafted_by_ai"],
        }

    return _mutate(
        conn,
        ctx,
        notice_id,
        expected=body.expected_version,
        operation="notice.approve",
        event_type="NoticeApproved",
        plan=plan,
        now=moment,
    )


def translation_gate(conn: Connection, n: dict[str, Any]) -> None:
    """COM-02: a legal or safety notice cannot be published while a translation it would show lacks recorded human review, or
    while a declared target language has no reviewed translation."""
    if n["kind"] not in SIGNIFICANT:
        return
    have = {t["language"]: t for t in translations_of(conn, n["latest_version_id"])}
    unreviewed = sorted(lang for lang, t in have.items() if t["review_state"] == "unreviewed")
    missing = sorted(
        lang
        for lang in n["target_languages"]
        if have.get(lang, {}).get("review_state") != "reviewed"
    )
    if unreviewed or missing:
        raise PolicyViolation(
            "A legal or safety notice needs every translation reviewed by a person before it is published.",
            details={
                "reason": "translation_review_required",
                "unreviewed": unreviewed,
                "missing_or_unreviewed_targets": missing,
            },
        )


def _go_live(
    conn: Connection, ctx: RequestContext, n: dict[str, Any], now: dt.datetime
) -> dict[str, Any]:
    """Publish the latest approved/scheduled revision; supersede the previous published one."""
    if n["current_version_id"] is not None:
        conn.execute(
            text(
                "UPDATE notice_versions SET state = 'superseded' WHERE id = :id AND state = 'published'"
            ),
            {"id": n["current_version_id"]},
        )
    conn.execute(
        text("UPDATE notice_versions SET state = 'published', published_at = :now WHERE id = :id"),
        {"now": now, "id": n["latest_version_id"]},
    )
    return {"state": "published", "current_version_id": n["latest_version_id"]}


def publish(
    conn: Connection, ctx: RequestContext, actor: Actor, notice_id: uuid.UUID, body: PublishIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    if body.publish_at is not None and body.publish_at.tzinfo is None:
        raise InvalidSchema.for_fields([("publish_at", "timezone_required")])
    later = body.publish_at is not None and body.publish_at > moment

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if n["latest_state"] != "approved":
            raise StaleVersion(
                "Only an approved revision can be published; approval is a separate, recorded step.",
                details={"reason": "approval_required"},
            )
        if n["kind"] == "emergency":
            raise InvalidSchema.for_fields([("kind", "use_emergency_broadcast")])
        translation_gate(c, n)
        changes: dict[str, Any] = {}
        if body.supersedes_notice_id is not None:
            other = fetch_notice(c, body.supersedes_notice_id, lock=True)
            if other is None or other["id"] == n["id"] or other["state"] != "published":
                raise NotFound()
            c.execute(
                text(
                    "UPDATE notices SET state = 'superseded', superseded_by = :by, version = version + 1, updated_at = :now WHERE id = :id"
                ),
                {"by": n["id"], "now": m, "id": other["id"]},
            )
        if later:
            c.execute(
                text("UPDATE notice_versions SET state = 'scheduled', publish_at = :at WHERE id = :id"),
                {"at": body.publish_at, "id": n["latest_version_id"]},
            )  # fmt: skip
            if n["current_version_id"] is None:
                changes["state"] = "scheduled"
            return changes, {
                "revision": n["latest_revision"],
                "state": "scheduled",
                "publish_at": body.publish_at.isoformat() if body.publish_at else None,
            }
        changes.update(_go_live(c, ctx, n, m))
        return changes, {
            "revision": n["latest_revision"], "state": "published", "version_id": n["latest_version_id"],
            "supersedes_notice_id": body.supersedes_notice_id, "audience": n["audience"], "channel": "notices",
        }  # fmt: skip

    return _mutate(
        conn, ctx, notice_id, expected=body.expected_version, operation="notice.schedule" if later else "notice.publish",
        event_type="NoticeScheduled" if later else "NoticePublished", plan=plan, now=moment,
    )  # fmt: skip


def publish_due(conn: Connection, ctx: RequestContext, now: dt.datetime | None = None) -> int:
    """Publish scheduled revisions whose time has come (idempotent; the gates are checked again at that moment)."""
    moment = now or utc_now()
    done = 0
    for (nid,) in conn.execute(
        text(
            "SELECT n.id FROM notices n JOIN notice_versions v ON v.notice_id = n.id AND v.revision = n.latest_revision"
            " WHERE v.state = 'scheduled' AND v.publish_at <= :now ORDER BY v.publish_at, n.id FOR UPDATE OF n SKIP LOCKED"
        ),
        {"now": moment},
    ).all():

        def plan(
            c: Connection, n: dict[str, Any], m: dt.datetime
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            translation_gate(c, n)
            changes = _go_live(c, ctx, n, m)
            return changes, {
                "revision": n["latest_revision"], "state": "published", "version_id": n["latest_version_id"],
                "audience": n["audience"], "channel": "notices",
            }  # fmt: skip

        try:
            _mutate(
                conn,
                ctx,
                nid,
                expected=None,
                operation="notice.publish",
                event_type="NoticePublished",
                plan=plan,
                now=moment,
            )
            done += 1
        except PolicyViolation:
            continue  # a translation was un-reviewed since scheduling: it stays scheduled until a person fixes it
    return done


def archive(
    conn: Connection, ctx: RequestContext, actor: Actor, notice_id: uuid.UUID, reason: str, expected: int | None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if n["state"] != "published":
            raise StaleVersion(
                "Only a published notice can be archived.", details={"reason": "not_published"}
            )
        return {"state": "archived", "archived_at": m}, {"state": "archived"}

    return _mutate(
        conn,
        ctx,
        notice_id,
        expected=expected,
        operation="notice.archive",
        event_type="NoticeArchived",
        plan=plan,
        now=moment,
        reason=reason,
    )


# ------------------------------------------------------------------------------------------ translations (COM-02)
def add_translation(
    conn: Connection, ctx: RequestContext, notice_id: uuid.UUID, language: str, title: str, body: str, *,
    origin: str = "human", ai_run_ref: str | None = None, now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Attach a translation to the LATEST revision. ``origin='machine_draft'`` is for the ai-gateway integration only (the
    HTTP route accepts human translations); either way it starts ``unreviewed`` and a reviewed text can never be changed."""
    moment = now or utc_now()
    if origin not in {"human", "machine_draft"}:
        raise InvalidSchema.for_fields([("origin", "invalid")])

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if language == n["latest_language"]:
            raise InvalidSchema.for_fields([("language", "is_the_original_language")])
        if n["state"] in {"archived", "superseded"}:
            raise StaleVersion("The notice is closed.", details={"reason": "notice_closed"})
        existing = c.execute(
            text("SELECT id, review_state FROM notice_translations WHERE notice_version_id = :v AND language = :l FOR UPDATE"),
            {"v": n["latest_version_id"], "l": language},
        ).first()  # fmt: skip
        ai = origin == "machine_draft"
        if existing is not None and existing[1] == "reviewed":
            raise StaleVersion(
                "A reviewed translation cannot be changed; start a new revision.",
                details={"reason": "translation_reviewed"},
            )
        if existing is None:
            c.execute(
                text(
                    "INSERT INTO notice_translations (society_id, notice_id, notice_version_id, language, title, body, origin,"
                    " drafted_by_ai, ai_run_ref, translated_by, created_at) VALUES (:s, :n, :v, :l, :t, :b, :o, :ai, :ref,"
                    " :by, :now)"
                ),
                {
                    "s": ctx.society_id, "n": n["id"], "v": n["latest_version_id"], "l": language, "t": title, "b": body,
                    "o": origin, "ai": ai, "ref": ai_run_ref if ai else None, "by": None if ai else ctx.person_id, "now": m,
                },
            )  # fmt: skip
        else:
            c.execute(
                text(
                    "UPDATE notice_translations SET title = :t, body = :b, origin = :o, drafted_by_ai = :ai, ai_run_ref = :ref,"
                    " translated_by = :by, review_state = 'unreviewed', reviewed_by = NULL, reviewed_at = NULL,"
                    " review_note = NULL, version = version + 1 WHERE id = :id"
                ),
                {"t": title, "b": body, "o": origin, "ai": ai, "ref": ai_run_ref if ai else None, "by": None if ai else ctx.person_id, "id": existing[0]},
            )  # fmt: skip
        return {}, {
            "language": language,
            "origin": origin,
            "review_state": "unreviewed",
            "revision": n["latest_revision"],
        }

    return _mutate(
        conn, ctx, notice_id, expected=None, operation="notice.translation_add", event_type="NoticeTranslationAdded", plan=plan, now=moment
    )  # fmt: skip


def review_translation(
    conn: Connection, ctx: RequestContext, actor: Actor, notice_id: uuid.UUID, language: str, decision: str,
    note: str | None, now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    """COM-02: a person records review of the exact text. For a legal/safety notice a HUMAN translation needs a different
    reviewer than its translator; a machine draft needs any human."""
    moment = now or utc_now()

    def plan(
        c: Connection, n: dict[str, Any], m: dt.datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        row = c.execute(
            text("SELECT id, review_state, translated_by, origin FROM notice_translations WHERE notice_version_id = :v AND language = :l FOR UPDATE"),
            {"v": n["latest_version_id"], "l": language},
        ).first()  # fmt: skip
        if row is None:
            raise NotFound()
        if row[1] != "unreviewed":
            raise StaleVersion(
                "This translation was already reviewed.", details={"reason": "already_reviewed"}
            )
        if n["kind"] in SIGNIFICANT and row[3] == "human" and row[2] == ctx.person_id:
            raise PolicyViolation(
                "A legal or safety translation needs a reviewer other than its translator.",
                details={"reason": "reviewer_must_differ"},
            )
        state = "reviewed" if decision == "approve" else "rejected"
        c.execute(
            text(
                "UPDATE notice_translations SET review_state = :st, reviewed_by = :by, reviewed_at = :now, review_note = :note,"
                " version = version + 1 WHERE id = :id"
            ),
            {"st": state, "by": ctx.person_id, "now": m, "note": note, "id": row[0]},
        )  # fmt: skip
        return {}, {"language": language, "review_state": state, "revision": n["latest_revision"]}

    return _mutate(
        conn, ctx, notice_id, expected=None, operation="notice.translation_review", event_type="NoticeTranslationReviewed", plan=plan, now=moment, reason=note
    )  # fmt: skip


# ------------------------------------------------------------------------------------------ receipts and delivery records
def record_receipt(
    conn: Connection, ctx: RequestContext, actor: Actor, n: dict[str, Any], kind: str, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """COM-01: a read or acknowledgement of the CURRENT published revision (one of each kind per person per revision)."""
    if (
        n["state"] != "published"
        or n["current_version_id"] is None
        or not in_audience(conn, actor, n)
    ):
        raise NotFound()
    moment = now or utc_now()
    inserted = conn.execute(
        text(
            "INSERT INTO notice_receipts (society_id, notice_version_id, person_id, kind, at) VALUES (:s, :v, :p, :k, :now)"
            " ON CONFLICT (society_id, notice_version_id, person_id, kind) DO NOTHING RETURNING at"
        ),
        {"s": ctx.society_id, "v": n["current_version_id"], "p": actor.person_id, "k": kind, "now": moment},
    ).first()  # fmt: skip
    if inserted is not None and kind == "acknowledged":
        record_audit(
            conn,
            ctx,
            operation="notice.acknowledged",
            object_type="notice",
            object_id=n["id"],
            after={"revision_state": "published"},
        )
    at = inserted[0] if inserted else conn.execute(
        text("SELECT at FROM notice_receipts WHERE notice_version_id = :v AND person_id = :p AND kind = :k"),
        {"v": n["current_version_id"], "p": actor.person_id, "k": kind},
    ).scalar_one()  # fmt: skip
    return {
        "kind": kind,
        "at": at,
        "recorded": inserted is not None,
        "revision_id": n["current_version_id"],
    }


def receipt_summary(conn: Connection, n: dict[str, Any], *, detail: bool) -> dict[str, Any]:
    version_id = n["current_version_id"] or n["latest_version_id"]
    counts = {
        r[0]: r[1] for r in conn.execute(
            text("SELECT kind, count(*) FROM notice_receipts WHERE notice_version_id = :v GROUP BY kind"), {"v": version_id}
        ).all()
    }  # fmt: skip
    deliveries = [
        {"channel": r[0], "status": r[1], "count": r[2]} for r in conn.execute(
            text("SELECT channel, status, count(*) FROM notice_deliveries WHERE notice_version_id = :v GROUP BY channel, status ORDER BY 1, 2"),
            {"v": version_id},
        ).all()
    ]  # fmt: skip
    out: dict[str, Any] = {
        "notice_id": n["id"], "revision_id": version_id, "read": counts.get("read", 0),
        "acknowledged": counts.get("acknowledged", 0), "delivery_summary": deliveries,
    }  # fmt: skip
    if detail:
        out["acknowledgements"] = [
            {"person_id": r[0], "at": r[1]} for r in conn.execute(
                text("SELECT person_id, at FROM notice_receipts WHERE notice_version_id = :v AND kind = 'acknowledged' ORDER BY at DESC, id DESC LIMIT 100"),
                {"v": version_id},
            ).all()
        ]  # fmt: skip
    return out


def deliveries_of(conn: Connection, n: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT channel, status, attempt, provider_ref, detail, simulation, at, person_id FROM notice_deliveries"
            " WHERE notice_version_id = :v ORDER BY at DESC, id DESC LIMIT :n"
        ),
        {"v": n["current_version_id"] or n["latest_version_id"], "n": limit},
    ).mappings()
    return [dict(r) for r in rows]


def record_delivery_attempt(
    conn: Connection, ctx: RequestContext, version_id: uuid.UUID, person_id: uuid.UUID, channel: str, status: str, *,
    attempt: int = 1, provider_ref: str | None = None, detail: str | None = None, simulation: bool = False,
) -> None:  # fmt: skip
    """The contract for the notifications module: ONE ROW PER ATTEMPT (append-only). This module never dispatches."""
    conn.execute(
        text(
            "INSERT INTO notice_deliveries (society_id, notice_version_id, person_id, channel, status, attempt, provider_ref,"
            " detail, simulation) VALUES (:s, :v, :p, :c, :st, :a, :ref, :d, :sim)"
        ),
        {
            "s": ctx.society_id,
            "v": version_id,
            "p": person_id,
            "c": channel,
            "st": status,
            "a": attempt,
            "ref": provider_ref,
            "d": detail,
            "sim": simulation,
        },
    )


# ------------------------------------------------------------------------------------------ emergency (COM-05)
def validate_emergency(conn: Connection, body: EmergencyBroadcastIn) -> None:
    """Everything that can be refused without side effects (text, audience ids): run BEFORE the rate limit is spent."""
    check_emergency_text(body)
    _audience_columns(conn, body.audience)


def check_emergency_text(body: EmergencyBroadcastIn) -> None:
    """No links, no advertisements (INV-05). Cheap and deterministic, so the route can run it BEFORE spending rate limit."""
    if _URL.search(body.title) or _URL.search(body.message):
        raise PolicyViolation(
            "An emergency broadcast carries no links or advertisements.",
            details={"reason": "no_links_in_emergency"},
        )


def emergency_broadcast(
    conn: Connection, ctx: RequestContext, actor: Actor, body: EmergencyBroadcastIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    """COM-05: published AT ONCE by a privileged role (their identity is recorded as approver), plain text, no links, never
    AI-drafted. The notifications module sends it on the emergency channel from ``EmergencyBroadcastIssued``."""
    moment = now or utc_now()
    if _URL.search(body.title) or _URL.search(body.message):
        raise PolicyViolation(
            "An emergency broadcast carries no links or advertisements.",
            details={"reason": "no_links_in_emergency"},
        )
    cols = _audience_columns(conn, body.audience)
    notice_id, version_id = uuid7(), uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO notices (id, society_id, kind, audience, audience_scope, audience_block_ids, audience_unit_ids,"
                " audience_roles, state, current_version_id, created_by, created_at, updated_at) VALUES (:id, :s,"
                " 'emergency', CAST(:aud AS jsonb), :scope, :blocks, :units, :roles, 'draft', NULL, :by, :now, :now)"
            ),
            {
                "id": notice_id, "s": ctx.society_id, "aud": json.dumps(cols["audience"]), "scope": cols["audience_scope"],
                "blocks": cols["audience_block_ids"], "units": cols["audience_unit_ids"], "roles": cols["audience_roles"],
                "by": ctx.person_id, "now": moment,
            },
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO notice_versions (id, society_id, notice_id, revision, language, title, body, content_hash, state,"
                " created_by, created_at, approved_by, approved_at, published_at) VALUES (:id, :s, :n, 1, :l, :t, :b, :h,"
                " 'approved', :by, :now, :by, :now, NULL)"
            ),
            {"id": version_id, "s": ctx.society_id, "n": notice_id, "l": body.language, "t": body.title, "b": body.message,
             "h": content_hash(body.language, body.title, body.message), "by": ctx.person_id, "now": moment},
        )  # fmt: skip
        c.execute(
            text("UPDATE notice_versions SET state = 'published', published_at = :now WHERE id = :id"),
            {"now": moment, "id": version_id},
        )  # fmt: skip
        c.execute(
            text("UPDATE notices SET state = 'published', current_version_id = :v WHERE id = :id"),
            {"v": version_id, "id": notice_id},
        )  # fmt: skip
        return MutationResult(
            notice_id, 1, after={"state": "published", "kind": "emergency"},
            event_payload={
                "notice_id": notice_id, "version_id": version_id, "kind": "emergency", "channel": "emergency",
                "audience_scope": cols["audience_scope"], "audience": cols["audience"], "hazard": body.hazard,
                "language": body.language, "carries_ads": False,
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="notice.emergency_broadcast",
        object_type="notice",
        event_type="EmergencyBroadcastIssued",
        apply=apply,
        approver_id=ctx.person_id,
    )
    fresh = fetch_notice(conn, notice_id)
    assert fresh is not None  # noqa: S101
    return fresh
