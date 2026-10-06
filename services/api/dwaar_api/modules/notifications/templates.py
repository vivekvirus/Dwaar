"""Notification templates: the per-society registry of copy keys, DLT header / template ids and whitelisted URLs.

REQ: NOTIF-01 (a template for the security or emergency channel must pass the content-class validator), CALL-02 (SMS only through a DLT-registered
header and template, links only on whitelisted hosts; a template without DLT ids is a PLACEHOLDER and is never sent), D-21.

The DLT ids are placeholders until the society registers its principal entity with an operator; this build never invents one.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.errors import NotFound, StaleVersion
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import catalog
from . import categories as cat


def template_view(row: Any) -> dict[str, Any]:
    sendable = row["channel"] != "sms" or bool(row["dlt_header"] and row["dlt_template_id"])
    return {
        "id": row["id"],
        "template_key": row["template_key"],
        "category": row["category"],
        "channel": row["channel"],
        "language": row["language"],
        "content_class": row["content_class"],
        "body_key": row["body_key"],
        "dlt_header": row["dlt_header"],
        "dlt_template_id": row["dlt_template_id"],
        "whitelisted_url": row["whitelisted_url"],
        "status": row["status"],
        "sendable": bool(sendable and row["status"] == "active"),
        "dlt_placeholder": row["channel"] == "sms" and not sendable,
        "created_at": row["created_at"],
        "version": row["version"],
    }


_COLS = (
    "id, template_key, category, channel, language, content_class, body_key, dlt_header, dlt_template_id, whitelisted_url,"
    " status, created_at, version"
)


def list_templates(
    conn: Connection, *, category: str | None = None, channel: str | None = None
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"SELECT {_COLS} FROM notification_templates WHERE (CAST(:c AS text) IS NULL OR category = :c)"  # noqa: S608
            " AND (CAST(:ch AS text) IS NULL OR channel = :ch) ORDER BY category, template_key, channel, language"
        ),
        {"c": category, "ch": channel},
    ).mappings()
    return [template_view(r) for r in rows]


def create_template(
    conn: Connection,
    ctx: RequestContext,
    *,
    template_key: str,
    category: str,
    channel: str,
    language: str,
    content_class: str,
    body_key: str,
    dlt_header: str | None,
    dlt_template_id: str | None,
    whitelisted_url: str | None,
    hosts: Iterable[str],
) -> dict[str, Any]:
    """Register a template after the content rules have passed. Rejections are 422 ``policy_violation`` with a stable reason."""
    assert ctx.society_id is not None  # noqa: S101
    cat.validate_template(
        category=category, channel=channel, language=language, content_class=content_class, body_key=body_key,
        whitelisted_url=whitelisted_url, hosts=hosts,
    )  # fmt: skip
    if channel != "sms" and (dlt_header or dlt_template_id):
        raise cat.ContentRejected("dlt_fields_only_for_sms")
    tid = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO notification_templates (id, society_id, template_key, category, channel, language, content_class,"
                " body_key, dlt_header, dlt_template_id, whitelisted_url, created_by)"
                " VALUES (:id, :s, :k, :cat, :ch, :l, :cc, :b, :dh, :dt, :u, :by)"
            ),
            {"id": tid, "s": ctx.society_id, "k": template_key, "cat": category, "ch": channel, "l": language, "cc": content_class,
             "b": body_key, "dh": dlt_header, "dt": dlt_template_id, "u": whitelisted_url, "by": ctx.person_id},
        )  # fmt: skip
        return MutationResult(
            tid,
            1,
            after={"category": category, "channel": channel, "language": language, "content_class": content_class,
                   "has_dlt": bool(dlt_header and dlt_template_id)},
            event_payload={"template_id": tid, "category": category, "channel": channel, "language": language},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="notification.template.create", object_type="notification_template",
        event_type="notification.template_created", apply=apply,
    )  # fmt: skip
    fetch = text(f"SELECT {_COLS} FROM notification_templates WHERE id = :id")  # noqa: S608
    row = conn.execute(fetch, {"id": tid}).mappings().one()
    return template_view(row)


def ensure_defaults(conn: Connection, ctx: RequestContext, hosts: Iterable[str]) -> int:
    """Seed the default catalog for a society (idempotent: existing keys are left alone). SMS templates carry NO DLT ids (placeholders)."""
    assert ctx.society_id is not None  # noqa: S101
    host = sorted(hosts)[0]
    made = 0
    for t in catalog.DEFAULT_TEMPLATES:
        for lang in cat.LANGUAGES:
            exists = conn.execute(
                text(
                    "SELECT 1 FROM notification_templates WHERE template_key = :k AND channel = :ch AND language = :l"
                ),
                {"k": t.template_key, "ch": t.channel, "l": lang},
            ).first()
            if exists is not None:
                continue
            create_template(
                conn, ctx, template_key=t.template_key, category=t.category, channel=t.channel, language=lang,
                content_class=t.content_class, body_key=t.body_key, dlt_header=None, dlt_template_id=None,
                whitelisted_url=f"https://{host}{catalog.LINK_PATH}" if t.uses_link else None, hosts=[host],
            )  # fmt: skip
            made += 1
    return made


def template_ids(conn: Connection) -> list[uuid.UUID]:
    return [
        r[0] for r in conn.execute(text("SELECT id FROM notification_templates ORDER BY id")).all()
    ]


def register_dlt(
    conn: Connection,
    ctx: RequestContext,
    template_id: uuid.UUID,
    *,
    dlt_header: str,
    dlt_template_id: str,
    expected_version: int | None,
) -> dict[str, Any]:
    """Record the DLT sender header and template id the society registered with an operator (CALL-02): the placeholder becomes sendable.

    Only an SMS template has DLT ids, and only an active one. The ids are the society's own registration: this build never invents one."""
    row = conn.execute(
        text(
            "SELECT id, channel, status, version FROM notification_templates WHERE id = :id FOR UPDATE"
        ),
        {"id": template_id},
    ).first()
    if row is None:
        raise NotFound()
    if row[1] != "sms":
        raise cat.ContentRejected("dlt_fields_only_for_sms")
    if row[2] != "active":
        raise cat.ContentRejected("template_retired")
    if expected_version is not None and int(row[3]) != expected_version:
        raise StaleVersion(details={"version": int(row[3])})

    def apply(c: Connection) -> MutationResult:
        version = int(row[3]) + 1
        c.execute(
            text(
                "UPDATE notification_templates SET dlt_header = :h, dlt_template_id = :t, version = :v WHERE id = :id"
            ),
            {"h": dlt_header, "t": dlt_template_id, "v": version, "id": template_id},
        )
        return MutationResult(
            template_id,
            version,
            before={"has_dlt": False},
            after={"has_dlt": True},
            event_payload={"template_id": template_id, "version": version},
        )

    mutation(
        conn, ctx, operation="notification.template.register_dlt", object_type="notification_template",
        event_type="notification.template_dlt_registered", apply=apply,
    )  # fmt: skip
    fetch = text(f"SELECT {_COLS} FROM notification_templates WHERE id = :id")  # noqa: S608
    return template_view(conn.execute(fetch, {"id": template_id}).mappings().one())
