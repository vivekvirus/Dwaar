"""Document vault: versions, effective dates, authority, access levels, immutable published versions, scan gate, signed URLs.

REQ: COM-04 (versions, effective dates, authority, access levels for bye-laws, minutes, audit reports and circulars; published
versions immutable; sha256 recorded), SEC-03 (type and size validated, malware-scanned: a version is publishable only when its
scan state is CLEAN, and the default scanner never says clean), SEC-04 (storage keys are unguessable and never returned;
signed URLs are short-lived and issued only after a current access check), INV-01.

Flow: ``create_document`` -> ``add_version`` (a draft with dates and authority, no file yet) -> ``upload_content`` (validated,
hashed, stored through the ``ObjectStore`` adapter, scanned through the ``MalwareScanner`` adapter) -> ``publish_version``
(needs a stored, hashed, clean file; supersedes the previous published version). A published version never changes: a
correction is a new version. Withdrawing a version hides it from everyone; the row and the file remain for the audit trail.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import uuid
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import DependencyUnavailable, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation, record_audit
from ...core.db import RequestContext
from .actors import Actor
from .config import CommunityConfig
from .files import safe_filename, validate_upload
from .permissions import LEVEL_ROLES
from .scanner import MalwareScanner
from .schemas import DocumentCreate, VersionCreate
from .storage import ObjectStore, StorageError

_DOC_COLS: Final = "d.id, d.doc_type, d.title, d.authority, d.access_level, d.state, d.current_version_id, d.version, d.created_at, d.updated_at"
_VER_COLS: Final = (
    "v.id, v.document_id, v.version_no, v.state, v.effective_from, v.authority, v.change_note, v.original_filename,"
    " v.media_type, v.size_bytes, v.sha256, v.scan_state, v.scanner, v.scanner_simulation, v.storage_simulation,"
    " v.scanned_at, v.created_by, v.created_at, v.published_at, v.withdrawn_at"
)

_DOC_SQL: Final = "SELECT " + _DOC_COLS + " FROM documents d WHERE d.id = :id"  # noqa: S608
_VER_SQL: Final = "SELECT " + _VER_COLS + " FROM document_versions v WHERE v.document_id = :d"  # noqa: S608


def can_read_level(role: str, access_level: str) -> bool:
    return role in LEVEL_ROLES[access_level]


def doc_visible(actor: Actor, doc: dict[str, Any]) -> bool:
    return actor.can_draft or (
        doc["state"] == "active" and can_read_level(actor.role, doc["access_level"])
    )


def fetch_document(
    conn: Connection, doc_id: uuid.UUID, *, lock: bool = False
) -> dict[str, Any] | None:
    if (
        lock
        and conn.execute(
            text("SELECT id FROM documents WHERE id = :id FOR UPDATE"), {"id": doc_id}
        ).first()
        is None
    ):
        return None
    row = conn.execute(text(_DOC_SQL), {"id": doc_id}).mappings().first()
    return dict(row) if row else None


def fetch_version(
    conn: Connection, doc_id: uuid.UUID, version_id: uuid.UUID, *, lock: bool = False
) -> dict[str, Any] | None:
    if (
        lock
        and conn.execute(
            text("SELECT id FROM document_versions WHERE id = :v AND document_id = :d FOR UPDATE"),
            {"v": version_id, "d": doc_id},
        ).first()
        is None
    ):
        return None
    row = (
        conn.execute(text(_VER_SQL + " AND v.id = :v"), {"v": version_id, "d": doc_id})
        .mappings()
        .first()
    )
    return dict(row) if row else None


def versions_of(conn: Connection, doc_id: uuid.UUID, *, staff: bool) -> list[dict[str, Any]]:
    visible = (
        ["draft", "published", "superseded", "withdrawn"] if staff else ["published", "superseded"]
    )
    rows = conn.execute(
        text(_VER_SQL + " AND v.state = ANY(:states) ORDER BY v.version_no DESC"),
        {"d": doc_id, "states": visible},
    ).mappings()
    return [version_view(dict(r)) for r in rows]


def version_view(v: dict[str, Any]) -> dict[str, Any]:
    """Never carries the storage key. ``scan`` says plainly whether a real scanner looked at the file."""
    return {
        "id": v["id"], "version_no": v["version_no"], "state": v["state"], "effective_from": v["effective_from"],
        "authority": v["authority"], "change_note": v["change_note"], "filename": v["original_filename"],
        "media_type": v["media_type"], "size_bytes": v["size_bytes"], "sha256": v["sha256"],
        "scan": {"state": v["scan_state"], "scanner": v["scanner"], "simulation": v["scanner_simulation"], "scanned_at": v["scanned_at"]},
        "storage_simulation": v["storage_simulation"], "published_at": v["published_at"], "withdrawn_at": v["withdrawn_at"],
    }  # fmt: skip


def document_view(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc["id"], "doc_type": doc["doc_type"], "title": doc["title"], "authority": doc["authority"],
        "access_level": doc["access_level"], "state": doc["state"], "current_version_id": doc["current_version_id"],
        "version": doc["version"], "created_at": doc["created_at"], "updated_at": doc["updated_at"],
    }  # fmt: skip


# ------------------------------------------------------------------------------------------ writes
def create_document(
    conn: Connection, ctx: RequestContext, body: DocumentCreate, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    doc_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO documents (id, society_id, doc_type, title, authority, access_level, created_by, created_at, updated_at)"
                " VALUES (:id, :s, :t, :ti, :a, :l, :by, :now, :now)"
            ),
            {"id": doc_id, "s": ctx.society_id, "t": body.doc_type, "ti": body.title, "a": body.authority, "l": body.access_level, "by": ctx.person_id, "now": moment},
        )  # fmt: skip
        return MutationResult(
            doc_id, 1, after={"doc_type": body.doc_type, "access_level": body.access_level},
            event_payload={"document_id": doc_id, "doc_type": body.doc_type, "access_level": body.access_level},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="document.create",
        object_type="document",
        event_type="DocumentCreated",
        apply=apply,
    )
    doc = fetch_document(conn, doc_id)
    assert doc is not None  # noqa: S101
    return doc


def _bump_doc(
    conn: Connection, doc: dict[str, Any], changes: dict[str, Any], now: dt.datetime
) -> int:
    sets = "".join(f"{c} = :{c}, " for c in changes)
    sql = f"UPDATE documents SET {sets}version = version + 1, updated_at = :_now WHERE id = :_id AND version = :_v"  # noqa: S608
    if (
        conn.execute(
            text(sql), {**changes, "_now": now, "_id": doc["id"], "_v": doc["version"]}
        ).rowcount
        != 1
    ):
        raise StaleVersion()
    return int(doc["version"]) + 1


def add_version(
    conn: Connection, ctx: RequestContext, doc_id: uuid.UUID, body: VersionCreate, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    doc = fetch_document(conn, doc_id, lock=True)
    if doc is None:
        raise NotFound()
    if doc["state"] != "active":
        raise StaleVersion("The document is archived.", details={"reason": "document_archived"})
    version_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        next_no = c.execute(
            text(
                "SELECT coalesce(max(version_no), 0) + 1 FROM document_versions WHERE document_id = :d"
            ),
            {"d": doc_id},
        ).scalar_one()
        c.execute(
            text(
                "INSERT INTO document_versions (id, society_id, document_id, version_no, effective_from, authority, change_note,"
                " created_by, created_at) VALUES (:id, :s, :d, :no, :ef, :au, :cn, :by, :now)"
            ),
            {"id": version_id, "s": ctx.society_id, "d": doc_id, "no": next_no, "ef": body.effective_from, "au": body.authority or doc["authority"], "cn": body.change_note, "by": ctx.person_id, "now": moment},
        )  # fmt: skip
        new_version = _bump_doc(c, doc, {}, moment)
        return MutationResult(
            doc_id, new_version, after={"version_no": next_no, "state": "draft"},
            event_payload={"document_id": doc_id, "version_id": version_id, "version_no": next_no, "state": "draft"},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="document.version_create",
        object_type="document",
        event_type="DocumentVersionDrafted",
        apply=apply,
    )
    got = fetch_version(conn, doc_id, version_id)
    assert got is not None  # noqa: S101
    return got


def _scan_and_store(
    conn: Connection, ctx: RequestContext, version: dict[str, Any], data: bytes, filename: str, media: str, store: ObjectStore,
    scanner: MalwareScanner, now: dt.datetime,
) -> dict[str, Any]:  # fmt: skip
    digest = hashlib.sha256(data).hexdigest()
    result = scanner.scan(data, filename)
    old_key = conn.execute(
        text("SELECT object_key FROM document_versions WHERE id = :v"), {"v": version["id"]}
    ).scalar_one()
    new_key: str | None = None
    if result.state != "infected":  # an infected file is never kept
        try:
            new_key = store.put(data)
        except StorageError:
            raise DependencyUnavailable(retry_after=30) from None
    conn.execute(
        text(
            "UPDATE document_versions SET original_filename = :fn, media_type = :mt, size_bytes = :sz, sha256 = :h,"
            " object_key = :k, storage_simulation = :ssim, scan_state = :ss, scanner = :sc, scanner_simulation = :sim,"
            " scanned_at = :now WHERE id = :v"
        ),
        {
            "fn": filename if new_key else None, "mt": media if new_key else None, "sz": len(data) if new_key else None,
            "h": digest if new_key else None, "k": new_key, "ssim": store.simulation if new_key else False,
            "ss": result.state, "sc": result.scanner, "sim": result.simulation, "now": now, "v": version["id"],
        },
    )  # fmt: skip
    if old_key:
        with contextlib.suppress(
            StorageError
        ):  # an orphan object is harmless: nothing references it
            store.delete(old_key)
    return {"scan_state": result.state, "sha256": digest if new_key else None}


def upload_content(
    conn: Connection, ctx: RequestContext, cfg: CommunityConfig, store: ObjectStore, scanner: MalwareScanner, doc_id: uuid.UUID,
    version_id: uuid.UUID, data: bytes, content_type: str | None, filename: str | None, now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    doc = fetch_document(conn, doc_id, lock=True)
    version = fetch_version(conn, doc_id, version_id, lock=True)
    if doc is None or version is None:
        raise NotFound()
    if version["state"] != "draft":
        raise StaleVersion(
            "A published version is immutable; add a new version.",
            details={"reason": "version_not_draft"},
        )
    media = validate_upload(data, content_type, cfg.max_upload_bytes)
    name = safe_filename(filename)

    def apply(c: Connection) -> MutationResult:
        info = _scan_and_store(c, ctx, version, data, name, media, store, scanner, moment)
        new_version = _bump_doc(c, doc, {}, moment)
        return MutationResult(
            doc_id, new_version, after={"scan_state": info["scan_state"]},
            event_payload={"document_id": doc_id, "version_id": version_id, "scan_state": info["scan_state"], "sha256": info["sha256"]},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="document.upload",
        object_type="document",
        event_type="DocumentFileUploaded",
        apply=apply,
    )
    got = fetch_version(conn, doc_id, version_id)
    assert got is not None  # noqa: S101
    return got


def rescan(
    conn: Connection, ctx: RequestContext, store: ObjectStore, scanner: MalwareScanner, doc_id: uuid.UUID, version_id: uuid.UUID,
    now: dt.datetime | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Run the scanner again over a DRAFT file (for example after a scanner was configured). Still fails closed."""
    moment = now or utc_now()
    doc = fetch_document(conn, doc_id, lock=True)
    version = fetch_version(conn, doc_id, version_id, lock=True)
    if doc is None or version is None:
        raise NotFound()
    if version["state"] != "draft":
        raise StaleVersion(
            "Only a draft file is scanned again.", details={"reason": "version_not_draft"}
        )
    key = conn.execute(
        text("SELECT object_key FROM document_versions WHERE id = :v"), {"v": version_id}
    ).scalar_one()
    if key is None:
        raise StaleVersion("There is no file to scan.", details={"reason": "no_file"})
    try:
        data = store.get(key)
    except StorageError:
        raise DependencyUnavailable(retry_after=30) from None
    result = scanner.scan(data, version["original_filename"] or "")

    def apply(c: Connection) -> MutationResult:
        if result.state == "infected":
            c.execute(
                text(
                    "UPDATE document_versions SET object_key = NULL, sha256 = NULL, size_bytes = NULL, media_type = NULL,"
                    " original_filename = NULL, scan_state = 'infected', scanner = :sc, scanner_simulation = :sim, scanned_at = :now WHERE id = :v"
                ),
                {"sc": result.scanner, "sim": result.simulation, "now": moment, "v": version_id},
            )  # fmt: skip
            store.delete(key)
        else:
            c.execute(
                text("UPDATE document_versions SET scan_state = :ss, scanner = :sc, scanner_simulation = :sim, scanned_at = :now WHERE id = :v"),
                {"ss": result.state, "sc": result.scanner, "sim": result.simulation, "now": moment, "v": version_id},
            )  # fmt: skip
        new_version = _bump_doc(c, doc, {}, moment)
        return MutationResult(
            doc_id, new_version, after={"scan_state": result.state},
            event_payload={"document_id": doc_id, "version_id": version_id, "scan_state": result.state},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="document.rescan",
        object_type="document",
        event_type="DocumentFileScanned",
        apply=apply,
    )
    got = fetch_version(conn, doc_id, version_id)
    assert got is not None  # noqa: S101
    return got


def publish_version(
    conn: Connection, ctx: RequestContext, doc_id: uuid.UUID, version_id: uuid.UUID, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    doc = fetch_document(conn, doc_id, lock=True)
    version = fetch_version(conn, doc_id, version_id, lock=True)
    if doc is None or version is None:
        raise NotFound()
    if version["state"] != "draft":
        raise StaleVersion("This version is not a draft.", details={"reason": "version_not_draft"})
    if version["sha256"] is None or version["media_type"] is None:
        raise PolicyViolation("Upload the file before publishing.", details={"reason": "no_file"})
    if version["scan_state"] != "clean":
        # SEC-03: infected, unscanned or "no scanner configured" are all refused (fail closed)
        raise PolicyViolation(
            "The file has not been scanned clean, so it cannot be published.",
            details={"reason": "scan_not_clean", "scan_state": version["scan_state"]},
        )

    def apply(c: Connection) -> MutationResult:
        if doc["current_version_id"] is not None:
            c.execute(
                text(
                    "UPDATE document_versions SET state = 'superseded' WHERE id = :id AND state = 'published'"
                ),
                {"id": doc["current_version_id"]},
            )
        c.execute(
            text("UPDATE document_versions SET state = 'published', published_by = :by, published_at = :now WHERE id = :id"),
            {"by": ctx.person_id, "now": moment, "id": version_id},
        )  # fmt: skip
        new_version = _bump_doc(c, doc, {"current_version_id": version_id}, moment)
        return MutationResult(
            doc_id, new_version, before={"current_version_id": doc["current_version_id"]}, after={"current_version_id": version_id},
            event_payload={
                "document_id": doc_id, "version_id": version_id, "version_no": version["version_no"], "doc_type": doc["doc_type"],
                "access_level": doc["access_level"], "effective_from": version["effective_from"].isoformat(),
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="document.publish",
        object_type="document",
        event_type="DocumentVersionPublished",
        apply=apply,
    )
    got = fetch_version(conn, doc_id, version_id)
    assert got is not None  # noqa: S101
    return got


def withdraw_version(
    conn: Connection, ctx: RequestContext, doc_id: uuid.UUID, version_id: uuid.UUID, reason: str, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    doc = fetch_document(conn, doc_id, lock=True)
    version = fetch_version(conn, doc_id, version_id, lock=True)
    if doc is None or version is None:
        raise NotFound()
    if version["state"] not in {"published", "superseded"}:
        raise StaleVersion(
            "Only a published version can be withdrawn.",
            details={"reason": "version_not_published"},
        )

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text("UPDATE document_versions SET state = 'withdrawn', withdrawn_at = :now, withdraw_reason = :r WHERE id = :id"),
            {"now": moment, "r": reason, "id": version_id},
        )  # fmt: skip
        changes = {"current_version_id": None} if doc["current_version_id"] == version_id else {}
        new_version = _bump_doc(c, doc, changes, moment)
        return MutationResult(
            doc_id,
            new_version,
            after={"withdrawn_version": version_id},
            event_payload={"document_id": doc_id, "version_id": version_id, "state": "withdrawn"},
        )

    mutation(
        conn,
        ctx,
        operation="document.withdraw",
        object_type="document",
        event_type="DocumentVersionWithdrawn",
        apply=apply,
        reason=reason,
    )
    got = fetch_version(conn, doc_id, version_id)
    assert got is not None  # noqa: S101
    return got


def readable_version(
    conn: Connection, actor: Actor, doc_id: uuid.UUID, version_id: uuid.UUID
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The (document, version) the caller may download RIGHT NOW, else NotFound (never says which check failed)."""
    doc = fetch_document(conn, doc_id)
    version = fetch_version(conn, doc_id, version_id) if doc else None
    if doc is None or version is None or not doc_visible(actor, doc):
        raise NotFound()
    return doc, ensure_downloadable(actor, doc, version)


def ensure_downloadable(
    actor: Actor, doc: dict[str, Any], version: dict[str, Any]
) -> dict[str, Any]:
    if version["state"] in {"published", "superseded"} or (
        version["state"] == "draft" and actor.can_draft
    ):
        pass
    else:
        raise NotFound()
    if version["scan_state"] != "clean" or version["sha256"] is None:
        raise NotFound()
    if not (actor.can_draft or can_read_level(actor.role, doc["access_level"])):
        raise NotFound()
    return version


def audit_access(
    conn: Connection, ctx: RequestContext, operation: str, doc_id: uuid.UUID, version_id: uuid.UUID
) -> None:
    record_audit(
        conn,
        ctx,
        operation=operation,
        object_type="document",
        object_id=doc_id,
        after={"version_id": version_id},
    )
