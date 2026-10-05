"""Load the shipped legal and tax packs into the global ``legal_packs`` / ``tax_packs`` tables.

REQ: INV-10 (law is configuration: rows come from the versioned pack files, nothing is hard-coded here),
GOV-01 / D-24 (approval is evidence: a file that merely CLAIMS approval is stored as unapproved, ADR-0007 #9),
SOC-01 (legal pack and tax pack selection).

Run as the migration/owner role (``make seed`` / deployment step); the API role has no privileges on these tables.
Re-running is safe: an unchanged pack is left alone, a changed unapproved pack is updated in place, and a changed
pack whose stored row is already approved is refused (approved content is immutable: ship a new pack version).
``dwaar_packs`` is imported lazily so the API process does not need the packs package to serve requests.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text


class PackLoadError(Exception):
    """A stored approved pack would be altered, or a pack file is unusable."""


@dataclass(frozen=True)
class LoadReport:
    legal_inserted: int
    legal_updated: int
    legal_unchanged: int
    tax_inserted: int
    tax_updated: int
    tax_unchanged: int


def _jsonb(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)


def load_packs(conn: Connection, *, repository: Any | None = None) -> LoadReport:
    """Upsert every shipped legal and tax pack. ``repository`` defaults to ``dwaar_packs.FilePackRepository``."""
    packs_mod = importlib.import_module("dwaar_packs")
    repo = repository if repository is not None else packs_mod.FilePackRepository()
    legal_type = packs_mod.LegalPack
    counts = {"legal": [0, 0, 0], "tax": [0, 0, 0]}
    for pack in repo.list_packs():
        if isinstance(pack, legal_type):
            _upsert_legal(conn, pack, packs_mod.pack_content_hash(pack), counts["legal"])
        elif getattr(pack, "pack_type", None) in {"tds", "gst-rwa", "gst-einvoice", "fee-schedule"}:
            _upsert_tax(conn, pack, packs_mod.pack_content_hash(pack), counts["tax"])
    return LoadReport(*counts["legal"], *counts["tax"])


def _status_conflict(existing_status: str, existing_hash: str, new_hash: str, key: str) -> bool:
    """True when the stored row is approved and the incoming content differs (refuse), False when it may change."""
    if existing_hash == new_hash:
        return False
    if existing_status == "approved":
        raise PackLoadError(
            f"pack {key} is approved; its content is immutable (publish a new version)"
        )
    return True


def _upsert_legal(conn: Connection, pack: Any, content_hash: str, tally: list[int]) -> None:
    row = pack.to_db_row()
    existing = (
        conn.execute(
            text(
                "SELECT id, pack_status, content_hash FROM legal_packs"
                " WHERE pack_key = :key AND version = :version"
            ),
            {"key": pack.pack_id, "version": pack.version},
        )
        .mappings()
        .first()
    )
    params = {
        "key": pack.pack_id,
        "jurisdiction": row["jurisdiction"],
        "entity_type": row["entity_type"],
        "version": row["version"],
        "title": pack.title,
        "pack_status": pack.status,
        "enabled": pack.enabled,
        "rules": _jsonb(row["rules"]),
        "sources": _jsonb(row["legal_sources"]),
        "hash": content_hash,
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
        "effective_from": row["effective_from"],
        "effective_to": row["effective_to"],
    }
    if existing is None:
        conn.execute(
            text(
                "INSERT INTO legal_packs (pack_key, jurisdiction, entity_type, version, title, pack_status,"
                " enabled, rules, legal_sources, content_hash, approved_by, approved_at, effective_from,"
                " effective_to) VALUES (:key, :jurisdiction, :entity_type, :version, :title, :pack_status,"
                " :enabled, CAST(:rules AS jsonb), CAST(:sources AS jsonb), :hash, :approved_by,"
                " :approved_at, :effective_from, :effective_to)"
            ),
            params,
        )
        tally[0] += 1
        return
    if not _status_conflict(
        existing["pack_status"], existing["content_hash"], content_hash, pack.pack_id
    ):
        tally[2] += 1
        return
    conn.execute(
        text(
            "UPDATE legal_packs SET jurisdiction = :jurisdiction, entity_type = :entity_type, title = :title,"
            " pack_status = :pack_status, enabled = :enabled, rules = CAST(:rules AS jsonb),"
            " legal_sources = CAST(:sources AS jsonb), content_hash = :hash, approved_by = :approved_by,"
            " approved_at = :approved_at, effective_from = :effective_from, effective_to = :effective_to,"
            " version_no = version_no + 1 WHERE pack_key = :key AND version = :version"
        ),
        params,
    )
    tally[1] += 1


def _upsert_tax(conn: Connection, pack: Any, content_hash: str, tally: list[int]) -> None:
    existing = (
        conn.execute(
            text(
                "SELECT id, pack_status, content_hash FROM tax_packs"
                " WHERE pack_key = :key AND version = :version"
            ),
            {"key": pack.pack_id, "version": pack.version},
        )
        .mappings()
        .first()
    )
    params = {
        "key": pack.pack_id,
        "type": pack.pack_type,
        "version": pack.version,
        "title": pack.title,
        "pack_status": pack.status,
        "enabled": pack.enabled,
        "content": _jsonb(pack.model_dump(mode="json")),
        "hash": content_hash,
        "approved_by": pack.approved_by,
        "approved_at": pack.approved_at,
        "effective_from": pack.effective_from,
        "effective_to": pack.effective_to,
    }
    if existing is None:
        conn.execute(
            text(
                "INSERT INTO tax_packs (pack_key, pack_type, version, title, pack_status, enabled, content,"
                " content_hash, approved_by, approved_at, effective_from, effective_to)"
                " VALUES (:key, :type, :version, :title, :pack_status, :enabled, CAST(:content AS jsonb),"
                " :hash, :approved_by, :approved_at, :effective_from, :effective_to)"
            ),
            params,
        )
        tally[0] += 1
        return
    if not _status_conflict(
        existing["pack_status"], existing["content_hash"], content_hash, pack.pack_id
    ):
        tally[2] += 1
        return
    conn.execute(
        text(
            "UPDATE tax_packs SET pack_type = :type, title = :title, pack_status = :pack_status,"
            " enabled = :enabled, content = CAST(:content AS jsonb), content_hash = :hash,"
            " approved_by = :approved_by, approved_at = :approved_at, effective_from = :effective_from,"
            " effective_to = :effective_to, version_no = version_no + 1"
            " WHERE pack_key = :key AND version = :version"
        ),
        params,
    )
    tally[1] += 1
