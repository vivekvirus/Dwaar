"""Row -> response dictionaries. Decimals leave the API as exact strings (INV-02), never floats.

REQ: SOC-01 (PAN/TAN/GSTIN only masked), SOC-02, PRD 5.2 (guard: masked register read; the guard view carries no
areas, interest or cost, and nothing financial).
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any


def dec(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")


def society_basic(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "city": row["city"],
        "state": row["state"],
        "timezone": row["timezone"],
        "status": row["status"],
        "version": row["version"],
    }


def legal_entity_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """Masked identifiers only. The ciphertext columns are never selected into this view."""
    return {
        "id": row["id"],
        "name": row["name"],
        "entity_type": row["entity_type"],
        "registration_no": row["registration_no"],
        "pan_masked": row["pan_masked"],
        "tan_masked": row["tan_masked"],
        "gstin_masked": row["gstin_masked"],
        "gst_registered": row["gst_registered"],
        "version": row["version"],
    }


def block_view(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "floors": row["floors"],
        "has_lift": row["has_lift"],
        "status": row["status"],
        "version": row["version"],
    }


def unit_view(row: Mapping[str, Any], *, masked: bool = False) -> dict[str, Any]:
    """``masked=True`` is the guard's register view: where a unit is, nothing about its size or cost."""
    base: dict[str, Any] = {
        "id": row["id"],
        "block_id": row["block_id"],
        "block_name": row.get("block_name"),
        "label": row["label"],
        "floor": row["floor"],
        "status": row["status"],
        "version": row["version"],
    }
    if masked:
        return base
    base.update(
        carpet_area_sqft=dec(row["carpet_area_sqft"]),
        builtup_area_sqft=dec(row["builtup_area_sqft"]),
        undivided_interest_pct=dec(row["undivided_interest_pct"]),
        construction_cost_paise=row["construction_cost_paise"],
    )
    return base


def audit_unit(row: Mapping[str, Any]) -> dict[str, Any]:
    """Audit/diff form of a unit row: plain JSON types (decimals as strings)."""
    return {
        "block_id": row["block_id"],
        "label": row["label"],
        "floor": row["floor"],
        "carpet_area_sqft": dec(row["carpet_area_sqft"]),
        "builtup_area_sqft": dec(row["builtup_area_sqft"]),
        "undivided_interest_pct": dec(row["undivided_interest_pct"]),
        "construction_cost_paise": row["construction_cost_paise"],
        "status": row["status"],
    }
