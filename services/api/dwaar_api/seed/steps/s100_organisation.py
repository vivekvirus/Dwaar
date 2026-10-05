"""Organisation: the two societies, their legal entities, blocks and units (SOC-01, SOC-02, SOC-03).

Done as the platform operator would onboard a society (role ``platform_admin``, out of band: platform roles are not
self-service, IAM-13), through ``organisation.service.create_society`` / ``create_block`` and the CSV import
(``imports.run_import``), so every row has its audit row and outbox event. No PAN/TAN/GSTIN is invented.
"""

from __future__ import annotations

import csv
import io
from decimal import Decimal

from sqlalchemy import text

from ...modules.organisation import imports, service
from ...modules.organisation.schemas import BlockCreate, LegalEntityIn, SocietyCreate
from ..dataset import SOCIETIES, SocietySpec
from ..runtime import SeedContext

NAME = "organisation"
ORDER = 100
ROLE = "platform_admin"


def unit_csv(spec: SocietySpec) -> bytes:
    """Deterministic areas and costs (decimals as strings, money as integer paise: INV-02)."""
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            "block",
            "label",
            "floor",
            "carpet_area_sqft",
            "builtup_area_sqft",
            "undivided_interest_pct",
            "construction_cost_paise",
        ]
    )
    for block in spec.blocks:
        for floor, label in block.labels():
            k = int(label[-2:])
            carpet = Decimal(600 + (floor % 3) * 50 + (k % 5) * 25)
            builtup = (carpet * Decimal("1.2")).quantize(Decimal("0.01"))
            cost = int(builtup * 5000 * 100)  # Rs 5,000 per sq ft, in paise
            writer.writerow(
                [
                    block.name,
                    label,
                    floor,
                    f"{carpet:.2f}",
                    f"{builtup:.2f}",
                    spec.interest_pct,
                    cost,
                ]
            )
    return out.getvalue().encode()


def _pack_ids(ctx: SeedContext, spec: SocietySpec) -> tuple[object, object]:
    with ctx.tx(f"lookup:packs:{spec.key}") as (conn, _c):
        legal = conn.execute(
            text(
                "SELECT id FROM legal_pack_catalog WHERE pack_key = :k ORDER BY effective_from DESC LIMIT 1"
            ),
            {"k": spec.legal_pack_key},
        ).scalar_one()
        tax = conn.execute(
            text(
                "SELECT id FROM tax_pack_catalog WHERE pack_key = :k ORDER BY effective_from DESC LIMIT 1"
            ),
            {"k": spec.tax_pack_key},
        ).scalar_one()
    return legal, tax


def run(ctx: SeedContext) -> None:
    operator = ctx.person("operator")
    for spec in SOCIETIES:
        sid = ctx.society_id(spec.key)
        with ctx.tx(f"exists:{spec.key}", society=sid, role="seed") as (conn, _c):
            exists = conn.execute(
                text("SELECT EXISTS (SELECT 1 FROM societies WHERE id = :i)"), {"i": sid}
            ).scalar_one()
        if exists:
            ctx.count("societies_existing")
        else:
            legal, tax = _pack_ids(ctx, spec)
            body = SocietyCreate.model_validate(
                {
                    "name": spec.name,
                    "legal_entity": LegalEntityIn(
                        name=spec.legal_name,
                        entity_type=spec.entity_type,
                        registration_no=spec.registration_no,
                    ),
                    "legal_pack_id": legal,
                    "tax_pack_id": tax,
                    "city": spec.city,
                    "state": spec.state,
                }
            )
            with ctx.tx(f"society-create:{spec.key}", society=sid, person=operator, role=ROLE) as (
                conn,
                rctx,
            ):
                service.create_society(conn, rctx, sid, body, ctx.cipher)
            ctx.count("societies_created")
            ctx.say(f"  society {spec.key}: created {spec.name}")
        _blocks_and_units(ctx, spec, sid, operator)
    ctx.forget_societies()


def _blocks_and_units(ctx: SeedContext, spec: SocietySpec, sid, operator) -> None:  # type: ignore[no-untyped-def]
    with ctx.tx(f"blocks-read:{spec.key}", society=sid, role="seed") as (conn, _c):
        have = {r[0] for r in conn.execute(text("SELECT name FROM blocks"))}
        units = conn.execute(text("SELECT count(*) FROM units")).scalar_one()
    for block in spec.blocks:
        if block.name in have:
            continue
        with ctx.tx(f"block:{spec.key}:{block.name}", society=sid, person=operator, role=ROLE) as (
            conn,
            rctx,
        ):
            service.create_block(
                conn,
                rctx,
                sid,
                BlockCreate(name=block.name, floors=block.floors, has_lift=block.has_lift),
            )
        ctx.count("blocks_created")
    if units:
        ctx.count("unit_batches_existing")
        return
    with ctx.tx(f"units:{spec.key}", society=sid, person=operator, role=ROLE) as (conn, rctx):
        result = imports.run_import(
            conn, rctx, sid, unit_csv(spec), dry_run=False, create_missing_blocks=False
        )
    ctx.count("units_created", int(result["created"]) if "created" in result else spec.unit_count)
    ctx.say(f"  society {spec.key}: {spec.unit_count} units in {len(spec.blocks)} blocks")
