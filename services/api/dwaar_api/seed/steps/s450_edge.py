"""Edge: a gateway device with a deterministic LOCAL-ONLY key, two standing rules and the first signed policy snapshot (default ON).

REQ: EDGE-04 (signed snapshot), EDGE-09 (per-device key), GATE-14 (standing rules), SOC-05 (device enrolled by a guard, approved by the
supervisor), BUILD_BRIEF 7 (simulators are labelled; keys derived from public labels are worth nothing and local only).

DEFAULT ON (slice 3 integration, ADR-0019): runs unless ``DWAAR_SEED_EDGE`` is ``0``/``false``/``no``/``off``. The gateway is a SOCIETY gateway:
it is enrolled WITHOUT a gate binding, because a gate-bound device may only report for its own gate and the seeded societies have more than one
gate (a bound gateway would see every other gate's events quarantined as ``device_wrong_gate``).

The gateway of society ``mh`` is named ``Main gate edge gateway`` and its Ed25519 seed is ``sha256(b"dwaar-local-edge-device|mh:Main gate
edge gateway")`` (docs/contracts/edge-sync.md section 8; ``python -m dwaar_api.modules.edge.localdev`` prints everything the edge needs).
"""

from __future__ import annotations

import os
import uuid
from typing import Any

from sqlalchemy import text

from ...modules.edge import localkeys
from ...modules.edge.config import EdgeConfig
from ...modules.edge.localdev import seed_device_id
from ...modules.edge.snapshot import publish_policy
from ...modules.edge.standing_rules import StandingRuleCreate, create_rule
from ...modules.visits import gates
from ...modules.visits.schemas import DeviceDecision, DeviceEnrol
from ..runtime import SeedContext, SocietyRef
from . import s400_visits

NAME = "edge"
ORDER = 450

_GATEWAY_NAMES = {"mh": localkeys.SEED_DEVICE_NAME, "ka": "Tower gate edge gateway"}


def enabled() -> bool:
    return os.environ.get("DWAAR_SEED_EDGE", "").strip().lower() not in {"0", "false", "no", "off"}


def _ensure_gateway(
    ctx: SeedContext, plan: s400_visits.SocietyPlan, soc: SocietyRef
) -> uuid.UUID | None:
    name = _GATEWAY_NAMES.get(plan.society)
    if name is None:
        return None
    gate_name = plan.gates[0].name
    with ctx.tx(f"edge:gate-read:{plan.society}", society=soc.id, role="seed") as (conn, _c):
        gate = conn.execute(
            text("SELECT id FROM gates WHERE lower(name) = lower(:n)"), {"n": gate_name}
        ).first()
    if gate is None:
        return None
    label = f"{plan.society}:{name}"
    key = localkeys.device_public_key_b64(label)
    with ctx.tx(f"edge:device-read:{plan.society}", society=soc.id, role="seed") as (conn, _c):
        dev: Any = conn.execute(
            text("SELECT id, state, version FROM devices WHERE public_key = :k"), {"k": key}
        ).first()
    guard, supervisor = ctx.person(plan.guard), ctx.person(plan.supervisor)
    if dev is None:
        scope = f"edge:device:{plan.society}:{name}"
        with ctx.tx(scope, society=soc.id, person=guard, role="guard") as (conn, rctx):
            created = gates.enrol_device(
                conn, rctx, soc.id,
                DeviceEnrol(kind="gateway", name=name, gate_id=None, public_key=key, firmware="edge-sim-0.1",
                            capabilities={"edge": True, "simulation": True}, simulation=True),
            )  # fmt: skip
        device_id = uuid.UUID(str(created["id"]))
        assert device_id == seed_device_id(scope)  # noqa: S101 (documented derivation, see localdev)
        state, version = "pending_approval", 1
        ctx.count("devices_enrolled")
    else:
        device_id, state, version = dev[0], dev[1], dev[2]
    if state == "pending_approval":
        with ctx.tx(
            f"edge:device-approve:{plan.society}",
            society=soc.id,
            person=supervisor,
            role="guard_sup",
        ) as (conn, rctx):
            gates.decide_device(
                conn, rctx, device_id, DeviceDecision(decision="approve", expected_version=version)
            )
        ctx.count("device_approvals_created")
    return device_id


def _ensure_rules(ctx: SeedContext, plan: s400_visits.SocietyPlan, soc: SocietyRef) -> None:
    if plan.society != "mh":
        return
    unit = soc.unit("A", "203")
    owner = ctx.person("ganesh")
    wanted = (
        StandingRuleCreate(unit_id=unit, rule_kind="allow_window", visit_kind="vendor", category="milk", start_local="06:00", end_local="07:00"),
        StandingRuleCreate(unit_id=unit, rule_kind="leave_at_gate", visit_kind="delivery", category="food", start_local="22:00", end_local="06:00"),
    )  # fmt: skip
    for body in wanted:
        with ctx.tx(f"edge:rule-read:{body.rule_kind}", society=soc.id, role="seed") as (conn, _c):
            have = conn.execute(
                text(
                    "SELECT 1 FROM standing_rules WHERE unit_id = :u AND rule_kind = :k AND state = 'active'"
                ),
                {"u": unit, "k": body.rule_kind},
            ).first()
        if have is not None:
            continue
        with ctx.tx(
            f"edge:rule:{body.rule_kind}", society=soc.id, person=owner, role="owner_occ"
        ) as (conn, rctx):
            create_rule(conn, rctx, soc.id, body)
        ctx.count("standing_rules_created")


def run(ctx: SeedContext) -> None:
    if not enabled():
        ctx.say(
            "      (edge seed disabled by DWAAR_SEED_EDGE: no gateway device, standing rules or policy snapshot)"
        )
        return
    cfg = EdgeConfig.from_environment(ctx.settings)
    for plan in s400_visits.PLANS:
        soc = ctx.society(plan.society)
        if _ensure_gateway(ctx, plan, soc) is None:
            continue
        _ensure_rules(ctx, plan, soc)
        with ctx.tx(f"edge:publish:{plan.society}", society=soc.id, role="system") as (conn, rctx):
            result = publish_policy(conn, rctx, cfg)
        if result.changed:
            ctx.count("policy_snapshots_created")
