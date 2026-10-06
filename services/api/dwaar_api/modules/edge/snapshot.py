"""Policy manifest builder and publisher: signed, monotonic, content-hashed snapshots for the edge.

REQ: EDGE-04 (signed snapshots: sequence, issue time, validity, issuer key id, data-minimisation manifest), GATE-06 (resident credentials
with status, validity and revocation version), GATE-14 (standing rules per household), GATE-01 (invitation windows, uses, revocation
versions), PRD 9.3 (cloud authoritative for identity, roles, passes and revocations; revocations first), PRD 13 (edge policy publisher:
on change and periodic refresh; signed monotonic version; atomic snapshot; revocations prioritised), PRD 12.4 (PolicyPublished), EDGE-10
(tombstones kept for a retention period), INV-10 (timings come from the approved pack and the society policy, never from code constants),
INV-01 (everything runs under the society RLS context).

A snapshot is produced only when the manifest content changed (SHA-256 of its canonical JSON), when the issuer key rotated, when the last
one is older than the refresh interval, or when forced. ``publish_policy`` is idempotent: call it from a worker, a domain-event hook or an
admin request any number of times.
"""

# ruff: noqa: S608  (SQL fragments are constants; every value is a bind parameter)

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import importlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.events import canonical_json, payload_hash
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import format_iso_utc, start_of_ist_day, utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import Database, RequestContext
from ..visits import policy as gate_policy
from ..visits.common import (
    _EFFECTIVE,  # noqa: PLC2701 (the single definition of "effective membership today")
)
from .config import SCHEMA_VERSION, EdgeConfig
from .staff_shift_input import override_section, staff_section

#: outbox event types after which a snapshot may have changed (PRD 12.4 names plus this codebase's identity/visits events)
POLICY_RELEVANT_EVENTS: Final = frozenset(
    {
        "MembershipVerified", "RoleGranted", "RoleExpired", "InvitationCreated", "InvitationRevoked", "InvitationExpired",
        "DeviceActivated", "DeviceRevoked", "GateCreated", "LaneCreated", "GatePolicyChanged", "StandingRuleCreated",
        "StandingRuleEnded", "identity.membership_changed", "identity.role_granted", "identity.role_revoked",
        "identity.hold_placed", "identity.hold_decided", "identity.reverification_required", "identity.membership_disputed",
        "identity.owner_decision", "identity.verification_case_advanced",
        "StaffEngagementCreated", "StaffEngagementUpdated", "StaffEngagementEnded", "StaffRegistered", "StaffUpdated",
        "SupervisorOverrideGranted", "ShiftEnded",
    }
)  # fmt: skip
_FALLBACK_OFFLINE: Final = {
    "resident_credential_validity_hours": 72,
    "guest_pass_max_hours": 2,
    "clock_uncertainty_disable_auto_approvals_seconds": 60,
    "policy_age_guard_assisted_verification_hours": 72,
}


# ------------------------------------------------------------------------------------------ opaque references
def _ref(key: bytes, prefix: str, parts: tuple[str, ...]) -> str:
    digest = hmac.new(key, ("|".join(parts)).encode(), hashlib.sha256).digest()[:24]
    return prefix + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def credential_ref(
    key: bytes, society_id: uuid.UUID, membership_id: uuid.UUID, generation: int
) -> str:
    return _ref(key, "cr_", ("cred", str(society_id), str(membership_id), str(generation)))


def person_ref(key: bytes, society_id: uuid.UUID, person_id: uuid.UUID) -> str:
    return _ref(key, "pr_", ("person", str(society_id), str(person_id)))


def mask_alias(alias: str | None) -> str | None:
    """``Test Visitor`` -> ``T*** V***``: enough for a guard to confirm, not enough to read a name."""
    if not alias or not alias.strip():
        return None
    return " ".join(w[0].upper() + "***" for w in alias.split() if w)[:60]


# ------------------------------------------------------------------------------------------ timing (from the approved pack)
def offline_defaults(approval_expiry_s: int | None = None) -> dict[str, int]:
    """Offline numbers from the cascade pack (PRD Appendix C). A broken pack falls back to the PRD defaults, never to a looser value."""
    try:
        packs = importlib.import_module("dwaar_packs")
        cfg = packs.cascade_config(
            {"expiry_seconds": approval_expiry_s} if approval_expiry_s else None
        )
        return {
            k: int(v)
            for k, v in cfg.offline.model_dump().items()
            if isinstance(v, int) and not isinstance(v, bool)
        }
    except Exception:
        return dict(_FALLBACK_OFFLINE)


def limits(conn: Connection | None = None) -> tuple[int, int]:
    """``(clock_uncertainty_limit_ms, policy_age_limit_s)`` for the sync side."""
    expiry = gate_policy.load_policy(conn).approval_expiry_seconds if conn is not None else None
    off = {**_FALLBACK_OFFLINE, **offline_defaults(expiry)}
    return (
        off["clock_uncertainty_disable_auto_approvals_seconds"] * 1000,
        off["policy_age_guard_assisted_verification_hours"] * 3600,
    )


def build_timing(conn: Connection) -> dict[str, Any]:
    policy = gate_policy.load_policy(conn)
    off = {**_FALLBACK_OFFLINE, **offline_defaults(policy.approval_expiry_seconds)}
    steps = gate_policy.cascade_plan(policy.approval_expiry_seconds)["steps"]
    return {
        "approval_expiry_s": policy.approval_expiry_seconds,
        "cascade_steps": [
            {"step": s["step"], "at_seconds": s["at_seconds"], "action": s["action"], "guard_options": list(s["guard_options"])}
            for s in steps
        ],
        "guest_offline_max_s": off["guest_pass_max_hours"] * 3600,
        "resident_offline_validity_s": off["resident_credential_validity_hours"] * 3600,
        "clock_uncertainty_limit_ms": off["clock_uncertainty_disable_auto_approvals_seconds"] * 1000,
        "policy_age_limit_s": off["policy_age_guard_assisted_verification_hours"] * 3600,
    }  # fmt: skip


# ------------------------------------------------------------------------------------------ registry of credential references
def _sync_credential_refs(
    conn: Connection,
    cfg: EdgeConfig,
    society_id: uuid.UUID,
    actor: uuid.UUID | None,
    now: dt.datetime,
) -> None:
    """Make ``edge_credential_refs`` mirror the effective memberships: new ref for a new membership or a re-activation, revoke the rest."""
    effective = conn.execute(
        text(  # noqa: S608 (constant SQL fragment)
            f"SELECT m.id, m.person_id FROM memberships m WHERE {_EFFECTIVE} AND m.kind <> 'staff' ORDER BY m.id"
        )
    ).all()
    latest = {
        r[0]: (int(r[1]), str(r[2]))
        for r in conn.execute(
            text(
                "SELECT DISTINCT ON (membership_id) membership_id, generation, state FROM edge_credential_refs"
                " ORDER BY membership_id, generation DESC"
            )
        ).all()
    }
    effective_ids = set()
    for membership_id, person_id in effective:
        effective_ids.add(membership_id)
        current = latest.get(membership_id)
        if current is not None and current[1] == "active":
            continue
        generation = 0 if current is None else current[0] + 1
        conn.execute(
            text(
                "INSERT INTO edge_credential_refs (id, society_id, membership_id, generation, credential_ref, person_ref)"
                " VALUES (:id, :s, :m, :g, :cr, :pr)"
            ),
            {
                "id": uuid7(), "s": society_id, "m": membership_id, "g": generation,
                "cr": credential_ref(cfg.ref_key, society_id, membership_id, generation),
                "pr": person_ref(cfg.ref_key, society_id, person_id),
            },
        )  # fmt: skip
    for membership_id, (generation, state) in sorted(latest.items(), key=lambda kv: str(kv[0])):
        if state == "active" and membership_id not in effective_ids:
            version = gate_policy.next_revocation_version(conn, society_id, actor)
            conn.execute(
                text(
                    "UPDATE edge_credential_refs SET state = 'revoked', revocation_version = :v, revoked_at = :now"
                    " WHERE membership_id = :m AND generation = :g AND state = 'active'"
                ),
                {"v": version, "now": now, "m": membership_id, "g": generation},
            )


# ------------------------------------------------------------------------------------------ manifest
def _iso(value: dt.datetime | None) -> str | None:
    return None if value is None else format_iso_utc(value)


def _day_start(day: dt.date | None) -> str | None:
    return None if day is None else format_iso_utc(start_of_ist_day(day))


def build_manifest(
    conn: Connection, cfg: EdgeConfig, society_id: uuid.UUID, now: dt.datetime
) -> dict[str, Any]:
    """The data-minimised manifest of ONE society (RLS context set). Deterministic: sorted, no clock reads other than ``now`` filters."""
    retention = dt.timedelta(days=cfg.revocation_retention_days)
    horizon = now - retention
    gates = [
        {"id": str(r[0]), "kind": r[1]}
        for r in conn.execute(
            text("SELECT id, kind FROM gates WHERE status = 'active' ORDER BY id")
        )
    ]
    lanes = [
        {"id": str(r[0]), "gate_id": str(r[1]), "direction": r[2]}
        for r in conn.execute(
            text("SELECT id, gate_id, direction FROM lanes WHERE status = 'active' ORDER BY id")
        )
    ]
    devices = [
        {"id": str(r[0]), "kind": r[1], "gate_id": str(r[2]) if r[2] else None, "status": r[3]}
        for r in conn.execute(
            text(
                "SELECT id, kind, gate_id, state FROM devices WHERE state = 'active'"
                " OR (state = 'revoked' AND revoked_at > :h) ORDER BY id"
            ),
            {"h": horizon},
        )
    ]
    revocations: list[dict[str, Any]] = []
    residents: list[dict[str, Any]] = []
    rows = conn.execute(
        text(
            "SELECT r.credential_ref, r.person_ref, m.unit_id, r.state, r.revocation_version, r.revoked_at,"
            " m.effective_from, m.effective_to,"
            " EXISTS (SELECT 1 FROM membership_holds h WHERE h.membership_id = m.id AND h.state IN ('active', 'appealed')) AS held"
            " FROM edge_credential_refs r JOIN memberships m ON m.society_id = r.society_id AND m.id = r.membership_id"
            " ORDER BY r.credential_ref"
        )
    ).mappings()
    for r in rows:
        if r["state"] == "revoked":
            if r["revoked_at"] <= horizon:
                continue  # the tombstone has outlived its retention
            status, version = "revoked", int(r["revocation_version"])
            revocations.append({"ref": r["credential_ref"], "version": version})
        else:
            status, version = ("suspended" if r["held"] else "active"), 0
        residents.append(
            {
                "credential_ref": r["credential_ref"],
                "person_ref": r["person_ref"],
                "unit_id": str(r["unit_id"]),
                "status": status,
                "valid_from": _day_start(r["effective_from"]),
                "valid_until": _day_start(r["effective_to"] + dt.timedelta(days=1)) if r["effective_to"] else None,
                "revocation_version": version,
            }
        )  # fmt: skip
    invitations: list[dict[str, Any]] = []
    windows: dict[uuid.UUID, list[dict[str, str]]] = {}
    for w in conn.execute(
        text(
            "SELECT invitation_id, window_start, window_end FROM invitation_windows ORDER BY invitation_id, seq"
        )
    ):
        windows.setdefault(w[0], []).append(
            {"start": format_iso_utc(w[1]), "end": format_iso_utc(w[2])}
        )
    for i in conn.execute(
        text(
            "SELECT id, gate_id, window_start, window_end, max_uses, uses, token_nonce, kind, visitor_alias, revoked_version,"
            " state, revoked_at FROM invitations WHERE (state = 'active' AND window_end > :now AND uses < max_uses)"
            " OR (state = 'revoked' AND revoked_at > :h) ORDER BY id"
        ),
        {"now": now, "h": horizon},
    ).mappings():
        revoked = i["state"] == "revoked"
        entry: dict[str, Any] = {
            "id": str(i["id"]),
            "gate_id": str(i["gate_id"]) if i["gate_id"] else None,
            "window_start": format_iso_utc(i["window_start"]),
            "window_end": format_iso_utc(i["window_end"]),
            "windows": windows.get(i["id"], []),
            "max_uses": int(i["max_uses"]),
            "uses_remaining": 0 if revoked else int(i["max_uses"]) - int(i["uses"]),
            "revoked_version": int(i["revoked_version"]),
            "nonce": i["token_nonce"],
            "kind": i["kind"],
        }
        alias = mask_alias(i["visitor_alias"])
        if alias:
            entry["visitor_alias"] = alias
        invitations.append(entry)
        if revoked:
            revocations.append({"ref": str(i["id"]), "version": int(i["revoked_version"])})
    standing = [
        {
            "unit_id": str(r["unit_id"]),
            "rule_kind": r["rule_kind"],
            "params": r["params"],
            "effective_from": r["effective_from"].isoformat(),
            "effective_to": r["effective_to"].isoformat() if r["effective_to"] else None,
        }
        for r in conn.execute(
            text(
                "SELECT id, unit_id, rule_kind, params, effective_from, effective_to FROM standing_rules"
                " WHERE state = 'active' AND (effective_to IS NULL OR effective_to >= CAST(:today AS date)) ORDER BY unit_id, id"
            ),
            {"today": (now.astimezone(dt.timezone(dt.timedelta(hours=5, minutes=30)))).date()},
        ).mappings()
    ]
    revocations.sort(
        key=lambda r: (-int(r["version"]), str(r["ref"]))
    )  # newest deny first (EDGE-04)
    return {
        "gates": gates,
        "lanes": lanes,
        "devices": devices,
        "residents": residents,
        "invitations": invitations,
        "standing_rules": standing,
        "timing": build_timing(conn),
        "revocations": revocations,
        # slice 4 (AT-12, Appendix C): engagements with valid hours, and the supervisor overrides in force (see staff_shift_input)
        "staff": staff_section(conn, now, cfg.revocation_retention_days),
        "overrides": override_section(conn, [g["id"] for g in gates], now),
    }


# ------------------------------------------------------------------------------------------ snapshots
@dataclass(frozen=True)
class PublishResult:
    seq: int
    changed: bool
    reason: str  # initial | changed | refresh | key_rotation | forced | unchanged
    snapshot_id: uuid.UUID
    content_hash: str
    issued_at: dt.datetime
    valid_until: dt.datetime
    issuer_key_id: str


def snapshot_document(row: Mapping[str, Any]) -> dict[str, Any]:
    """The wire snapshot of a stored row: exactly what was signed, plus the signature."""
    return {
        "schema_version": int(row["schema_version"]),
        "society_id": str(row["society_id"]),
        "seq": int(row["seq"]),
        "issued_at": format_iso_utc(row["issued_at"]),
        "valid_until": format_iso_utc(row["valid_until"]),
        "issuer_key_id": row["issuer_key_id"],
        "manifest": row["manifest"],
        "signature": row["signature"],
    }


def _latest(conn: Connection) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(
                "SELECT id, society_id, seq, schema_version, issued_at, valid_until, issuer_key_id, content_hash, reason,"
                " manifest, signature FROM policy_snapshots ORDER BY seq DESC LIMIT 1"
            )
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def latest_snapshot(conn: Connection) -> dict[str, Any] | None:
    return _latest(conn)


def publish_policy(
    conn: Connection,
    ctx: RequestContext,
    cfg: EdgeConfig,
    *,
    now: dt.datetime | None = None,
    force: bool = False,
) -> PublishResult:
    """Publish the society's policy if (and only if) something changed. Idempotent; safe under concurrency (advisory lock per society).

    Registry changes (new or revoked credential references) happen in the same transaction as the snapshot: both commit or neither.
    """
    society_id = ctx.society_id
    assert society_id is not None  # noqa: S101
    base = now or utc_now()
    moment = base.replace(microsecond=(base.microsecond // 1000) * 1000)
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"edge-policy:{society_id}"},
    )
    _sync_credential_refs(conn, cfg, society_id, ctx.person_id, moment)
    manifest = build_manifest(conn, cfg, society_id, moment)
    content_hash = payload_hash(manifest)
    last = _latest(conn)
    timing = manifest["timing"]
    reason: str | None
    if last is None:
        reason = "initial"
    elif force:
        reason = "forced"
    elif last["content_hash"] != content_hash:
        reason = "changed"
    elif last["issuer_key_id"] != cfg.signer.key_id:
        reason = "key_rotation"
    elif (
        moment - last["issued_at"] >= dt.timedelta(seconds=cfg.refresh_interval_s)
        or moment >= last["valid_until"]
    ):
        reason = "refresh"
    else:
        reason = None
    if reason is None:
        assert last is not None  # noqa: S101
        return PublishResult(
            int(last["seq"]), False, "unchanged", last["id"], last["content_hash"], last["issued_at"],
            last["valid_until"], last["issuer_key_id"],
        )  # fmt: skip
    seq = 1 if last is None else int(last["seq"]) + 1
    valid_until = moment + dt.timedelta(seconds=int(timing["policy_age_limit_s"]))
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "society_id": str(society_id),
        "seq": seq,
        "issued_at": format_iso_utc(moment),
        "valid_until": format_iso_utc(valid_until),
        "issuer_key_id": cfg.signer.key_id,
        "manifest": manifest,
    }
    signature = cfg.signer.sign(canonical_json(unsigned))
    snapshot_id = uuid7()
    counts = {
        k: len(manifest[k])
        for k in (
            "gates",
            "lanes",
            "devices",
            "residents",
            "invitations",
            "standing_rules",
            "revocations",
            "overrides",
        )
    }
    counts["staff_entries"] = len(manifest["staff"]["entries"])
    counts["staff_ended"] = len(manifest["staff"]["ended"])

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO policy_snapshots (id, society_id, seq, schema_version, issued_at, valid_until, issuer_key_id,"
                " content_hash, reason, manifest, signature) VALUES (:id, :s, :seq, :sv, :iat, :vu, :kid, :h, :why,"
                " CAST(:m AS jsonb), :sig)"
            ),
            {
                "id": snapshot_id, "s": society_id, "seq": seq, "sv": SCHEMA_VERSION, "iat": moment, "vu": valid_until,
                "kid": cfg.signer.key_id, "h": content_hash, "why": reason,
                "m": canonical_json(manifest).decode("utf-8"), "sig": signature,
            },
        )  # fmt: skip
        return MutationResult(
            snapshot_id, min(seq, 2**31 - 1),
            after={"seq": seq, "reason": reason, "issuer_key_id": cfg.signer.key_id, "counts": counts},
            event_payload={
                "snapshot_id": snapshot_id, "seq": seq, "reason": reason, "manifest_digest": content_hash,
                "valid_until": valid_until, "issuer_key_id": cfg.signer.key_id, "counts": counts,
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="edge.policy_publish", object_type="policy_snapshot", event_type="PolicyPublished",
        apply=apply, reason=f"policy snapshot {seq}: {reason}",
    )  # fmt: skip
    return PublishResult(
        seq, True, reason, snapshot_id, content_hash, moment, valid_until, cfg.signer.key_id
    )


def handle_domain_event(
    conn: Connection,
    ctx: RequestContext,
    cfg: EdgeConfig,
    event_type: str,
    *,
    now: dt.datetime | None = None,
) -> PublishResult | None:
    """Worker hook: ``None`` for an event that cannot change a snapshot, else :func:`publish_policy` (idempotent, deduplicated by content hash)."""
    if event_type not in POLICY_RELEVANT_EVENTS:
        return None
    return publish_policy(conn, ctx, cfg, now=now)


def publish_for_society(
    db: Database,
    cfg: EdgeConfig,
    society_id: uuid.UUID,
    *,
    now: dt.datetime | None = None,
    force: bool = False,
) -> PublishResult:
    """Periodic refresh entry point for the worker: one society, own transaction, system actor."""
    ctx = RequestContext(society_id, None, "system", uuid7())
    with db.app_tx(ctx) as conn:
        return publish_policy(conn, ctx, cfg, now=now, force=force)
