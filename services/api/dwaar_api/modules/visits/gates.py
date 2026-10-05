"""Gates, lanes, device enrolment (SOC-05 subset) and the gate policy. Every write goes through ``core.audit.mutation``.

REQ: SOC-05 (a device is enrolled by a REQUEST and activated only by a different, authorised person; one society),
GATE-11 (policy), PRD 8.2 (gates, lanes, devices), INV-01 (every query runs under the RLS context of the validated scope; ids
in bodies resolve only inside that society), ARCH-01.

Certificates are slice 3: ``cert_fingerprint`` stays NULL and the enrolment record carries the device's Ed25519 PUBLIC key only.
A device that is not ``active`` can never be named in an observation (see ``visits.observe``).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation, StaleVersion
from dwaar_common.ids import uuid7
from dwaar_common.signing import SigningError, key_id_for, public_key_from_b64

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import policy as policy_mod
from .schemas import (
    DeviceDecision,
    DeviceEnrol,
    DeviceRevoke,
    GateCreate,
    LaneCreate,
    PolicyPut,
)

_DEVICE_COLS = (
    "id, kind, name, gate_id, state, key_id, firmware, capabilities, simulation, last_seen_at,"
    " requested_by, decided_by, decided_at, decision_reason, revoked_at, revoke_reason, version, created_at"
)


# ------------------------------------------------------------------------------------------ views
def gate_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "status": row["status"],
        "version": row["version"],
    }


def lane_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "gate_id": row["gate_id"],
        "label": row["label"],
        "direction": row["direction"],
        "status": row["status"],
        "version": row["version"],
    }


def device_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "gate_id": row["gate_id"],
        "state": row["state"],
        "key_id": row["key_id"],
        "firmware": row["firmware"],
        "capabilities": row["capabilities"],
        "simulation": row["simulation"],
        "last_seen_at": row["last_seen_at"],
        "requested_by": row["requested_by"],
        "decided_by": row["decided_by"],
        "decided_at": row["decided_at"],
        "decision_reason": row["decision_reason"],
        "revoked_at": row["revoked_at"],
        "version": row["version"],
        "created_at": row["created_at"],
    }


# ------------------------------------------------------------------------------------------ gates
def fetch_gate(conn: Connection, gate_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text("SELECT id, name, kind, status, version FROM gates WHERE id = :id"),
            {"id": gate_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def require_active_gate(
    conn: Connection, gate_id: uuid.UUID, *, field: str = "gate_id"
) -> dict[str, Any]:
    gate = fetch_gate(conn, gate_id)
    if gate is None or gate["status"] != "active":
        raise InvalidSchema.for_fields([(field, "unknown_gate")])
    return gate


def list_gates(conn: Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("SELECT id, name, kind, status, version FROM gates ORDER BY lower(name), id")
    ).mappings()
    return [gate_view(r) for r in rows]


def create_gate(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: GateCreate
) -> dict[str, Any]:
    gate_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO gates (id, society_id, name, kind, created_by) VALUES (:id, :s, :n, :k, :by)"
            ),
            {"id": gate_id, "s": society_id, "n": body.name, "k": body.kind, "by": ctx.person_id},
        )
        return MutationResult(
            gate_id,
            1,
            after={"name": body.name, "kind": body.kind, "status": "active"},
            event_payload={"gate_id": gate_id, "kind": body.kind},
        )

    mutation(
        conn,
        ctx,
        operation="gate.create",
        object_type="gate",
        event_type="GateCreated",
        apply=apply,
    )
    gate = fetch_gate(conn, gate_id)
    assert gate is not None  # noqa: S101
    return gate_view(gate)


def create_lane(
    conn: Connection,
    ctx: RequestContext,
    society_id: uuid.UUID,
    gate_id: uuid.UUID,
    body: LaneCreate,
) -> dict[str, Any]:
    gate = fetch_gate(conn, gate_id)
    if gate is None or gate["status"] != "active":
        raise NotFound()
    lane_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO lanes (id, society_id, gate_id, label, direction, created_by)"
                " VALUES (:id, :s, :g, :l, :d, :by)"
            ),
            {
                "id": lane_id,
                "s": society_id,
                "g": gate_id,
                "l": body.label,
                "d": body.direction,
                "by": ctx.person_id,
            },
        )
        return MutationResult(
            lane_id,
            1,
            after={"gate_id": gate_id, "label": body.label, "direction": body.direction},
            event_payload={"lane_id": lane_id, "gate_id": gate_id, "direction": body.direction},
        )

    mutation(
        conn,
        ctx,
        operation="lane.create",
        object_type="lane",
        event_type="LaneCreated",
        apply=apply,
    )
    row = (
        conn.execute(
            text("SELECT id, gate_id, label, direction, status, version FROM lanes WHERE id = :id"),
            {"id": lane_id},
        )
        .mappings()
        .one()
    )
    return lane_view(row)


def list_lanes(conn: Connection, gate_id: uuid.UUID) -> list[dict[str, Any]]:
    if fetch_gate(conn, gate_id) is None:
        raise NotFound()
    rows = conn.execute(
        text(
            "SELECT id, gate_id, label, direction, status, version FROM lanes WHERE gate_id = :g"
            " ORDER BY lower(label), id"
        ),
        {"g": gate_id},
    ).mappings()
    return [lane_view(r) for r in rows]


# ------------------------------------------------------------------------------------------ devices
def fetch_device(conn: Connection, device_id: uuid.UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_DEVICE_COLS} FROM devices WHERE id = :id"),  # noqa: S608 (constant column list)
            {"id": device_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def enrol_device(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: DeviceEnrol
) -> dict[str, Any]:
    """Record an enrolment REQUEST: the device is ``pending_approval`` and unusable until somebody else approves it."""
    try:
        key_id = key_id_for(public_key_from_b64(body.public_key))
    except (SigningError, ValueError):
        raise InvalidSchema.for_fields([("public_key", "invalid_public_key")]) from None
    if body.gate_id is not None:
        require_active_gate(conn, body.gate_id)
    device_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO devices (id, society_id, kind, name, gate_id, public_key, key_id, firmware, capabilities,"
                " simulation, requested_by) VALUES (:id, :s, :k, :n, :g, :pk, :kid, :fw, CAST(:caps AS jsonb), :sim, :by)"
            ),
            {
                "id": device_id,
                "s": society_id,
                "k": body.kind,
                "n": body.name,
                "g": body.gate_id,
                "pk": body.public_key,
                "kid": key_id,
                "fw": body.firmware,
                "caps": policy_mod.json_text(body.capabilities),
                "sim": body.simulation,
                "by": ctx.person_id,
            },
        )
        return MutationResult(
            device_id,
            1,
            after={
                "kind": body.kind,
                "state": "pending_approval",
                "key_id": key_id,
                "gate_id": body.gate_id,
            },
            event_payload={"device_id": device_id, "kind": body.kind, "state": "pending_approval"},
        )

    try:
        mutation(
            conn,
            ctx,
            operation="device.enrol_request",
            object_type="device",
            event_type="DeviceEnrolmentRequested",
            apply=apply,
        )
    except IntegrityError as exc:
        if "devices_society_key_uq" in str(exc.orig):
            raise PolicyViolation(details={"reason": "already_enrolled"}) from None
        raise
    device = fetch_device(conn, device_id)
    assert device is not None  # noqa: S101
    return device_view(device)


def list_devices(conn: Connection, state: str | None) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"SELECT {_DEVICE_COLS} FROM devices"  # noqa: S608 (constant column list)
            " WHERE (CAST(:st AS text) IS NULL OR state = CAST(:st AS text)) ORDER BY created_at DESC, id DESC LIMIT 200"
        ),
        {"st": state},
    ).mappings()
    return [device_view(r) for r in rows]


def decide_device(
    conn: Connection, ctx: RequestContext, device_id: uuid.UUID, body: DeviceDecision
) -> dict[str, Any]:
    """Approve or reject a pending enrolment. Maker != checker: the requester can never decide their own device."""
    device = fetch_device(conn, device_id)
    if device is None:
        raise NotFound()
    if ctx.person_id is not None and device["requested_by"] == ctx.person_id:
        raise PolicyViolation(details={"reason": "maker_checker"})
    if body.decision == "reject" and not (body.reason and len(body.reason.strip()) >= 5):
        raise InvalidSchema.for_fields([("reason", "reason_required")])
    new_state = "active" if body.decision == "approve" else "rejected"

    def apply(c: Connection) -> MutationResult:
        updated = c.execute(
            text(
                "UPDATE devices SET state = :st, decided_by = :by, decided_at = clock_timestamp(),"
                " decision_reason = :why, version = version + 1"
                " WHERE id = :id AND state = 'pending_approval' AND version = :v RETURNING version"
            ),
            {
                "st": new_state,
                "by": ctx.person_id,
                "why": body.reason,
                "id": device_id,
                "v": body.expected_version,
            },
        ).first()
        if updated is None:
            raise StaleVersion(details={"state": device["state"], "version": device["version"]})
        return MutationResult(
            device_id,
            int(updated[0]),
            before={"state": "pending_approval"},
            after={"state": new_state},
            event_payload={"device_id": device_id, "state": new_state},
        )

    mutation(
        conn,
        ctx,
        operation=f"device.{body.decision}",
        object_type="device",
        event_type="DeviceActivated" if new_state == "active" else "DeviceEnrolmentRejected",
        apply=apply,
        reason=body.reason,
        approver_id=ctx.person_id,
    )
    fresh = fetch_device(conn, device_id)
    assert fresh is not None  # noqa: S101
    return device_view(fresh)


def revoke_device(
    conn: Connection, ctx: RequestContext, device_id: uuid.UUID, body: DeviceRevoke
) -> dict[str, Any]:
    device = fetch_device(conn, device_id)
    if device is None:
        raise NotFound()

    def apply(c: Connection) -> MutationResult:
        updated = c.execute(
            text(
                "UPDATE devices SET state = 'revoked', revoked_by = :by, revoked_at = clock_timestamp(),"
                " revoke_reason = :why, version = version + 1"
                " WHERE id = :id AND state = 'active' AND version = :v RETURNING version"
            ),
            {"by": ctx.person_id, "why": body.reason, "id": device_id, "v": body.expected_version},
        ).first()
        if updated is None:
            raise StaleVersion(details={"state": device["state"], "version": device["version"]})
        return MutationResult(
            device_id,
            int(updated[0]),
            before={"state": "active"},
            after={"state": "revoked"},
            event_payload={"device_id": device_id, "state": "revoked"},
        )

    mutation(
        conn,
        ctx,
        operation="device.revoke",
        object_type="device",
        event_type="DeviceRevoked",
        apply=apply,
        reason=body.reason,
    )
    fresh = fetch_device(conn, device_id)
    assert fresh is not None  # noqa: S101
    return device_view(fresh)


# ------------------------------------------------------------------------------------------ policy
def put_policy(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, body: PolicyPut
) -> dict[str, Any]:
    current = policy_mod.load_policy(conn)
    if body.expected_version != current.version:
        raise StaleVersion(details={"version": current.version})
    expiry = body.approval_expiry_seconds
    if expiry is not None:
        policy_mod.validate_expiry(expiry)
    overrides = dict(current.overstay_overrides)
    if body.overstay_minutes is not None:
        policy_mod.validate_overstay(body.overstay_minutes)
        overrides = dict(body.overstay_minutes)
    new_expiry = expiry if expiry is not None else current.approval_expiry_seconds
    new_validity = (
        body.permission_validity_minutes
        if body.permission_validity_minutes is not None
        else current.permission_validity_minutes
    )
    new_override = (
        body.override_validity_minutes
        if body.override_validity_minutes is not None
        else current.override_validity_minutes
    )
    before = {
        "approval_expiry_seconds": current.approval_expiry_seconds,
        "permission_validity_minutes": current.permission_validity_minutes,
        "override_validity_minutes": current.override_validity_minutes,
        "overstay_minutes": dict(current.overstay_overrides),
    }
    after = {
        "approval_expiry_seconds": new_expiry,
        "permission_validity_minutes": new_validity,
        "override_validity_minutes": new_override,
        "overstay_minutes": overrides,
    }

    def apply(c: Connection) -> MutationResult:
        if current.version == 0:
            c.execute(
                text(
                    "INSERT INTO gate_policies (id, society_id, approval_expiry_seconds, permission_validity_minutes,"
                    " override_validity_minutes, overstay_minutes, updated_by)"
                    " VALUES (:id, :s, :e, :p, :o, CAST(:ov AS jsonb), :by)"
                    " ON CONFLICT (society_id) DO NOTHING"
                ),
                {
                    "id": uuid7(),
                    "s": society_id,
                    "e": new_expiry,
                    "p": new_validity,
                    "o": new_override,
                    "ov": policy_mod.json_text(overrides),
                    "by": ctx.person_id,
                },
            )
            row = c.execute(text("SELECT version FROM gate_policies")).first()
            if row is None or int(row[0]) != 1:
                # the counter row appeared concurrently (a revocation): the caller read version 0, so this is stale
                raise StaleVersion()
            return MutationResult(
                society_id, 1, before=before, after=after, event_payload={"version": 1}
            )
        updated = c.execute(
            text(
                "UPDATE gate_policies SET approval_expiry_seconds = :e, permission_validity_minutes = :p,"
                " override_validity_minutes = :o, overstay_minutes = CAST(:ov AS jsonb), updated_by = :by,"
                " version = version + 1 WHERE version = :v RETURNING version"
            ),
            {
                "e": new_expiry,
                "p": new_validity,
                "o": new_override,
                "ov": policy_mod.json_text(overrides),
                "by": ctx.person_id,
                "v": current.version,
            },
        ).first()
        if updated is None:
            raise StaleVersion()
        return MutationResult(
            society_id,
            int(updated[0]),
            before=before,
            after=after,
            event_payload={"version": int(updated[0])},
        )

    mutation(
        conn,
        ctx,
        operation="gate_policy.put",
        object_type="gate_policy",
        event_type="GatePolicyChanged",
        apply=apply,
    )
    return policy_mod.load_policy(conn).as_view()
