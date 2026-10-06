"""Parcels: pre-approval, receipt, storage, consent, single-use pickup, refusal/return/loss, courier claims, custody reports.

REQ: PAR-01 (brand + window pre-approval; an order screenshot is refused), PAR-02 (state machine, record of the receipt), PAR-03 (consent
explicit and revocable before custody; single-use token or SUPERVISED alternate proof; family pickup needs delegated authority), PAR-04
(courier claims live in their own table and never move custody; a gate entry is never a delivery), PAR-05 (custody report),
PAR-08, INV-07 (received / stored / collected are distinct), INV-01 (RLS context + unit coverage), DB-02, PRD 12.4.

State machine (enforced by SELECT ... FOR UPDATE on the parcel row, then a guarded UPDATE)::

    expected --receive--> received_at_gate --store--> stored --issue token--> pickup_pending --collect--> collected
        \\--cancel--> cancelled          \\------------- refuse -> refused --return--> returned ------------/
    (received_at_gate | stored | pickup_pending | refused) --declare lost--> lost_exception

Custody is a CHAIN of ``custody_transfers`` (append-only). The parcel row carries its head (``custodian``, ``custody_seq``), moved in the
SAME transaction. A second pickup of a collected parcel is DENIED and the denial is recorded (``parcel_pickup_attempts``) in its own
transaction so it survives the rollback of the denied request: the custody history is never touched (AT-13).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_common.errors import (
    AlreadyDecided,
    DwaarError,
    InvalidSchema,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    StaleVersion,
)
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import Scope
from ...core.db import RequestContext
from ...core.pagination import PageParams, Paginator, SortColumn
from ..visits import common as visits_common
from ..visits import gates
from .config import DEFAULT_CONFIG, ParcelsConfig
from .schemas import (
    CourierClaim,
    CustodyReportCreate,
    ExpectationCreate,
    ParcelCollect,
    ParcelReceive,
    ParcelResolve,
    ParcelStore,
)

#: states in which the society physically holds the parcel (the custody list of PAR-05)
IN_CUSTODY: Final = ("received_at_gate", "stored", "pickup_pending", "refused")
OPEN_STATES: Final = ("expected", *IN_CUSTODY)
COLLECTABLE: Final = ("received_at_gate", "stored", "pickup_pending")
#: proof kinds a supervisor may rely on without a token. A screenshot of an order page is NOT among them (PAR-08).
ALTERNATE_PROOF_KINDS: Final = frozenset(
    {"photo_id_checked", "supervisor_vouched", "household_confirmed_by_call"}
)
_SCREENSHOT_WORDS: Final = (
    "screenshot",
    "screen_shot",
    "order_page",
    "order_image",
    "image_of_order",
)


def _hash_token(token: str) -> str:
    """The token is 192 bits of randomness: a plain SHA-256 is enough (nothing to brute-force); only the hash is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def guard_party(person_id: uuid.UUID | None) -> str:
    return f"guard:{person_id}" if person_id else "guard"


@dataclass
class PickupDenied(Exception):  # noqa: N818 (domain signal, converted to an HTTP error by the route)
    """A pickup was refused. The route records the attempt in its own transaction and re-raises ``error``."""

    parcel_id: uuid.UUID
    reason: str
    method: str
    error: DwaarError


# ------------------------------------------------------------------------------------------ reading
_PARCEL_COLS: Final = (
    "p.id, p.unit_id, p.brand, p.carrier, p.carrier_ref, p.state, p.expected_from, p.expected_until, p.expected_by,"
    " p.matched_expectation, p.gate_id, p.received_at, p.received_by, p.bin_code, p.stored_at, p.photo_ref,"
    " p.leave_at_gate_consent_at, p.leave_at_gate_revoked_at, p.left_at_gate, p.pickup_token_hash IS NOT NULL AS token_live,"
    " p.pickup_token_issued_at, p.pickup_token_expires_at, p.pickup_pending_at, p.collected_at, p.collected_by_kind,"
    " p.collected_via, p.resolved_at, p.resolution_note, p.custody_seq, p.custodian, p.version, p.created_at,"
    " u.label AS unit_label, b.name AS block_name"
)
_PARCEL_FROM: Final = (
    " FROM parcels p JOIN units u ON u.society_id = p.society_id AND u.id = p.unit_id"
    " JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
)


def _locked(conn: Connection, parcel_id: uuid.UUID) -> dict[str, Any]:
    row = (
        conn.execute(text("SELECT * FROM parcels WHERE id = :id FOR UPDATE"), {"id": parcel_id})
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return dict(row)


def _custody_of(
    conn: Connection, ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT parcel_id, seq, from_party, to_party, at, reason, evidence_ref, actor_id FROM custody_transfers"
            " WHERE parcel_id = ANY(:ids) ORDER BY parcel_id, seq"
        ),
        {"ids": list(ids)},
    ).mappings()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["parcel_id"], []).append(
            {
                k: r[k]
                for k in (
                    "seq",
                    "from_party",
                    "to_party",
                    "at",
                    "reason",
                    "evidence_ref",
                    "actor_id",
                )
            }
        )
    return out


def _claims_of(conn: Connection, ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT parcel_id, id, source, claim, claimed_at, external_ref, external, recorded_at FROM courier_observations"
            " WHERE parcel_id = ANY(:ids) ORDER BY parcel_id, claimed_at, id"
        ),
        {"ids": list(ids)},
    ).mappings()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["parcel_id"], []).append(
            {
                k: r[k]
                for k in (
                    "id",
                    "source",
                    "claim",
                    "claimed_at",
                    "external_ref",
                    "external",
                    "recorded_at",
                )
            }
        )
    return out


def _attempts_of(
    conn: Connection, ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT parcel_id, outcome, reason, method, at FROM parcel_pickup_attempts"
            " WHERE parcel_id = ANY(:ids) ORDER BY parcel_id, at, id"
        ),
        {"ids": list(ids)},
    ).mappings()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["parcel_id"], []).append(
            {k: r[k] for k in ("outcome", "reason", "method", "at")}
        )
    return out


def parcel_view(
    row: Mapping[Any, Any],
    *,
    audience: str,
    custody: Sequence[Mapping[Any, Any]] = (),
    claims: Sequence[Mapping[Any, Any]] = (),
    attempts: Sequence[Mapping[Any, Any]] = (),
) -> dict[str, Any]:
    """One parcel for one audience (``guard``: no resident identity, no token detail; ``household`` / ``full``: the whole record).

    PAR-04: ``in_society_custody`` is what the SOCIETY holds; ``courier_claims`` are what a courier SAYS (always labelled
    ``external``); the two are never merged, and a visit of kind delivery is not a parcel receipt.
    """
    consent_active = (
        row["leave_at_gate_consent_at"] is not None and row["leave_at_gate_revoked_at"] is None
    )
    view: dict[str, Any] = {
        "id": row["id"],
        "unit_id": row["unit_id"],
        "block_name": row["block_name"],
        "unit_label": row["unit_label"],
        "brand": row["brand"],
        "carrier": row["carrier"],
        "carrier_ref": row["carrier_ref"],
        "state": row["state"],
        "expectation": {
            "from": row["expected_from"],
            "until": row["expected_until"],
            "matched": row["matched_expectation"],
        },
        "gate_id": row["gate_id"],
        "received_at": row["received_at"],
        "bin_code": row["bin_code"],
        "stored_at": row["stored_at"],
        "photo_ref": row["photo_ref"],
        "leave_at_gate": {
            "consent_active": consent_active,
            "consent_at": row["leave_at_gate_consent_at"],
            "revoked_at": row["leave_at_gate_revoked_at"],
            "left_at_gate": row["left_at_gate"],
        },
        "pickup": {
            "token_live": bool(row["token_live"]),
            "token_expires_at": row["pickup_token_expires_at"],
            "pending_at": row["pickup_pending_at"],
        },
        "collected": {
            "at": row["collected_at"],
            "by_kind": row["collected_by_kind"],
            "via": row["collected_via"],
        },
        "resolved_at": row["resolved_at"],
        "resolution_note": row["resolution_note"],
        "custodian": row["custodian"],
        "in_society_custody": row["state"] in IN_CUSTODY,
        "courier_claims": [dict(c) for c in claims],
        "courier_says_delivered": any(c["claim"] == "delivered" for c in claims),
        "custody": [dict(c) for c in custody],
        "version": row["version"],
        "created_at": row["created_at"],
    }
    if audience == "guard":
        # a guard needs to hand the right parcel over, not to read the household's affairs
        view["pickup"] = {
            "token_live": bool(row["token_live"]),
            "token_expires_at": None,
            "pending_at": None,
        }
        view["leave_at_gate"] = {
            "consent_active": consent_active,
            "consent_at": None,
            "revoked_at": None,
            "left_at_gate": row["left_at_gate"],
        }
    else:
        view["pickup_attempts"] = [dict(a) for a in attempts]
        view["received_by"] = row["received_by"]
    return view


def _views(
    conn: Connection, rows: Sequence[Mapping[Any, Any]], audience: str
) -> list[dict[str, Any]]:
    ids = [r["id"] for r in rows]
    custody, claims, attempts = (
        _custody_of(conn, ids),
        _claims_of(conn, ids),
        _attempts_of(conn, ids),
    )
    return [
        parcel_view(
            r, audience=audience, custody=custody.get(r["id"], ()), claims=claims.get(r["id"], ()),
            attempts=attempts.get(r["id"], ()),
        )
        for r in rows
    ]  # fmt: skip


def get_view(conn: Connection, parcel_id: uuid.UUID, audience: str) -> dict[str, Any]:
    row = (
        conn.execute(
            text(f"SELECT {_PARCEL_COLS}{_PARCEL_FROM} WHERE p.id = :id"),  # noqa: S608
            {"id": parcel_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    return _views(conn, [row], audience)[0]


def parcel_unit(conn: Connection, parcel_id: uuid.UUID) -> uuid.UUID | None:
    row = conn.execute(
        text("SELECT unit_id FROM parcels WHERE id = :id"), {"id": parcel_id}
    ).first()
    return None if row is None else uuid.UUID(str(row[0]))


def list_parcels(
    conn: Connection,
    paginator: Paginator,
    page: PageParams,
    *,
    society_id: uuid.UUID,
    scope: Scope,
    audience: str,
    state: str | None,
    unit_id: uuid.UUID | None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    if unit_id is not None:
        if not scope.covers_unit(unit_id):
            raise NotFound()
        where.append("p.unit_id = :unit")
        params["unit"] = unit_id
        filters["unit_id"] = unit_id
    elif not scope.society_wide:
        where.append("p.unit_id = ANY(:units)")
        params["units"] = sorted(scope.unit_ids, key=lambda u: u.int)
        filters["units"] = ",".join(str(u) for u in sorted(scope.unit_ids, key=lambda u: u.int))
    if state is not None:
        where.append("p.state = :state")
        params["state"] = state
        filters["state"] = state
    elif audience == "guard":
        where.append("p.state = ANY(:open)")
        params["open"] = list(OPEN_STATES)
        filters["open"] = "guard"
    result = paginator.fetch(
        conn,
        select_sql=f"SELECT {_PARCEL_COLS}{_PARCEL_FROM}",  # noqa: S608
        where=where,
        params=params,
        sort=[
            SortColumn("p.created_at", "timestamptz", nullable=False),
            SortColumn("p.id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        filters=filters,
        descending=True,
    )
    return {"items": _views(conn, result.items, audience), "next_cursor": result.next_cursor}


# ------------------------------------------------------------------------------------------ custody chain
def _move_custody(
    conn: Connection,
    *,
    society_id: uuid.UUID | None,
    parcel_id: uuid.UUID,
    prev_seq: int,
    from_party: str,
    to_party: str,
    reason: str,
    actor: uuid.UUID | None,
    evidence_ref: str | None = None,
) -> int:
    """Append the next link of the custody chain. The chain's unique keys make a second, concurrent hand-over from the same
    predecessor fail; the trigger makes ``from_party`` equal the current custodian."""
    assert society_id is not None  # noqa: S101
    seq = prev_seq + 1
    conn.execute(
        text(
            "INSERT INTO custody_transfers (id, society_id, parcel_id, seq, prev_seq, from_party, to_party, reason,"
            " evidence_ref, actor_id) VALUES (:id, :s, :p, :seq, :prev, :f, :t, :why, :ev, :actor)"
        ),
        {
            "id": uuid7(), "s": society_id, "p": parcel_id, "seq": seq, "prev": prev_seq or None, "f": from_party,
            "t": to_party, "why": reason, "ev": evidence_ref, "actor": actor,
        },
    )  # fmt: skip
    return seq


def _check_version(row: Mapping[str, Any], expected: int) -> None:
    if int(row["version"]) != expected:
        raise StaleVersion(details={"current_version": int(row["version"])})


# ------------------------------------------------------------------------------------------ PAR-01 pre-approval
def create_expectation(
    conn: Connection, ctx: RequestContext, body: ExpectationCreate, *, now: dt.datetime
) -> dict[str, Any]:
    if body.source == "order_screenshot":
        # AI-R04 (order-screenshot parsing) is M2 and NOT built; PAR-08: even then a screenshot is never proof of entitlement
        raise PolicyViolation(details={"reason": "order_screenshot_not_available"})
    if body.expected_until <= now:
        raise InvalidSchema.for_fields([("expected_until", "window_already_over")])
    visits_common.require_unit(conn, body.unit_id)
    parcel_id = uuid7()
    assert ctx.society_id is not None  # noqa: S101

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO parcels (id, society_id, unit_id, brand, carrier, state, expected_from, expected_until, expected_by,"
                " leave_at_gate_consent_at, leave_at_gate_consent_by, created_by) VALUES (:id, :s, :u, :brand, :carrier,"
                " 'expected', :f, :t, :by, CASE WHEN :consent THEN clock_timestamp() END,"
                " CASE WHEN :consent THEN CAST(:by AS uuid) END, :by)"
            ),
            {
                "id": parcel_id, "s": ctx.society_id, "u": body.unit_id, "brand": body.brand, "carrier": body.carrier,
                "f": body.expected_from, "t": body.expected_until, "by": ctx.person_id, "consent": body.leave_at_gate_consent,
            },
        )  # fmt: skip
        return MutationResult(
            parcel_id, 1,
            after={"unit_id": body.unit_id, "brand": body.brand, "state": "expected", "leave_at_gate_consent": body.leave_at_gate_consent},
            event_payload={"parcel_id": parcel_id, "unit_id": body.unit_id, "brand": body.brand, "state": "expected"},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="parcel.expect",
        object_type="parcel",
        event_type="ParcelExpected",
        apply=apply,
    )
    return get_view(conn, parcel_id, "household")


def cancel_expectation(
    conn: Connection, ctx: RequestContext, scope: Scope, parcel_id: uuid.UUID
) -> dict[str, Any]:
    row = _locked(conn, parcel_id)
    if not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    if row["state"] == "cancelled":
        return get_view(conn, parcel_id, "household")  # naturally idempotent
    if row["state"] != "expected":
        raise PolicyViolation(details={"reason": "custody_already_taken", "state": row["state"]})

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE parcels SET state = 'cancelled', version = version + 1 WHERE id = :id AND state = 'expected'"
            ),
            {"id": parcel_id},
        )
        return MutationResult(
            parcel_id, int(row["version"]) + 1, before={"state": "expected"}, after={"state": "cancelled"},
            event_payload={"parcel_id": parcel_id, "unit_id": row["unit_id"], "state": "cancelled"},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="parcel.expectation_cancel", object_type="parcel",
        event_type="ParcelExpectationCancelled", apply=apply,
    )  # fmt: skip
    return get_view(conn, parcel_id, "household")


# ------------------------------------------------------------------------------------------ PAR-03 consent
def put_consent(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    parcel_id: uuid.UUID,
    granted: bool,
    expected_version: int,
) -> dict[str, Any]:
    row = _locked(conn, parcel_id)
    if not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    _check_version(row, expected_version)
    if row["state"] != "expected":
        # revocable BEFORE custody only: once the guard holds the parcel the consent has been acted on
        raise PolicyViolation(details={"reason": "custody_already_taken", "state": row["state"]})
    active = row["leave_at_gate_consent_at"] is not None and row["leave_at_gate_revoked_at"] is None
    if not granted and row["leave_at_gate_consent_at"] is None:
        raise PolicyViolation(details={"reason": "no_consent_to_revoke"})
    if granted == active:
        return get_view(conn, parcel_id, "household")  # no change, naturally idempotent

    def apply(c: Connection) -> MutationResult:
        if granted:
            c.execute(
                text(
                    "UPDATE parcels SET leave_at_gate_consent_at = clock_timestamp(), leave_at_gate_consent_by = :by,"
                    " leave_at_gate_revoked_at = NULL, version = version + 1 WHERE id = :id AND state = 'expected'"
                ),
                {"id": parcel_id, "by": ctx.person_id},
            )
        else:
            c.execute(
                text(
                    "UPDATE parcels SET leave_at_gate_revoked_at = clock_timestamp(), version = version + 1"
                    " WHERE id = :id AND state = 'expected'"
                ),
                {"id": parcel_id},
            )
        return MutationResult(
            parcel_id, int(row["version"]) + 1, before={"consent_active": active}, after={"consent_active": granted},
            event_payload={"parcel_id": parcel_id, "unit_id": row["unit_id"], "consent_active": granted},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="parcel.leave_at_gate_consent", object_type="parcel",
        event_type="LeaveAtGateConsentGiven" if granted else "LeaveAtGateConsentRevoked", apply=apply,
    )  # fmt: skip
    return get_view(conn, parcel_id, "household")


# ------------------------------------------------------------------------------------------ PAR-02 receipt
def receive(conn: Connection, ctx: RequestContext, body: ParcelReceive) -> dict[str, Any]:
    visits_common.require_unit(conn, body.unit_id)
    gates.require_active_gate(conn, body.gate_id)
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    matched: dict[str, Any] | None = None
    if body.expected_parcel_id is not None:
        found = (
            conn.execute(
                text("SELECT * FROM parcels WHERE id = :id FOR UPDATE"),
                {"id": body.expected_parcel_id},
            )
            .mappings()
            .first()
        )
        if found is None or found["unit_id"] != body.unit_id:
            raise NotFound()
        if found["state"] != "expected":
            raise PolicyViolation(
                details={"reason": "not_in_expected_state", "state": found["state"]}
            )
        matched = dict(found)
    else:
        found = (
            conn.execute(
                text(
                    "SELECT * FROM parcels WHERE unit_id = :u AND state = 'expected' AND brand_key = lower(btrim(:brand))"
                    " AND expected_from <= clock_timestamp() AND expected_until >= clock_timestamp()"
                    " ORDER BY expected_from, id LIMIT 1 FOR UPDATE SKIP LOCKED"
                ),
                {"u": body.unit_id, "brand": body.brand},
            )
            .mappings()
            .first()
        )
        matched = dict(found) if found is not None else None
    if body.leave_at_gate:
        consenting = (
            matched is not None
            and matched["leave_at_gate_consent_at"] is not None
            and matched["leave_at_gate_revoked_at"] is None
        )
        if not consenting:
            # PAR-03: leaving a parcel unattended needs the resident's explicit, un-revoked consent
            raise PolicyViolation(details={"reason": "leave_at_gate_consent_required"})
    guard = guard_party(ctx.person_id)
    parcel_id = matched["id"] if matched else uuid7()
    version = int(matched["version"]) + 1 if matched else 1

    def apply(c: Connection) -> MutationResult:
        params = {
            "id": parcel_id, "s": ctx.society_id, "u": body.unit_id, "brand": body.brand, "carrier": body.carrier,
            "cref": body.carrier_ref, "gate": body.gate_id, "by": ctx.person_id, "photo": body.photo_ref,
            "laf": body.leave_at_gate, "guard": guard,
        }  # fmt: skip
        if matched is not None:
            done = c.execute(
                text(
                    "UPDATE parcels SET state = 'received_at_gate', gate_id = :gate, received_at = clock_timestamp(),"
                    " received_by = :by, carrier = coalesce(:carrier, carrier), carrier_ref = :cref, photo_ref = :photo,"
                    " matched_expectation = true, left_at_gate = :laf, custody_seq = 1, custodian = :guard,"
                    " version = version + 1 WHERE id = :id AND state = 'expected' RETURNING id"
                ),
                params,
            ).first()
            if done is None:
                raise PolicyViolation(details={"reason": "not_in_expected_state"})
        else:
            c.execute(
                text(
                    "INSERT INTO parcels (id, society_id, unit_id, brand, carrier, carrier_ref, state, gate_id, received_at,"
                    " received_by, photo_ref, left_at_gate, custody_seq, custodian, created_by) VALUES (:id, :s, :u, :brand,"
                    " :carrier, :cref, 'received_at_gate', :gate, clock_timestamp(), :by, :photo, :laf, 1, :guard, :by)"
                ),
                params,
            )
        _move_custody(
            c, society_id=ctx.society_id, parcel_id=parcel_id, prev_seq=0, from_party="courier", to_party=guard,
            reason="received", actor=ctx.person_id,
        )  # fmt: skip
        return MutationResult(
            parcel_id, version,
            after={"unit_id": body.unit_id, "brand": body.brand, "state": "received_at_gate", "matched_expectation": matched is not None},
            event_payload={
                "parcel_id": parcel_id, "unit_id": body.unit_id, "brand": body.brand, "state": "received_at_gate",
                "matched_expectation": matched is not None,
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="parcel.receive",
        object_type="parcel",
        event_type="ParcelReceivedAtGate",
        apply=apply,
    )
    return get_view(conn, parcel_id, "guard")


def store(
    conn: Connection, ctx: RequestContext, parcel_id: uuid.UUID, body: ParcelStore
) -> dict[str, Any]:
    row = _locked(conn, parcel_id)
    _check_version(row, body.expected_version)
    if row["state"] != "received_at_gate":
        raise PolicyViolation(details={"reason": "not_received_at_gate", "state": row["state"]})
    assert ctx.society_id is not None  # noqa: S101
    to_party = f"storage:{body.bin_code}"

    def apply(c: Connection) -> MutationResult:
        done = c.execute(
            text(
                "UPDATE parcels SET state = 'stored', bin_code = :bin, stored_at = clock_timestamp(), custody_seq = custody_seq + 1,"
                " custodian = :to, version = version + 1 WHERE id = :id AND state = 'received_at_gate'"
                " AND custody_seq = :seq RETURNING id"
            ),
            {"id": parcel_id, "bin": body.bin_code, "to": to_party, "seq": row["custody_seq"]},
        ).first()
        if done is None:
            raise PolicyViolation(details={"reason": "not_received_at_gate"})
        _move_custody(
            c, society_id=ctx.society_id, parcel_id=parcel_id, prev_seq=int(row["custody_seq"]),
            from_party=str(row["custodian"]), to_party=to_party, reason="stored", actor=ctx.person_id,
        )  # fmt: skip
        return MutationResult(
            parcel_id, int(row["version"]) + 1, before={"state": "received_at_gate"},
            after={"state": "stored", "bin_code": body.bin_code},
            event_payload={"parcel_id": parcel_id, "unit_id": row["unit_id"], "state": "stored"},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="parcel.store",
        object_type="parcel",
        event_type="ParcelStored",
        apply=apply,
    )
    return get_view(conn, parcel_id, "guard")


# ------------------------------------------------------------------------------------------ PAR-03 pickup
def issue_pickup_token(
    conn: Connection,
    ctx: RequestContext,
    scope: Scope,
    parcel_id: uuid.UUID,
    expected_version: int,
    cfg: ParcelsConfig = DEFAULT_CONFIG,
) -> dict[str, Any]:
    row = _locked(conn, parcel_id)
    if not scope.covers_unit(row["unit_id"]):
        raise NotFound()
    _check_version(row, expected_version)
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    standing = visits_common.member_standing(conn, ctx.person_id, row["unit_id"])
    if standing is None:
        raise NotFound()
    if standing.role == "family" and not standing.can_decide:
        # PAR-03: family pickup requires delegated authority
        raise PolicyViolation(details={"reason": "delegation_required"})
    if row["state"] not in ("stored", "pickup_pending"):
        raise PolicyViolation(details={"reason": "not_ready_for_pickup", "state": row["state"]})
    token = secrets.token_urlsafe(24)

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE parcels SET state = 'pickup_pending', pickup_token_hash = :h, pickup_token_issued_at = clock_timestamp(),"
                " pickup_token_expires_at = clock_timestamp() + make_interval(secs => :ttl), pickup_token_issued_by = :by,"
                " pickup_pending_at = coalesce(pickup_pending_at, clock_timestamp()), version = version + 1"
                " WHERE id = :id AND state IN ('stored', 'pickup_pending')"
            ),
            {
                "id": parcel_id,
                "h": _hash_token(token),
                "ttl": cfg.pickup_token_ttl.total_seconds(),
                "by": ctx.person_id,
            },
        )
        return MutationResult(
            parcel_id, int(row["version"]) + 1, before={"state": row["state"]}, after={"state": "pickup_pending", "token_issued": True},
            event_payload={"parcel_id": parcel_id, "unit_id": row["unit_id"], "state": "pickup_pending"},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="parcel.pickup_token_issue", object_type="parcel", event_type="ParcelPickupTokenIssued",
        apply=apply,
    )  # fmt: skip
    view = get_view(conn, parcel_id, "household")
    view["pickup_token"] = token  # shown ONCE: only its hash is stored
    return view


def _check_collector(
    conn: Connection, unit_id: uuid.UUID, body: ParcelCollect, parcel_id: uuid.UUID, method: str
) -> uuid.UUID | None:
    """PAR-03: a family pickup needs a household member who is delegated (a deciding family member). Returns the collector's person id."""
    members = {m.person_id: m for m in visits_common.household(conn, unit_id)}
    person = body.collector.person_id
    if body.collector.kind == "family":
        member = members.get(person) if person else None
        if member is None or member.role != "family" or not member.can_decide:
            raise PickupDenied(
                parcel_id, "delegation_required", method,
                PolicyViolation(details={"reason": "delegation_required"}),
            )  # fmt: skip
        return person
    if person is not None:
        member = members.get(person)
        unfit = (
            member is None
            or member.role in ("owner_nr", "staff")
            or (member.role == "family" and not member.can_decide)
        )
        if unfit:
            raise PickupDenied(
                parcel_id, "not_the_recipient", method, PolicyViolation(details={"reason": "not_the_recipient"})
            )  # fmt: skip
    return person


def collect(
    conn: Connection, ctx: RequestContext, scope: Scope, parcel_id: uuid.UUID, body: ParcelCollect,
    *, supervised_roles: frozenset[str],
) -> dict[str, Any]:  # fmt: skip
    """Hand the parcel over. Exactly one of any number of concurrent attempts wins; every other one is a recorded denial."""
    row = _locked(conn, parcel_id)
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    method = body.method

    def deny(reason: str, error: DwaarError) -> PickupDenied:
        return PickupDenied(parcel_id, reason, method, error)

    if row["state"] == "collected":
        raise deny("already_collected", AlreadyDecided(details={"reason": "already_collected"}))
    if row["state"] not in COLLECTABLE:
        raise deny(
            "not_collectable",
            PolicyViolation(details={"reason": "not_collectable", "state": row["state"]}),
        )
    if method == "token":
        if body.token is None or body.alternate_proof is not None:
            raise InvalidSchema.for_fields([("token", "required_for_token_method")])
        live = row["pickup_token_hash"] is not None
        fresh = (
            live
            and conn.execute(
                text("SELECT CAST(:exp AS timestamptz) > clock_timestamp()"),
                {"exp": row["pickup_token_expires_at"]},
            ).scalar_one()
        )
        if not live or not hmac.compare_digest(
            str(row["pickup_token_hash"]), _hash_token(body.token)
        ):
            raise deny("invalid_token", PolicyViolation(details={"reason": "invalid_token"}))
        if not fresh:
            raise deny("token_expired", PolicyViolation(details={"reason": "token_expired"}))
    else:
        proof = body.alternate_proof
        if proof is None or body.token is not None:
            raise InvalidSchema.for_fields([("alternate_proof", "required_for_alternate_method")])
        if any(word in proof.kind for word in _SCREENSHOT_WORDS):
            # PAR-08: a screenshot of an order page is never proof of entitlement
            raise deny(
                "screenshot_not_accepted",
                PolicyViolation(details={"reason": "screenshot_not_accepted"}),
            )
        if proof.kind not in ALTERNATE_PROOF_KINDS:
            raise InvalidSchema.for_fields([("alternate_proof.kind", "unknown_proof_kind")])
        if scope.role not in supervised_roles:
            raise deny(
                "supervision_required", NotAuthorised(details={"reason": "supervision_required"})
            )
    collector = _check_collector(conn, row["unit_id"], body, parcel_id, method)
    by_kind = (
        "supervised_alternate"
        if method == "alternate_proof"
        else ("delegate" if body.collector.kind == "family" else "recipient")
    )
    to_party = (
        f"{'delegate' if body.collector.kind == 'family' else 'resident'}:{collector}"
        if collector
        else "resident"
    )

    def apply(c: Connection) -> MutationResult:
        done = c.execute(
            text(
                "UPDATE parcels SET state = 'collected', collected_at = clock_timestamp(), collected_by_kind = :kind,"
                " collected_by_person = :who, collected_via = :via, pickup_token_hash = NULL, resolved_at = clock_timestamp(),"
                " custody_seq = custody_seq + 1, custodian = :to, version = version + 1"
                " WHERE id = :id AND state IN ('received_at_gate', 'stored', 'pickup_pending') AND custody_seq = :seq RETURNING id"
            ),
            {
                "id": parcel_id, "kind": by_kind, "who": collector, "via": method, "to": to_party, "seq": row["custody_seq"],
            },
        ).first()  # fmt: skip
        if done is None:  # pragma: no cover (the row is locked above)
            raise deny("already_collected", AlreadyDecided(details={"reason": "already_collected"}))
        _move_custody(
            c, society_id=ctx.society_id, parcel_id=parcel_id, prev_seq=int(row["custody_seq"]),
            from_party=str(row["custodian"]), to_party=to_party, reason="collected", actor=ctx.person_id,
            evidence_ref=None if method == "token" else f"alternate_proof:{body.alternate_proof.kind}" if body.alternate_proof else None,
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO parcel_pickup_attempts (id, society_id, parcel_id, outcome, reason, method, actor_id)"
                " VALUES (:id, :s, :p, 'granted', 'collected', :m, :a)"
            ),
            {"id": uuid7(), "s": ctx.society_id, "p": parcel_id, "m": method, "a": ctx.person_id},
        )
        return MutationResult(
            parcel_id, int(row["version"]) + 1, before={"state": row["state"]},
            after={"state": "collected", "via": method, "by_kind": by_kind},
            event_payload={"parcel_id": parcel_id, "unit_id": row["unit_id"], "state": "collected", "via": method},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="parcel.collect",
        object_type="parcel",
        event_type="ParcelCollected",
        apply=apply,
    )
    return get_view(conn, parcel_id, "guard")


def record_denied_attempt(conn: Connection, ctx: RequestContext, denied: PickupDenied) -> None:
    """The denied attempt, in its OWN transaction (the denied request rolled back): appended, never altering custody (AT-13)."""
    assert ctx.society_id is not None  # noqa: S101
    conn.execute(
        text(
            "INSERT INTO parcel_pickup_attempts (id, society_id, parcel_id, outcome, reason, method, actor_id)"
            " VALUES (:id, :s, :p, 'denied', :why, :m, :a)"
        ),
        {"id": uuid7(), "s": ctx.society_id, "p": denied.parcel_id, "why": denied.reason, "m": denied.method, "a": ctx.person_id},
    )  # fmt: skip


# ------------------------------------------------------------------------------------------ branches
def resolve(
    conn: Connection, ctx: RequestContext, parcel_id: uuid.UUID, body: ParcelResolve,
    *, may_declare_lost: bool,
) -> dict[str, Any]:  # fmt: skip
    row = _locked(conn, parcel_id)
    _check_version(row, body.expected_version)
    assert ctx.society_id is not None  # noqa: S101
    outcome = body.outcome
    if outcome == "lost_exception" and not may_declare_lost:
        raise NotAuthorised(details={"reason": "supervision_required"})
    sources = {
        "refused": ("received_at_gate", "stored", "pickup_pending"),
        "returned": ("received_at_gate", "stored", "pickup_pending", "refused"),
        "lost_exception": ("received_at_gate", "stored", "pickup_pending", "refused"),
    }[outcome]
    if row["state"] not in sources:
        raise PolicyViolation(
            details={"reason": "transition_not_allowed", "state": row["state"], "to": outcome}
        )
    to_party = None
    reason = None
    if outcome == "returned":
        to_party, reason = f"carrier:{(row['carrier'] or 'carrier')[:40]}", "returned"
    elif outcome == "lost_exception":
        to_party, reason = "lost", "lost"

    def apply(c: Connection) -> MutationResult:
        seq = int(row["custody_seq"])
        done = c.execute(
            text(
                "UPDATE parcels SET state = :to, resolved_at = clock_timestamp(), resolution_note = :note, pickup_token_hash = NULL,"
                " custody_seq = :newseq, custodian = :cust, version = version + 1 WHERE id = :id AND state = :prev_state AND custody_seq = :seq"
                " RETURNING id"
            ),
            {
                "to": outcome, "note": body.note, "newseq": seq + (1 if to_party else 0), "cust": to_party or row["custodian"],
                "id": parcel_id, "prev_state": row["state"], "seq": seq,
            },
        ).first()  # fmt: skip
        if done is None:  # pragma: no cover (the row is locked above)
            raise PolicyViolation(details={"reason": "transition_not_allowed"})
        if to_party and reason:
            _move_custody(
                c, society_id=ctx.society_id, parcel_id=parcel_id, prev_seq=seq, from_party=str(row["custodian"]),
                to_party=to_party, reason=reason, actor=ctx.person_id,
            )  # fmt: skip
        return MutationResult(
            parcel_id, int(row["version"]) + 1, before={"state": row["state"]}, after={"state": outcome},
            event_payload={"parcel_id": parcel_id, "unit_id": row["unit_id"], "state": outcome},
        )  # fmt: skip

    mutation(
        conn, ctx, operation=f"parcel.{outcome}", object_type="parcel",
        event_type={"refused": "ParcelRefused", "returned": "ParcelReturned", "lost_exception": "ParcelLost"}[outcome],
        apply=apply, reason=body.note,
    )  # fmt: skip
    return get_view(conn, parcel_id, "guard")


# ------------------------------------------------------------------------------------------ PAR-04 courier claims
def record_courier_claim(
    conn: Connection, ctx: RequestContext, parcel_id: uuid.UUID, body: CourierClaim
) -> dict[str, Any]:
    exists = conn.execute(text("SELECT 1 FROM parcels WHERE id = :id"), {"id": parcel_id}).first()
    if exists is None:
        raise NotFound()
    claim_id = uuid7()
    assert ctx.society_id is not None  # noqa: S101

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO courier_observations (id, society_id, parcel_id, source, claim, claimed_at, external_ref, recorded_by)"
                " VALUES (:id, :s, :p, :src, :claim, :at, :ref, :by)"
            ),
            {
                "id": claim_id, "s": ctx.society_id, "p": parcel_id, "src": body.source, "claim": body.claim,
                "at": body.claimed_at, "ref": body.external_ref, "by": ctx.person_id,
            },
        )  # fmt: skip
        return MutationResult(
            claim_id, 1, after={"parcel_id": parcel_id, "claim": body.claim, "source": body.source, "external": True},
            event_payload={"parcel_id": parcel_id, "claim": body.claim, "source": body.source, "external": True},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="parcel.courier_claim", object_type="courier_observation",
        event_type="CourierClaimRecorded", apply=apply,
    )  # fmt: skip
    return {
        "id": claim_id,
        "parcel_id": parcel_id,
        "claim": body.claim,
        "source": body.source,
        "external": True,
        "note": "external observation: the society does not hold this parcel because a courier says so",
    }


# ------------------------------------------------------------------------------------------ PAR-05 custody
def custody_snapshot(conn: Connection, gate_id: uuid.UUID | None = None) -> dict[str, Any]:
    """What the system says the society holds right now: the list and the per-bin count (the deterministic side of the report)."""
    rows = conn.execute(
        text(
            "SELECT id, state, bin_code FROM parcels WHERE state = ANY(:s) AND (CAST(:g AS uuid) IS NULL OR gate_id = :g)"
            " ORDER BY received_at, id"
        ),
        {"s": list(IN_CUSTODY), "g": gate_id},
    ).all()
    per_bin: dict[str, int] = {}
    for _id, _state, bin_code in rows:
        per_bin[bin_code or "-"] = per_bin.get(bin_code or "-", 0) + 1
    return {"count": len(rows), "parcel_ids": [r[0] for r in rows], "per_bin": per_bin}


def create_custody_report(
    conn: Connection, ctx: RequestContext, body: CustodyReportCreate
) -> dict[str, Any]:
    if body.gate_id is not None:
        gates.require_active_gate(conn, body.gate_id)
    assert ctx.society_id is not None  # noqa: S101
    assert ctx.person_id is not None  # noqa: S101
    snap = custody_snapshot(conn, body.gate_id)
    bins = sorted(set(snap["per_bin"]) | set(body.bin_counts))
    bin_diffs = {
        b: {"system": snap["per_bin"].get(b, 0), "physical": body.bin_counts.get(b)}
        for b in bins
        if body.bin_counts and snap["per_bin"].get(b, 0) != body.bin_counts.get(b, 0)
    }
    report_id = uuid7()
    details = {
        "system_parcel_ids": [str(p) for p in snap["parcel_ids"][:2000]],
        "bin_discrepancies": bin_diffs,
    }

    def apply(c: Connection) -> MutationResult:
        from ..visits.policy import json_text

        c.execute(
            text(
                "INSERT INTO parcel_custody_reports (id, society_id, gate_id, counted_by, physical_count, system_count, details, note)"
                " VALUES (:id, :s, :g, :by, :phys, :sys, CAST(:d AS jsonb), :note)"
            ),
            {
                "id": report_id, "s": ctx.society_id, "g": body.gate_id, "by": ctx.person_id, "phys": body.physical_count,
                "sys": snap["count"], "d": json_text(details), "note": body.note,
            },
        )  # fmt: skip
        return MutationResult(
            report_id, 1,
            after={"physical_count": body.physical_count, "system_count": snap["count"], "discrepancy": body.physical_count - snap["count"]},
            event_payload={
                "report_id": report_id, "physical_count": body.physical_count, "system_count": snap["count"],
                "discrepancy": body.physical_count - snap["count"],
            },
        )  # fmt: skip

    mutation(
        conn, ctx, operation="parcel.custody_report", object_type="parcel_custody_report",
        event_type="ParcelCustodyReported", apply=apply,
    )  # fmt: skip
    return report_view(
        {
            "id": report_id, "gate_id": body.gate_id, "physical_count": body.physical_count, "system_count": snap["count"],
            "discrepancy": body.physical_count - snap["count"], "details": details, "note": body.note, "counted_by": ctx.person_id,
            "created_at": None,
        }
    )  # fmt: skip


def report_view(row: Mapping[Any, Any]) -> dict[str, Any]:
    discrepancy = int(row["discrepancy"])
    return {
        "id": row["id"],
        "gate_id": row["gate_id"],
        "physical_count": row["physical_count"],
        "system_count": row["system_count"],
        "discrepancy": discrepancy,
        # truthful and never auto-resolved: a shortfall is a thing to investigate, not a parcel silently marked lost (INV-07)
        "status": "reconciled"
        if discrepancy == 0
        else ("physical_short" if discrepancy < 0 else "physical_over"),
        "details": row["details"],
        "note": row["note"],
        "counted_by": row["counted_by"],
        "created_at": row["created_at"],
    }


def list_reports(
    conn: Connection, paginator: Paginator, page: PageParams, *, society_id: uuid.UUID
) -> dict[str, Any]:
    result = paginator.fetch(
        conn,
        select_sql="SELECT id, gate_id, physical_count, system_count, discrepancy, details, note, counted_by, created_at FROM parcel_custody_reports",
        where=[],
        params={},
        sort=[
            SortColumn("created_at", "timestamptz", nullable=False),
            SortColumn("id", "uuid", nullable=False),
        ],
        page=page,
        society_id=society_id,
        descending=True,
    )
    return {"items": [report_view(r) for r in result.items], "next_cursor": result.next_cursor}
