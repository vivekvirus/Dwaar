"""Invitations (GATE-01, GATE-08): create, list, revoke (versioned), redeem a signed QR or a 6-digit code.

REQ: GATE-01 (purpose, host and unit, people count, gate, window, max uses, vehicle; the QR carries opaque ids, expiry and a
nonce; codes are hashed and rate-limited; revocation is versioned; recurring visits are EXPLICIT windows, never a permanent
OTP), GATE-08 (a phone-free host-issued pass: the visitor number is optional and never stored), GATE-13, INV-07 (redeeming
authorises a visit; it does not say the visitor entered), INV-01.

Every clock decision (window, expiry) uses the DATABASE clock inside SQL; the application clock never decides.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.errors import InvalidSchema, NotFound, PolicyViolation
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from . import common, gates, tokens
from . import policy as policy_mod
from .config import VisitsConfig
from .policy import GatePolicy
from .schemas import InvitationCreate, InvitationRedeem, Window

_MAX_RECURRING_WINDOW = dt.timedelta(hours=24)
_MAX_SINGLE_WINDOW = dt.timedelta(days=7)
_MAX_SPAN = dt.timedelta(days=366)

_INV_COLS = (
    "i.id, i.unit_id, i.kind, i.purpose, i.visitor_alias, i.people_count, i.gate_id, i.window_start, i.window_end,"
    " i.max_uses, i.uses, i.vehicle_plate, i.expected_minutes, i.state, i.revoked_version, i.token_nonce,"
    " i.code_hash IS NOT NULL AS has_code, i.host_person_id, i.version, i.created_at"
)


def invitation_view(
    row: Mapping[Any, Any],
    windows: Sequence[Mapping[Any, Any]],
    *,
    viewer: uuid.UUID | None,
    now: dt.datetime,
) -> dict[str, Any]:
    state = row["state"]
    if state == "active" and row["window_end"] <= now:
        state = "expired"  # lazy: the sweep persists it, the view never lies in the meantime
    return {
        "id": row["id"],
        "unit_id": row["unit_id"],
        "kind": row["kind"],
        "purpose": row["purpose"],
        "visitor_alias": row["visitor_alias"],
        "people_count": row["people_count"],
        "gate_id": row["gate_id"],
        "windows": [{"start": w["window_start"], "end": w["window_end"]} for w in windows],
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "max_uses": row["max_uses"],
        "uses": row["uses"],
        "vehicle_plate": row["vehicle_plate"],
        "expected_minutes": row["expected_minutes"],
        "state": state,
        "revoked_version": row["revoked_version"] or None,
        "has_code": row["has_code"],
        "host_is_me": viewer is not None and row["host_person_id"] == viewer,
        "version": row["version"],
        "created_at": row["created_at"],
    }


def _windows_of(
    conn: Connection, ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT invitation_id, window_start, window_end FROM invitation_windows"
            " WHERE invitation_id = ANY(:ids) ORDER BY invitation_id, seq"
        ),
        {"ids": list(ids)},
    ).mappings()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["invitation_id"], []).append(dict(r))
    return out


def _check_windows(windows: Sequence[Window], cfg: VisitsConfig, now: dt.datetime) -> list[Window]:
    """Explicit, ordered, non-overlapping windows. A recurring pass is a list of short windows; there is no open-ended form."""
    ordered = sorted(windows, key=lambda w: w.start)
    problems: list[tuple[str, str]] = []
    if len(ordered) > cfg.max_windows_per_invitation:
        problems.append(("windows", f"at_most_{cfg.max_windows_per_invitation}"))
    for i, w in enumerate(ordered):
        length = w.end - w.start
        if w.end <= w.start:
            problems.append((f"windows.{i}", "end_must_follow_start"))
        elif len(ordered) == 1 and length > _MAX_SINGLE_WINDOW:
            problems.append((f"windows.{i}", "longer_than_7_days"))
        elif len(ordered) > 1 and length > _MAX_RECURRING_WINDOW:
            problems.append((f"windows.{i}", "recurring_window_longer_than_24_hours"))
        if i and ordered[i - 1].end > w.start:
            problems.append((f"windows.{i}", "overlaps_previous_window"))
    if not problems and ordered[-1].end <= now:
        problems.append(("windows", "already_over"))
    if not problems and ordered[-1].end - ordered[0].start > _MAX_SPAN:
        problems.append(("windows", "span_longer_than_366_days"))
    if problems:
        raise InvalidSchema.for_fields(problems)
    return ordered


def _fresh_code(
    conn: Connection,
    cfg: VisitsConfig,
    society_id: uuid.UUID,
    unit_id: uuid.UUID,
    invitation_id: uuid.UUID,
) -> tuple[str, str]:
    """A 6-digit code whose hash is unique among the unit's live codes (so a code identifies ONE invitation)."""
    live = {
        r[0]
        for r in conn.execute(
            text(
                "SELECT code_hash FROM invitations WHERE unit_id = :u AND state = 'active'"
                " AND code_hash IS NOT NULL AND window_end > now()"
            ),
            {"u": unit_id},
        ).all()
    }
    for _ in range(20):
        code = tokens.new_code()
        digest = tokens.code_hash(cfg, society_id, unit_id, invitation_id, code)
        if digest not in live:
            return code, digest
    raise PolicyViolation(details={"reason": "code_space_exhausted"})  # pragma: no cover


def create_invitation(
    conn: Connection,
    ctx: RequestContext,
    cfg: VisitsConfig,
    society_id: uuid.UUID,
    body: InvitationCreate,
) -> dict[str, Any]:
    assert ctx.person_id is not None  # noqa: S101 (a resident request always has a person)
    common.require_unit(conn, body.unit_id)
    if body.gate_id is not None:
        gates.require_active_gate(conn, body.gate_id)
    policy_mod.check_expected_minutes(body.kind, body.expected_minutes)
    now = utc_now()
    windows = _check_windows(body.windows, cfg, now)
    token = (
        tokens.contact_token(cfg, society_id, body.visitor_phone) if body.visitor_phone else None
    )
    invitation_id = uuid7()
    nonce = tokens.new_nonce()
    code: str | None = None
    digest: str | None = None
    if body.with_code:
        code, digest = _fresh_code(conn, cfg, society_id, body.unit_id, invitation_id)
    start, end = windows[0].start, windows[-1].end

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO invitations (id, society_id, host_person_id, unit_id, kind, purpose, visitor_alias,"
                " visitor_contact_token, people_count, gate_id, window_start, window_end, max_uses, vehicle_plate,"
                " expected_minutes, token_nonce, code_hash, created_by) VALUES (:id, :s, :host, :u, :kind, :purpose,"
                " :alias, :tok, :n, :g, :ws, :we, :mu, :plate, :exp, :nonce, :ch, :host)"
            ),
            {
                "id": invitation_id, "s": society_id, "host": ctx.person_id, "u": body.unit_id, "kind": body.kind,
                "purpose": body.purpose, "alias": body.visitor_alias, "tok": token, "n": body.people_count,
                "g": body.gate_id, "ws": start, "we": end, "mu": body.max_uses, "plate": body.vehicle_plate,
                "exp": body.expected_minutes, "nonce": nonce, "ch": digest,
            },
        )  # fmt: skip
        for seq, w in enumerate(windows, start=1):
            c.execute(
                text(
                    "INSERT INTO invitation_windows (id, society_id, invitation_id, seq, window_start, window_end)"
                    " VALUES (:id, :s, :i, :seq, :ws, :we)"
                ),
                {
                    "id": uuid7(),
                    "s": society_id,
                    "i": invitation_id,
                    "seq": seq,
                    "ws": w.start,
                    "we": w.end,
                },
            )
        return MutationResult(
            invitation_id,
            1,
            after={
                "unit_id": body.unit_id, "kind": body.kind, "state": "active", "max_uses": body.max_uses,
                "windows": len(windows), "gate_id": body.gate_id, "has_code": body.with_code,
                "phone_free": token is None,
            },
            event_payload={
                "invitation_id": invitation_id, "unit_id": body.unit_id, "kind": body.kind,
                "max_uses": body.max_uses, "window_end": end,
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="invitation.create",
        object_type="invitation",
        event_type="InvitationCreated",
        apply=apply,
    )
    view = get_invitation(conn, invitation_id, viewer=ctx.person_id)
    assert view is not None  # noqa: S101
    view["qr"] = tokens.build_qr(
        cfg, invitation_id=invitation_id, society_id=society_id, nonce=nonce, not_before=start,
        expires=end, gate_id=body.gate_id,
    )  # fmt: skip
    view["code"] = code  # shown ONCE: only its keyed hash is stored
    return view


def get_invitation(
    conn: Connection, invitation_id: uuid.UUID, *, viewer: uuid.UUID | None
) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_INV_COLS} FROM invitations i WHERE i.id = :id"),  # noqa: S608
            {"id": invitation_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        return None
    windows = _windows_of(conn, [invitation_id]).get(invitation_id, [])
    return invitation_view(row, windows, viewer=viewer, now=utc_now())


def invitation_unit(conn: Connection, invitation_id: uuid.UUID) -> uuid.UUID | None:
    row = conn.execute(
        text("SELECT unit_id FROM invitations WHERE id = :id"), {"id": invitation_id}
    ).first()
    return None if row is None else uuid.UUID(str(row[0]))


def list_invitations(
    conn: Connection,
    units: Sequence[uuid.UUID],
    *,
    viewer: uuid.UUID | None,
    state: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    rows = (
        conn.execute(
            text(
                f"SELECT {_INV_COLS} FROM invitations i WHERE i.unit_id = ANY(:units)"  # noqa: S608
                " AND (CAST(:st AS text) IS NULL OR i.state = CAST(:st AS text))"
                " ORDER BY i.created_at DESC, i.id DESC LIMIT :n"
            ),
            {"units": list(units), "st": state, "n": limit},
        )
        .mappings()
        .all()
    )
    windows = _windows_of(conn, [r["id"] for r in rows])
    now = utc_now()
    return [invitation_view(r, windows.get(r["id"], []), viewer=viewer, now=now) for r in rows]


# ------------------------------------------------------------------------------------------ revocation
def revoke_invitation(
    conn: Connection, ctx: RequestContext, society_id: uuid.UUID, invitation_id: uuid.UUID
) -> dict[str, Any]:
    """Revoke a live pass: allocate the next society revocation version, close the pass, withdraw authorisations that
    have not been used for entry. A second revocation answers with the first one's version (naturally idempotent)."""
    row = (
        conn.execute(
            text(
                "SELECT id, unit_id, state, revoked_version, version FROM invitations WHERE id = :id FOR UPDATE"
            ),
            {"id": invitation_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound()
    if row["state"] == "revoked":
        return {
            "invitation_id": invitation_id, "state": "revoked", "revoked_version": row["revoked_version"],
            "version": row["version"], "already_revoked": True, "cancelled_visits": 0,
        }  # fmt: skip
    if row["state"] not in ("draft", "active"):
        raise PolicyViolation(details={"reason": "not_revocable", "state": row["state"]})
    holder: dict[str, Any] = {}

    def apply(c: Connection) -> MutationResult:
        rv = policy_mod.next_revocation_version(c, society_id, ctx.person_id)
        updated = c.execute(
            text(
                "UPDATE invitations SET state = 'revoked', revoked_version = :rv, revoked_at = clock_timestamp(),"
                " revoked_by = :by, version = version + 1 WHERE id = :id AND state IN ('draft', 'active')"
                " RETURNING version"
            ),
            {"rv": rv, "by": ctx.person_id, "id": invitation_id},
        ).first()
        if updated is None:  # pragma: no cover (the row is locked above)
            raise PolicyViolation(details={"reason": "not_revocable"})
        cancelled = c.execute(
            text(
                "UPDATE visits SET state = 'cancelled', closed_reason = 'invitation_revoked', version = version + 1"
                " WHERE invitation_id = :id AND state = 'authorised' RETURNING id"
            ),
            {"id": invitation_id},
        ).all()
        if cancelled:
            c.execute(
                text(
                    "UPDATE visit_stops SET authorised = false, state = 'cancelled', closed_reason = 'invitation_revoked'"
                    " WHERE visit_id = ANY(:ids) AND state = 'authorised'"
                ),
                {"ids": [r[0] for r in cancelled]},
            )
        holder.update(rv=rv, version=int(updated[0]), cancelled=len(cancelled))
        return MutationResult(
            invitation_id,
            int(updated[0]),
            before={"state": row["state"]},
            after={"state": "revoked", "revoked_version": rv, "cancelled_visits": len(cancelled)},
            event_payload={
                "invitation_id": invitation_id, "unit_id": row["unit_id"], "revoked_version": rv,
                "cancelled_visits": len(cancelled),
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="invitation.revoke",
        object_type="invitation",
        event_type="InvitationRevoked",
        apply=apply,
    )
    return {
        "invitation_id": invitation_id, "state": "revoked", "revoked_version": holder["rv"],
        "version": holder["version"], "already_revoked": False, "cancelled_visits": holder["cancelled"],
    }  # fmt: skip


# ------------------------------------------------------------------------------------------ redeem
def _invalid(reason: str) -> PolicyViolation:
    return PolicyViolation(details={"reason": reason})


def _locate(
    conn: Connection, cfg: VisitsConfig, society_id: uuid.UUID, body: InvitationRedeem
) -> dict[str, Any]:
    """The invitation row (locked) named by the QR or the code. Every 'not mine / not valid' is the same ``invalid_pass``."""
    cols = (
        "i.id, i.unit_id, i.kind, i.visitor_alias, i.visitor_contact_token, i.people_count, i.gate_id, i.max_uses,"
        " i.uses, i.vehicle_plate, i.expected_minutes, i.state, i.token_nonce, i.code_hash, i.window_end,"
        " i.version, i.revoked_version"
    )
    if body.qr is not None:
        payload = tokens.parse_qr(cfg, body.qr)
        if payload is None or payload.society_id != society_id:
            raise _invalid("invalid_pass")
        row = (
            conn.execute(
                text(f"SELECT {cols} FROM invitations i WHERE i.id = :id FOR UPDATE"),  # noqa: S608
                {"id": payload.invitation_id},
            )
            .mappings()
            .first()
        )
        if row is None or row["token_nonce"] != payload.nonce:
            raise _invalid("invalid_pass")
        return dict(row)
    if body.code is None or body.unit_id is None:
        raise InvalidSchema.for_fields([("code", "qr_or_code_with_unit_required")])
    rows = (
        conn.execute(
            text(
                f"SELECT {cols} FROM invitations i WHERE i.unit_id = :u AND i.code_hash IS NOT NULL"  # noqa: S608
                " AND i.state IN ('active', 'consumed', 'revoked', 'expired') ORDER BY i.created_at DESC LIMIT 50"
            ),
            {"u": body.unit_id},
        )
        .mappings()
        .all()
    )
    import hmac

    for r in rows:
        expected = tokens.code_hash(cfg, society_id, body.unit_id, r["id"], body.code)
        if hmac.compare_digest(expected.encode(), str(r["code_hash"]).encode()):
            locked = (
                conn.execute(
                    text(f"SELECT {cols} FROM invitations i WHERE i.id = :id FOR UPDATE"),  # noqa: S608
                    {"id": r["id"]},
                )
                .mappings()
                .one()
            )
            return dict(locked)
    raise _invalid("invalid_pass")


def redeem(
    conn: Connection,
    ctx: RequestContext,
    cfg: VisitsConfig,
    society_id: uuid.UUID,
    body: InvitationRedeem,
    policy: GatePolicy,
) -> dict[str, Any]:
    """Present a pass at a gate. A valid pass becomes an AUTHORISED visit; whether the visitor then walks in is a separate,
    observed fact (``visits.observe``). Consumption is a conditional UPDATE on uses < max_uses, so two guards presenting the
    same single-use pass at once cannot both succeed."""
    assert ctx.person_id is not None  # noqa: S101
    gates.require_active_gate(conn, body.gate_id)
    inv = _locate(conn, cfg, society_id, body)
    if inv["state"] == "revoked":
        raise _invalid("revoked")
    if inv["state"] == "consumed" or inv["uses"] >= inv["max_uses"]:
        raise _invalid("consumed")
    if inv["state"] == "expired":
        raise _invalid("expired")
    if inv["state"] != "active":
        raise _invalid("not_active")
    if inv["gate_id"] is not None and inv["gate_id"] != body.gate_id:
        raise _invalid("wrong_gate")
    window = (
        conn.execute(
            text(
                "SELECT min(w.window_end) AS window_end FROM invitation_windows w WHERE w.invitation_id = :id"
                " AND w.window_start <= clock_timestamp() AND w.window_end > clock_timestamp()"
            ),
            {"id": inv["id"]},
        )
        .mappings()
        .one()
    )
    if window["window_end"] is None:
        upcoming = conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM invitation_windows WHERE invitation_id = :id"
                " AND window_start > clock_timestamp())"
            ),
            {"id": inv["id"]},
        ).scalar_one()
        raise _invalid("not_yet_valid" if upcoming else "expired")
    visit_id = uuid7()
    stop_id = uuid7()
    holder: dict[str, Any] = {}

    def apply(c: Connection) -> MutationResult:
        used = c.execute(
            text(
                "UPDATE invitations SET uses = uses + 1,"
                " state = CASE WHEN uses + 1 >= max_uses THEN 'consumed' ELSE state END, version = version + 1"
                " WHERE id = :id AND state = 'active' AND uses < max_uses AND revoked_version = 0"
                " RETURNING uses, state"
            ),
            {"id": inv["id"]},
        ).first()
        if used is None:
            raise _invalid("consumed")
        c.execute(
            text(
                "INSERT INTO visits (id, society_id, kind, state, visitor_alias, visitor_contact_token, invitation_id,"
                " gate_id, people_count, vehicle_plate, expected_minutes, authorisation_source, authorised_at,"
                " authorised_until, consent_recorded, created_by) VALUES (:id, :s, :kind, 'authorised', :alias, :tok,"
                " :inv, :g, :n, :plate, :exp, 'invitation', clock_timestamp(),"
                " least(clock_timestamp() + make_interval(mins => :mins), :wend), false, :by)"
            ),
            {
                "id": visit_id, "s": society_id, "kind": inv["kind"],
                "alias": inv["visitor_alias"] or "Guest", "tok": inv["visitor_contact_token"], "inv": inv["id"],
                "g": body.gate_id, "n": inv["people_count"], "plate": inv["vehicle_plate"],
                "exp": inv["expected_minutes"], "mins": policy.permission_validity_minutes,
                "wend": window["window_end"], "by": ctx.person_id,
            },
        )  # fmt: skip
        c.execute(
            text(
                "INSERT INTO visit_stops (id, society_id, visit_id, unit_id, seq, authorised, state)"
                " VALUES (:id, :s, :v, :u, 1, true, 'authorised')"
            ),
            {"id": stop_id, "s": society_id, "v": visit_id, "u": inv["unit_id"]},
        )
        holder.update(uses=int(used[0]), state=str(used[1]))
        return MutationResult(
            visit_id,
            1,
            after={
                "state": "authorised", "source": "invitation", "invitation_id": inv["id"], "unit_id": inv["unit_id"],
                "invitation_uses": int(used[0]), "gate_id": body.gate_id,
            },
            event_payload={
                "visit_id": visit_id, "unit_id": inv["unit_id"], "source": "invitation", "invitation_id": inv["id"],
            },
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="invitation.redeem",
        object_type="visit",
        event_type="VisitAuthorised",
        apply=apply,
    )
    row = (
        conn.execute(
            text(f"SELECT {common.VISIT_COLUMNS} FROM visits v WHERE v.id = :id"),  # noqa: S608
            {"id": visit_id},
        )
        .mappings()
        .one()
    )
    visit = common.visit_views(conn, [row], view="guard")[0]
    return {
        "visit": visit,
        "invitation": {
            "id": inv["id"], "uses": holder["uses"], "max_uses": inv["max_uses"], "state": holder["state"],
        },
        "permission_expires_at": row["authorised_until"],
        "entry_observed": False,  # authorisation is not evidence of entry (INV-07)
    }  # fmt: skip


def expire_invitations(
    conn: Connection, ctx: RequestContext, *, now: dt.datetime | None = None, limit: int = 200
) -> int:
    """Persist ``expired`` for active passes whose last window is over (idempotent; also what the views show lazily)."""
    rows = conn.execute(
        text(
            "SELECT id, version FROM invitations WHERE state = 'active' AND window_end <= COALESCE(CAST(:now AS timestamptz), clock_timestamp())"
            " ORDER BY window_end LIMIT :n FOR UPDATE SKIP LOCKED"
        ),
        {"now": now, "n": limit},
    ).all()
    done = 0
    for inv_id, _version in rows:

        def apply(c: Connection, inv_id: uuid.UUID = inv_id) -> MutationResult:
            updated = c.execute(
                text(
                    "UPDATE invitations SET state = 'expired', version = version + 1"
                    " WHERE id = :id AND state = 'active' RETURNING version"
                ),
                {"id": inv_id},
            ).first()
            if updated is None:  # pragma: no cover
                raise PolicyViolation()
            return MutationResult(
                inv_id,
                int(updated[0]),
                after={"state": "expired"},
                event_payload={"invitation_id": inv_id},
            )

        mutation(
            conn, ctx, operation="invitation.expire", object_type="invitation", event_type="InvitationExpired",
            apply=apply,
        )  # fmt: skip
        done += 1
    return done
