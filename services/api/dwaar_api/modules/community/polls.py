"""Opinion polls (COM-06 ONLY): non-binding, owners-only option, result-visibility rules, neutral-wording hook.

REQ: COM-06 (clearly labelled NON-BINDING opinion polls; owners-only option; result visibility rules; neutral wording check),
D-24 / GOV-01 (binding votes are M2 governance behind an approved legal pack and are NOT built: there is no ballot, quorum,
meeting or resolution anywhere here, ``polls.is_binding`` is CHECKed false, and a test asserts no binding-vote route exists),
INV-04 (owner status is a role of the membership, never inferred from occupancy), INV-01.

One answer per person per poll (a unique constraint). A response row records WHO answered so the rule can hold, but no result
view ever returns it: results are counts only, and who answered what is not readable through this module.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any, Final

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from dwaar_common.errors import (
    AlreadyDecided,
    InvalidSchema,
    NotFound,
    PolicyViolation,
    StaleVersion,
)
from dwaar_common.ids import uuid7
from dwaar_common.timeutil import utc_now

from ...core.audit import MutationResult, mutation
from ...core.db import RequestContext
from ..identity import matrix
from . import wording
from .actors import Actor
from .schemas import PollCloseIn, PollCreate, PollOpenIn

OWNER_ROLES: Final = frozenset({matrix.OWNER_OCC, matrix.OWNER_NR})
_POLL_COLS: Final = (
    "p.id, p.question, p.description, p.eligibility, p.result_visibility, p.state, p.is_binding, p.label_key, p.opens_at,"
    " p.closes_at, p.neutrality_status, p.neutrality_report, p.created_by, p.version, p.created_at"
)
_POLL_SQL: Final = "SELECT " + _POLL_COLS + " FROM polls p"  # noqa: S608


def fetch_poll(
    conn: Connection, poll_id: uuid.UUID, *, lock: bool = False
) -> dict[str, Any] | None:
    if (
        lock
        and conn.execute(
            text("SELECT id FROM polls WHERE id = :id FOR UPDATE"), {"id": poll_id}
        ).first()
        is None
    ):
        return None
    row = conn.execute(text(_POLL_SQL + " WHERE p.id = :id"), {"id": poll_id}).mappings().first()
    return dict(row) if row else None


def options_of(conn: Connection, poll_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("SELECT id, position, label FROM poll_options WHERE poll_id = :p ORDER BY position"),
        {"p": poll_id},
    ).mappings()
    return [dict(r) for r in rows]


def eligible(actor: Actor, poll: dict[str, Any]) -> bool:
    if not actor.is_resident:
        return False
    return poll["eligibility"] == "all_members" or actor.role in OWNER_ROLES


def poll_view(
    conn: Connection, poll: dict[str, Any], actor: Actor, *, staff: bool
) -> dict[str, Any]:
    """Every view says it is NON-BINDING (``non_binding`` and ``label_key``); there is no other kind of poll."""
    mine = conn.execute(
        text("SELECT option_id FROM poll_responses WHERE poll_id = :p AND person_id = :me"),
        {"p": poll["id"], "me": actor.person_id},
    ).scalar()
    view: dict[str, Any] = {
        "id": poll["id"], "question": poll["question"], "description": poll["description"], "state": poll["state"],
        "eligibility": poll["eligibility"], "result_visibility": poll["result_visibility"], "non_binding": True,
        "label_key": poll["label_key"], "opens_at": poll["opens_at"], "closes_at": poll["closes_at"], "version": poll["version"],
        "options": options_of(conn, poll["id"]), "eligible": eligible(actor, poll), "my_response": mine, "created_at": poll["created_at"],
    }  # fmt: skip
    if staff:
        view["neutrality"] = {"status": poll["neutrality_status"], **poll["neutrality_report"]}
    return view


def create_poll(
    conn: Connection, ctx: RequestContext, body: PollCreate, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    report = wording.run_checks(body.question, body.description, body.options)
    status = "flagged" if report["flags"] else "clean"
    poll_id = uuid7()

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO polls (id, society_id, question, description, eligibility, result_visibility, neutrality_status,"
                " neutrality_report, created_by, created_at, updated_at) VALUES (:id, :s, :q, :d, :e, :rv, :ns,"
                " CAST(:nr AS jsonb), :by, :now, :now)"
            ),
            {
                "id": poll_id, "s": ctx.society_id, "q": body.question, "d": body.description, "e": body.eligibility,
                "rv": body.result_visibility, "ns": status, "nr": json.dumps(report), "by": ctx.person_id, "now": moment,
            },
        )  # fmt: skip
        for position, label in enumerate(body.options, start=1):
            c.execute(
                text("INSERT INTO poll_options (society_id, poll_id, position, label) VALUES (:s, :p, :pos, :l)"),
                {"s": ctx.society_id, "p": poll_id, "pos": position, "l": label},
            )  # fmt: skip
        return MutationResult(
            poll_id, 1, after={"state": "draft", "eligibility": body.eligibility, "neutrality_status": status},
            event_payload={"poll_id": poll_id, "state": "draft", "non_binding": True, "neutrality_status": status},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="poll.create",
        object_type="poll",
        event_type="PollDrafted",
        apply=apply,
    )
    poll = fetch_poll(conn, poll_id)
    assert poll is not None  # noqa: S101
    return poll


def _bump(
    conn: Connection, poll: dict[str, Any], sets: str, params: dict[str, Any], now: dt.datetime
) -> int:
    sql = f"UPDATE polls SET {sets}, version = version + 1, updated_at = :_now WHERE id = :_id AND version = :_v"  # noqa: S608
    if (
        conn.execute(
            text(sql), {**params, "_now": now, "_id": poll["id"], "_v": poll["version"]}
        ).rowcount
        != 1
    ):
        raise StaleVersion()
    return int(poll["version"]) + 1


def open_poll(
    conn: Connection, ctx: RequestContext, poll_id: uuid.UUID, body: PollOpenIn, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    poll = fetch_poll(conn, poll_id, lock=True)
    if poll is None:
        raise NotFound()
    if body.expected_version is not None and body.expected_version != poll["version"]:
        raise StaleVersion()
    if poll["state"] != "draft":
        raise StaleVersion("Only a draft poll can be opened.", details={"reason": "not_a_draft"})
    if body.closes_at is not None and (body.closes_at.tzinfo is None or body.closes_at <= moment):
        raise InvalidSchema.for_fields([("closes_at", "must_be_in_the_future")])
    status = poll["neutrality_status"]
    if status == "flagged":
        if not body.override_reason:
            raise PolicyViolation(
                "The neutral-wording check flagged this poll; edit it or open it with a recorded reason.",
                details={
                    "reason": "neutrality_flagged",
                    "flags": poll["neutrality_report"].get("flags", []),
                },
            )
        status = "overridden"

    def apply(c: Connection) -> MutationResult:
        new_version = _bump(
            c, poll, "state = 'open', opens_at = :now, closes_at = :closes, neutrality_status = :ns, neutrality_override_reason = :why",
            {"now": moment, "closes": body.closes_at, "ns": status, "why": body.override_reason}, moment,
        )  # fmt: skip
        return MutationResult(
            poll_id, new_version, before={"state": "draft"}, after={"state": "open", "neutrality_status": status},
            event_payload={"poll_id": poll_id, "state": "open", "non_binding": True, "eligibility": poll["eligibility"]},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="poll.open",
        object_type="poll",
        event_type="PollOpened",
        apply=apply,
        reason=body.override_reason,
    )
    got = fetch_poll(conn, poll_id)
    assert got is not None  # noqa: S101
    return got


def close_poll(
    conn: Connection, ctx: RequestContext, poll_id: uuid.UUID, body: PollCloseIn | None, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    poll = fetch_poll(conn, poll_id, lock=True)
    if poll is None:
        raise NotFound()
    if (
        body is not None
        and body.expected_version is not None
        and body.expected_version != poll["version"]
    ):
        raise StaleVersion()
    if poll["state"] != "open":
        raise StaleVersion("Only an open poll can be closed.", details={"reason": "not_open"})

    def apply(c: Connection) -> MutationResult:
        new_version = _bump(c, poll, "state = 'closed', closes_at = :now", {"now": moment}, moment)
        return MutationResult(
            poll_id, new_version, before={"state": "open"}, after={"state": "closed"},
            event_payload={"poll_id": poll_id, "state": "closed", "non_binding": True},
        )  # fmt: skip

    mutation(
        conn, ctx, operation="poll.close", object_type="poll", event_type="PollClosed", apply=apply
    )
    got = fetch_poll(conn, poll_id)
    assert got is not None  # noqa: S101
    return got


def close_due(conn: Connection, ctx: RequestContext, now: dt.datetime | None = None) -> int:
    """Close open polls whose closing time passed (idempotent; the actor is the system)."""
    moment = now or utc_now()
    done = 0
    for (pid,) in conn.execute(
        text(
            "SELECT id FROM polls WHERE state = 'open' AND closes_at IS NOT NULL AND closes_at <= :now ORDER BY closes_at, id FOR UPDATE SKIP LOCKED"
        ),
        {"now": moment},
    ).all():
        close_poll(conn, ctx, pid, None, moment)
        done += 1
    return done


def respond(
    conn: Connection, ctx: RequestContext, actor: Actor, poll_id: uuid.UUID, option_id: uuid.UUID, now: dt.datetime | None = None
) -> dict[str, Any]:  # fmt: skip
    moment = now or utc_now()
    poll = fetch_poll(
        conn, poll_id, lock=True
    )  # serialises answers per poll: one event version per answer
    if poll is None or poll["state"] == "draft":
        raise NotFound()  # a draft does not exist for residents
    if poll["state"] == "closed" or (poll["closes_at"] is not None and poll["closes_at"] <= moment):
        raise StaleVersion("This poll is closed.", details={"reason": "poll_closed"})
    if not eligible(actor, poll):
        raise (
            PolicyViolation("This poll is for owners only.", details={"reason": "owners_only"})
            if actor.is_resident
            else NotFound()
        )
    if (
        conn.execute(
            text("SELECT 1 FROM poll_options WHERE id = :o AND poll_id = :p"),
            {"o": option_id, "p": poll_id},
        ).first()
        is None
    ):
        raise InvalidSchema.for_fields([("option_id", "unknown_option")])
    unit = sorted(actor.unit_ids, key=lambda x: x.int)[0] if actor.unit_ids else None

    def apply(c: Connection) -> MutationResult:
        try:
            with c.begin_nested():
                c.execute(
                    text(
                        "INSERT INTO poll_responses (society_id, poll_id, option_id, person_id, unit_id, at)"
                        " VALUES (:s, :p, :o, :me, :u, :now)"
                    ),
                    {
                        "s": ctx.society_id,
                        "p": poll_id,
                        "o": option_id,
                        "me": actor.person_id,
                        "u": unit,
                        "now": moment,
                    },
                )
        except IntegrityError:
            raise AlreadyDecided("You have already answered this poll.") from None
        n = c.execute(
            text("SELECT count(*) FROM poll_responses WHERE poll_id = :p"), {"p": poll_id}
        ).scalar_one()
        # the aggregate here is the RESPONSE COUNT, not the poll row: each response is one aggregate version of 'poll_response'
        return MutationResult(
            poll_id, int(n), after={"responses": int(n)},
            event_payload={"poll_id": poll_id, "non_binding": True, "responses": int(n)},
        )  # fmt: skip

    mutation(
        conn,
        ctx,
        operation="poll.respond",
        object_type="poll_response",
        event_type="PollResponded",
        apply=apply,
    )
    return {"poll_id": poll_id, "recorded": True, "non_binding": True}


def results(conn: Connection, poll: dict[str, Any], actor: Actor, *, staff: bool) -> dict[str, Any]:
    """Counts only (never who answered). Visibility: ``live`` anytime, ``after_close`` once closed, ``managers_only`` never to
    residents. Staff roles (the drafters and the secretary) always see the counts of an opened poll."""
    base: dict[str, Any] = {
        "poll_id": poll["id"],
        "non_binding": True,
        "label_key": poll["label_key"],
        "state": poll["state"],
    }
    visible = poll["state"] != "draft" and (
        staff
        or poll["result_visibility"] == "live"
        or (poll["result_visibility"] == "after_close" and poll["state"] == "closed")
    )
    if not visible:
        return {
            **base,
            "visible": False,
            "reason": poll["result_visibility"] if poll["state"] != "draft" else "draft",
        }
    rows = conn.execute(
        text(
            "SELECT o.id, o.position, o.label, count(r.id) FROM poll_options o LEFT JOIN poll_responses r ON r.option_id = o.id"
            " WHERE o.poll_id = :p GROUP BY o.id, o.position, o.label ORDER BY o.position"
        ),
        {"p": poll["id"]},
    ).all()
    return {
        **base, "visible": True, "total_responses": sum(r[3] for r in rows),
        "options": [{"id": r[0], "position": r[1], "label": r[2], "count": r[3]} for r in rows],
    }  # fmt: skip
