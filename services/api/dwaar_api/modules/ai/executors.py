"""Deterministic execution of confirmed commands, and the validated edits a user may make before confirming.

REQ: INV-06 (AI proposes, deterministic services execute), AI-SYS-04 (validated payload; allowed command), AT-26, AI-R02 ('resident edits and
confirms; unit and location resolved to authorised ids, never free text'), AI-SYS-08 (easy correction).

The command is fixed in the stored proposal and inside its hash; edits can change CONTENT fields of the payload (and, for a complaint, pick
another of the caller's OWN units). Every edit is validated here; an unknown field, a wrong type or a unit the caller does not hold is refused.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_ai_gateway.guardrails import CommandSpec
from dwaar_common.errors import DependencyUnavailable, InvalidSchema, NotFound, PolicyViolation
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import AuthContext
from .ports import AiRuntime

CATEGORIES: Final = (
    "plumbing",
    "electrical",
    "lift",
    "parking",
    "security",
    "housekeeping",
    "noise",
    "water_supply",
    "civil",
    "other",
)
URGENCIES: Final = ("low", "normal", "high", "emergency")
_MAX_TEXT: Final = 6000

#: editable payload fields per draft kind (name -> "str" | "strlist" | enum tuple)
EDITABLE: Final[dict[str, dict[str, Any]]] = {
    "translation": {"translated_text": "str"},
    "poll_wording": {"neutral_wording": "str", "options": "strlist"},
    "notice_draft": {"title": "str", "body": "str"},
    "complaint": {
        "description": "str",
        "category": CATEGORIES,
        "urgency": URGENCIES,
        "unit_id": "uuid",
        "common_area": "str",
    },
    "triage": {},
    "handover": {"narrative": "str"},
}


def _check_value(field: str, kind: Any, value: Any) -> Any:
    if kind == "str":
        if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
            raise InvalidSchema.for_fields([(f"edits.{field}", "invalid_text")])
        return value
    if kind == "strlist":
        if (
            not isinstance(value, list)
            or len(value) > 10
            or not all(isinstance(v, str) and 0 < len(v) <= 200 for v in value)
        ):
            raise InvalidSchema.for_fields([(f"edits.{field}", "invalid_list")])
        return value
    if kind == "uuid":
        try:
            return uuid.UUID(str(value))
        except ValueError:
            raise InvalidSchema.for_fields([(f"edits.{field}", "invalid_uuid")]) from None
    if isinstance(kind, tuple):
        if value not in kind:
            raise InvalidSchema.for_fields([(f"edits.{field}", "not_allowed_value")])
        return value
    raise InvalidSchema.for_fields([(f"edits.{field}", "not_editable")])


def apply_edits(
    conn: Connection,
    auth: AuthContext,
    row: Mapping[str, Any],
    edits: Mapping[str, Any] | None,
    now_versions: Sequence[int],
) -> tuple[dict[str, Any], list[uuid.UUID], list[int], bool]:
    """(final payload, target ids, target versions, edited?). The proposal row itself is never modified."""
    payload: dict[str, Any] = json.loads(json.dumps(row["payload"]))
    target_ids = list(row["target_ids"])
    target_versions = list(now_versions)
    if not edits:
        return payload, target_ids, target_versions, False
    allowed = EDITABLE.get(str(payload.get("kind")), {})
    unknown = sorted(set(edits) - set(allowed))
    if unknown:
        raise InvalidSchema.for_fields([(f"edits.{k}", "not_editable") for k in unknown])
    changed = False
    for field, value in edits.items():
        clean = _check_value(field, allowed[field], value)
        if field == "unit_id":
            if not auth.scope.covers_unit(clean):
                raise NotFound()  # not one of the caller's own units
            unit = conn.execute(
                text("SELECT u.id, b.name, u.label, u.version FROM units u JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
                     " WHERE u.id = :id AND u.status = 'active'"),
                {"id": clean},
            ).first()  # fmt: skip
            if unit is None:
                raise NotFound()
            payload.update(
                {
                    "unit_id": str(unit[0]),
                    "block": str(unit[1]),
                    "unit_label": str(unit[2]),
                    "common_area": None,
                    "location_status": "unit",
                }
            )
            target_ids, target_versions = [unit[0]], [int(unit[3])]
            changed = True
            continue
        if field == "common_area":
            if clean.lower() not in {
                "lobby",
                "terrace",
                "parking",
                "garden",
                "gate",
                "clubhouse",
                "playground",
                "lift",
                "staircase",
                "basement",
                "podium",
            }:
                raise InvalidSchema.for_fields([("edits.common_area", "unknown_common_area")])
            payload.update(
                {
                    "common_area": clean.lower(),
                    "unit_id": None,
                    "unit_label": None,
                    "block": None,
                    "location_status": "common_area",
                }
            )
            target_ids, target_versions = [], []
            changed = True
            continue
        if payload.get(field) != clean:
            changed = True
        payload[field] = clean
    return payload, target_ids, target_versions, changed


def require_complete(command: str, payload: Mapping[str, Any]) -> None:
    """Deterministic completeness rules of the command itself (the ticket API would refuse the same)."""
    if command == "ticket.create":
        problems = []
        if not payload.get("unit_id") and not payload.get("common_area"):
            problems.append("location")
        if not str(payload.get("description", "")).strip():
            problems.append("description")
        if payload.get("category") not in CATEGORIES:
            problems.append("category")
        if payload.get("urgency") not in URGENCIES:
            problems.append("urgency")
        if problems:
            raise PolicyViolation(details={"reason": "missing_required_fields", "fields": problems})


_UNSAFE_TITLE: Final = re.compile(r"[\x00-\x1f]")


def _draft_title(payload: Mapping[str, Any]) -> str:
    for k in (
        "title",
        "neutral_wording",
        "original_text",
        "description",
        "narrative",
        "original_question",
    ):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return _UNSAFE_TITLE.sub(" ", v.strip())[:80]
    return str(payload.get("kind", "AI draft"))


def execute(
    conn: Connection, auth: AuthContext, rt: AiRuntime, spec: CommandSpec, proposal_id: uuid.UUID, row: Mapping[str, Any],
    payload: Mapping[str, Any], external_key: str,
) -> dict[str, Any]:  # fmt: skip
    """Run the command and return its JSON receipt. ``ai.save_draft`` is self-contained; the others go through their port."""
    if spec.name == "ai.save_draft":
        return _save_draft(conn, auth, proposal_id, payload)
    if spec.name == "notice.create_draft" and spec.port not in rt.ports:
        # until the notices module registers its port the draft is kept as the author's own private draft; nothing is published either way
        return _save_draft(conn, auth, proposal_id, payload, via="local_draft_until_notices_module")
    port = rt.ports.get(spec.port or "")
    if port is None:
        raise DependencyUnavailable(
            details={"reason": "module_not_available", "command": spec.name}, retry_after=60
        )  # the module that executes this command is not installed: the proposal stays open
    receipt = port.execute(
        conn, auth.ctx, payload, proposal_id=proposal_id, external_key=external_key
    )
    return {"via": spec.port, **json.loads(json.dumps(receipt, default=str))}


def _save_draft(
    conn: Connection,
    auth: AuthContext,
    proposal_id: uuid.UUID,
    payload: Mapping[str, Any],
    via: str = "ai.save_draft",
) -> dict[str, Any]:
    draft_id = uuid7()
    kind = str(payload.get("kind"))

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text("INSERT INTO ai_drafts (id, society_id, owner_id, kind, title, content, source_proposal_id) VALUES (:id, :s, :o, :k, :t, CAST(:c AS jsonb), :p)"),
            {"id": draft_id, "s": auth.scope.society_id, "o": auth.principal.person_id, "k": kind, "t": _draft_title(payload), "c": json.dumps(payload, ensure_ascii=False), "p": proposal_id},
        )  # fmt: skip
        return MutationResult(draft_id, 1, None, {"kind": kind, "status": "draft"}, {"kind": kind})

    mutation(
        conn,
        auth.ctx,
        operation="ai.draft.save",
        object_type="ai_draft",
        event_type="AIDraftSaved",
        apply=apply,
    )
    return {
        "via": via,
        "draft_id": str(draft_id),
        "kind": kind,
        "saved": True,
        "published": False,
        "sent": False,
    }
