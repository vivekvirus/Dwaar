"""Persistence and orchestration for AI requests, confirmations, feedback and controls.

REQ: AI-SYS-01 (ai_runs: no raw prompts), AI-SYS-04 (proposal object; confirmation binds to the payload hash; execution re-checks role, target
version, budget and idempotency), AI-SYS-06/AT-29 (kill switch, per-feature rollback, budget, fallback), AT-25 (safe diagnostics), AT-26, INV-06,
INV-01, PRD 12.4 (mutation + audit + outbox in one transaction).
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy import Connection, text

from dwaar_ai_gateway import pii
from dwaar_ai_gateway.binding import (
    ConfirmationRejected,
    StoredProposal,
    compute_hash,
    verify_confirmation,
)
from dwaar_ai_gateway.features import LocationDirectory, LocationRef
from dwaar_ai_gateway.guardrails import ForbiddenAutonomousAction, excluded_matches
from dwaar_ai_gateway.pipeline import Availability, GatewayRequest
from dwaar_ai_gateway.types import Caller, GatewayResult, Outcome
from dwaar_common.errors import (
    AlreadyDecided,
    DependencyUnavailable,
    DwaarError,
    InvalidSchema,
    NotAuthorised,
    NotFound,
    PolicyViolation,
    RequestExpired,
    StaleVersion,
)
from dwaar_common.ids import uuid7

from ...core.audit import MutationResult, mutation
from ...core.authz import AuthContext
from . import executors
from .ports import AiRuntime
from .schemas import ConfirmBody, ControlsPut, FeedbackBody, ProposalCreate

log = logging.getLogger("dwaar_api.ai")

#: IST day start in SQL (the society's day, not the server's)
_DAY_START: Final = (
    "(date_trunc('day', now() AT TIME ZONE 'Asia/Kolkata') AT TIME ZONE 'Asia/Kolkata')"
)


# ====================================================================================== caller, availability
def caller_of(auth: AuthContext, language: str) -> Caller:
    s = auth.scope
    return Caller(
        s.society_id,
        auth.principal.person_id,
        s.role,
        society_wide=s.society_wide,
        unit_ids=s.unit_ids,
        language=language,
    )


def feature_state(conn: Connection, society_id: uuid.UUID, feature_id: str) -> dict[str, Any]:
    row = (
        conn.execute(
            text(
                "SELECT state, prompt_version_pin, daily_limit, version FROM ai_feature_controls WHERE society_id = :s AND feature_id = :f"
            ),
            {"s": society_id, "f": feature_id},
        )
        .mappings()
        .first()
    )
    return (
        dict(row)
        if row
        else {"state": "enabled", "prompt_version_pin": None, "daily_limit": None, "version": 0}
    )


def society_switches(conn: Connection, society_id: uuid.UUID) -> dict[str, Any]:
    ctl = (
        conn.execute(
            text(
                "SELECT kill_switch, reason, version FROM ai_society_controls WHERE society_id = :s"
            ),
            {"s": society_id},
        )
        .mappings()
        .first()
    )
    quota = conn.execute(
        text("SELECT ai_requests_per_day FROM society_quotas WHERE society_id = :s"),
        {"s": society_id},
    ).scalar()
    used = conn.execute(
        text(
            f"SELECT count(*) FROM ai_runs WHERE society_id = :s AND model_called AND created_at >= {_DAY_START}"
        ),
        {"s": society_id},  # noqa: S608
    ).scalar_one()
    return {"kill_switch": bool(ctl["kill_switch"]) if ctl else False, "kill_reason": ctl["reason"] if ctl else None,
            "quota_per_day": int(quota or 0), "used_today": int(used), "controls_version": int(ctl["version"]) if ctl else 0}  # fmt: skip


def availability(
    conn: Connection, society_id: uuid.UUID, feature_id: str, uses_model: bool
) -> Availability:
    """Kill switch, per-feature switch and budget for ONE society (ARCH-05). Only optional assistance depends on this; gate, billing, payment
    and security paths never call the AI module, so nothing here can disable them (AT-29)."""
    sw = society_switches(conn, society_id)
    fc = feature_state(conn, society_id, feature_id)
    if sw["kill_switch"]:
        return Availability(False, "kill_switch")
    if fc["state"] == "disabled":
        return Availability(False, "feature_disabled")
    if not uses_model:
        return Availability(True, prompt_pin=fc["prompt_version_pin"])
    if sw["quota_per_day"] <= 0:
        return Availability(False, "not_enabled")
    budget_ok = sw["used_today"] < sw["quota_per_day"]
    if budget_ok and fc["daily_limit"] is not None:
        used_f = conn.execute(
            text(
                f"SELECT count(*) FROM ai_runs WHERE society_id = :s AND feature_id = :f AND model_called AND created_at >= {_DAY_START}"
            ),  # noqa: S608
            {"s": society_id, "f": feature_id},
        ).scalar_one()
        budget_ok = int(used_f) < int(fc["daily_limit"])
    return Availability(True, None, budget_ok, fc["prompt_version_pin"])


def location_directory(conn: Connection, auth: AuthContext) -> LocationDirectory:
    """The units the caller may name: their OWN grants (never society-wide free choice), with the current unit version."""
    if auth.scope.society_wide or not auth.scope.unit_ids:
        return LocationDirectory()
    rows = conn.execute(
        text("SELECT u.id, b.name, u.label, u.version FROM units u JOIN blocks b ON b.society_id = u.society_id AND b.id = u.block_id"
             " WHERE u.id = ANY(:ids) AND u.status = 'active' ORDER BY b.name, u.label"),
        {"ids": sorted(auth.scope.unit_ids, key=lambda i: i.int)},
    ).all()  # fmt: skip
    return LocationDirectory(
        units=[LocationRef(r[0], str(r[1]), str(r[2]), int(r[3])) for r in rows]
    )


# ====================================================================================== create
def _uuid_list(values: Sequence[str]) -> list[uuid.UUID]:
    out = []
    for v in values:
        try:
            out.append(uuid.UUID(v))
        except ValueError:
            continue
    return out


def _insert_run(conn: Connection, auth: AuthContext, res: GatewayResult, purpose: str) -> uuid.UUID:
    run_id = uuid7()
    conn.execute(
        text(
            "INSERT INTO ai_runs (id, society_id, actor_id, actor_role, feature_id, purpose, provider, model, simulation, model_called,"
            " prompt_version, schema_version, source_ids, latency_ms, cost_paise, input_tokens, output_tokens, status, reason, outcome,"
            " input_hash, redaction_counts, diagnostics) VALUES (:id, :s, :actor, :role, :f, :purpose, :provider, :model, :sim, :called,"
            " :pv, :sv, :src, :lat, :cost, :tin, :tout, :status, :reason, :outcome, :ih, CAST(:rc AS jsonb), CAST(:diag AS jsonb))"
        ),
        {
            "id": run_id, "s": auth.scope.society_id, "actor": auth.principal.person_id, "role": auth.scope.role, "f": res.feature_id,
            "purpose": purpose, "provider": res.provider, "model": res.model, "sim": res.simulation, "called": res.model_called,
            "pv": res.prompt_version, "sv": res.schema_version, "src": _uuid_list(res.source_ids), "lat": res.latency_ms,
            "cost": 0 if res.simulation else res.cost_paise, "tin": res.input_tokens, "tout": res.output_tokens, "status": res.status,
            "reason": res.reason, "outcome": res.outcome.value if res.outcome else None, "ih": res.input_hash or None,
            "rc": _json(res.redaction_counts), "diag": _json(res.diagnostics),
        },
    )  # fmt: skip
    return run_id


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, default=str)


def _log_diagnostics(auth: AuthContext, res: GatewayResult) -> None:
    """The SAFE diagnostic of AT-25: feature, codes and counts only. Never the document, the prompt or the model output."""
    for d in res.diagnostics:
        if d.get("severity") == "critical" or d["code"] in {"provider_error", "handler_error"}:
            log.warning(
                "ai safe diagnostic feature=%s code=%s why=%s reason=%s tools_attempted=%s",
                res.feature_id, d["code"], d.get("why") or d.get("kind") or d.get("error", "-"), res.reason, d.get("tool_calls_attempted", 0),
            )  # fmt: skip


def create(
    conn: Connection, auth: AuthContext, rt: AiRuntime, body: ProposalCreate
) -> dict[str, Any]:
    gw = rt.gateway
    feature_id = body.feature_id
    hits = excluded_matches([feature_id, *body.inputs.keys()])
    if hits:  # PRD 11.5: not an unknown feature but a refusal that names the rule
        raise PolicyViolation(
            details={"reason": "excluded_ai_cannot_be_enabled", "capability": hits[0][1]}
        )
    handler = gw.handlers.get(feature_id)
    if handler is None:
        raise NotFound()
    spec = handler.spec
    if spec.id == "AI-R02" and isinstance(body.inputs.get("unit_id"), str):
        try:
            unit = uuid.UUID(body.inputs["unit_id"])
        except ValueError:
            raise NotFound() from None
        if not auth.scope.covers_unit(unit):
            raise NotFound()  # a unit the caller does not hold looks like a unit that does not exist
    caller = caller_of(auth, body.language)
    av = availability(conn, auth.scope.society_id, feature_id, spec.uses_model)
    sources: Sequence[Any] = ()
    reason_override: str | None = None
    if spec.id in {"AI-F01", "AI-G08"} and spec.available and av.allowed:
        port = rt.sources.get(spec.id)
        if port is None:
            reason_override = "data_source_not_available"  # the ticket / shift module is not installed: the ordinary screens remain
        else:
            sources = _fetch_sources(spec.id, port, caller, body.inputs)
    locations = location_directory(conn, auth) if spec.id == "AI-R02" else None
    if reason_override:
        res = GatewayResult("unavailable", spec.id, "none", reason=reason_override)
        res.fallback = {
            "kind": "ordinary_form",
            "feature_id": spec.id,
            "reason": reason_override,
            "blocks_user": False,
            "upsell": False,
            "message_key": "ai.fallback.ordinary_path",
        }
        res.outcome = Outcome.ABSTAINED
    else:
        res = gw.run(GatewayRequest(feature_id, caller, body.inputs, av, sources, locations))
    if res.status == "rejected":
        if res.reason == "invalid_input":
            raise InvalidSchema.for_fields(
                [(f["field"], f["problem"]) for f in (res.answer or {}).get("fields", [])]
            )
        if res.reason == "role_not_allowed_for_feature":
            raise NotAuthorised()
        raise NotFound()
    run_id = _insert_run(conn, auth, res, spec.purpose)
    _log_diagnostics(auth, res)
    out: dict[str, Any] = {
        "request_id": str(auth.request_id), "status": res.status, "run_id": str(run_id), "feature_id": res.feature_id, "kind": res.kind,
        "simulation": res.simulation, "reason": res.reason, "fallback": res.fallback, "labels": res.labels.as_dict() if res.labels else None,
        "answer": res.answer, "proposal": None,
    }  # fmt: skip
    if res.proposal is not None:
        out["proposal"] = _store_proposal(conn, auth, run_id, res, spec.id)
    return out


def _fetch_sources(
    feature_id: str, port: Any, caller: Caller, inputs: Mapping[str, Any]
) -> Sequence[Any]:
    try:
        if feature_id == "AI-F01":
            ids = inputs.get("ticket_ids")
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                return ()
            return port.tickets(caller, ids)  # type: ignore[no-any-return]
        shift = inputs.get("shift_id")
        return port.events(caller, shift) if isinstance(shift, str) else ()
    except Exception:  # noqa: BLE001 - a broken data module must not break the ordinary path
        log.warning("ai source port failed feature=%s", feature_id)
        return ()


def _store_proposal(
    conn: Connection, auth: AuthContext, run_id: uuid.UUID, res: GatewayResult, feature_id: str
) -> dict[str, Any]:
    p = res.proposal
    assert p is not None
    assert res.labels is not None
    labels_json = _json(res.labels.as_dict())
    if (
        p.risk_class.value == "X"
    ):  # unreachable by construction; the database CHECK is the third wall
        raise ForbiddenAutonomousAction(p.command, "class_x")
    proposal_id = uuid7()
    digest = compute_hash(
        society_id=auth.scope.society_id, actor_id=auth.principal.person_id, command=p.command, risk_class=p.risk_class.value,
        payload=p.payload, target_ids=p.target_ids, target_versions=p.target_versions, expires_at=p.expires_at,
    )  # fmt: skip

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "INSERT INTO action_proposals (id, society_id, ai_run_id, actor_id, actor_role, feature_id, intent, command, risk_class, payload,"
                " payload_hash, target_ids, target_versions, evidence, missing_fields, estimated_effect, labels, expires_at)"
                " VALUES (:id, :s, :run, :actor, :role, :f, :intent, :cmd, :rc, CAST(:payload AS jsonb), :hash, :tids, :tvs,"
                " CAST(:ev AS jsonb), :missing, :eff, CAST(:labels AS jsonb), :exp)"
            ),
            {
                "id": proposal_id, "s": auth.scope.society_id, "run": run_id, "actor": auth.principal.person_id, "role": auth.scope.role,
                "f": feature_id, "intent": p.intent, "cmd": p.command, "rc": p.risk_class.value, "payload": _json(p.payload), "hash": digest,
                "tids": list(p.target_ids), "tvs": list(p.target_versions), "ev": _json(p.evidence), "missing": p.missing_fields,
                "eff": p.estimated_effect, "labels": labels_json, "exp": p.expires_at,
            },
        )  # fmt: skip
        c.execute(
            text("UPDATE ai_runs SET proposal_id = :p, version = version + 1 WHERE id = :r"),
            {"p": proposal_id, "r": run_id},
        )
        return MutationResult(
            object_id=proposal_id, object_version=1, after={"feature_id": feature_id, "command": p.command, "risk_class": p.risk_class.value, "state": "proposed", "targets": len(p.target_ids)},
            event_payload={"feature_id": feature_id, "command": p.command, "risk_class": p.risk_class.value, "ai_run_id": str(run_id)},
        )  # fmt: skip

    mutation(
        conn,
        auth.ctx,
        operation="ai.proposal.create",
        object_type="action_proposal",
        event_type="AIProposalCreated",
        apply=apply,
    )
    return proposal_view(
        {
            "id": proposal_id,
            "feature_id": feature_id,
            "intent": p.intent,
            "command": p.command,
            "risk_class": p.risk_class.value,
            "payload": p.payload,
            "payload_hash": digest,
            "target_ids": list(p.target_ids),
            "target_versions": list(p.target_versions),
            "evidence": p.evidence,
            "missing_fields": p.missing_fields,
            "estimated_effect": p.estimated_effect,
            "expires_at": p.expires_at,
            "state": "proposed",
            "ai_run_id": run_id,
            "edited": False,
            "result": None,
            "version": 1,
        }
    )


def proposal_view(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]), "ai_run_id": str(row["ai_run_id"]), "feature_id": row["feature_id"], "intent": row["intent"], "command": row["command"],
        "risk_class": row["risk_class"], "payload": row["payload"], "payload_hash": row["payload_hash"],
        "target_ids": [str(t) for t in row["target_ids"]], "target_versions": list(row["target_versions"]), "evidence": row["evidence"],
        "missing_fields": list(row["missing_fields"]), "estimated_effect": row["estimated_effect"],
        "expires_at": row["expires_at"].astimezone(dt.UTC).isoformat() if isinstance(row["expires_at"], dt.datetime) else row["expires_at"],
        "state": row["state"], "edited": bool(row["edited"]), "result": row["result"], "version": row["version"],
    }  # fmt: skip


_PROPOSAL_COLS: Final = (
    "id, ai_run_id, actor_id, actor_role, feature_id, intent, command, risk_class, payload, payload_hash, target_ids, target_versions, evidence,"
    " missing_fields, estimated_effect, expires_at, state, edited, result, version, society_id"
)


def get_proposal(
    conn: Connection, auth: AuthContext, proposal_id: uuid.UUID, *, lock: bool = False
) -> dict[str, Any]:
    row = (
        conn.execute(
            text(
                f"SELECT {_PROPOSAL_COLS} FROM action_proposals WHERE id = :id"
                + (" FOR UPDATE" if lock else "")
            ),
            {"id": proposal_id},  # noqa: S608
        )
        .mappings()
        .first()
    )
    if row is None or row["actor_id"] != auth.principal.person_id:
        raise NotFound()  # another person's proposal is indistinguishable from none
    return dict(row)


def list_proposals(
    conn: Connection, auth: AuthContext, state: str | None, limit: int
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(f"SELECT {_PROPOSAL_COLS} FROM action_proposals WHERE actor_id = :a AND (CAST(:st AS text) IS NULL OR state = :st)"  # noqa: S608
             " ORDER BY created_at DESC, id DESC LIMIT :lim"),
        {"a": auth.principal.person_id, "st": state, "lim": limit},
    ).mappings()  # fmt: skip
    return [proposal_view(dict(r)) for r in rows]


# ====================================================================================== confirm
def _rejection(code: str) -> DwaarError:
    """Map a pure re-validation failure to its PRD 12.2 error. Every stale case says a NEW proposal is required (AT-26)."""
    if code == "hash_mismatch":
        return PolicyViolation(
            details={"reason": "payload_hash_mismatch", "new_proposal_required": True}
        )
    if code == "expired":
        return RequestExpired(details={"new_proposal_required": True})
    if code == "already_decided":
        return AlreadyDecided()
    if code == "wrong_actor":
        return NotFound()
    if code in {"role_not_allowed", "approver_required"}:
        return NotAuthorised()
    reason = "role_changed" if code == "role_changed" else "target_changed"
    return StaleVersion(details={"reason": reason, "new_proposal_required": True})


def _target_versions_now(
    conn: Connection,
    rt: AiRuntime,
    caller: Caller,
    command: str,
    feature_id: str,
    ids: Sequence[uuid.UUID],
) -> list[int]:
    """The CURRENT version of every target, read fresh. A target that is gone or archived reads as -1, which never equals a stored version."""
    if not ids:
        return []
    if command == "ticket.create":
        fetched = conn.execute(
            text("SELECT id, version FROM units WHERE id = ANY(:ids) AND status = 'active'"),
            {"ids": list(ids)},
        ).all()
        rows: dict[uuid.UUID, int] = {r[0]: int(r[1]) for r in fetched}
        return [int(rows.get(i, -1)) for i in ids]
    port = rt.sources.get(feature_id)
    if command == "ticket.apply_triage" and port is not None:
        docs = {
            d.source_id: d.version
            for d in port.tickets(caller, [str(i) for i in ids])
            if d.society_id == caller.society_id
        }
        return [int(docs.get(str(i), -1)) for i in ids]
    return [-1 for _ in ids]


def confirm(
    conn: Connection, auth: AuthContext, rt: AiRuntime, proposal_id: uuid.UUID, body: ConfirmBody
) -> dict[str, Any]:
    row = get_proposal(conn, auth, proposal_id, lock=True)
    spec = rt.gateway.commands.get(row["command"])
    if spec is None:
        raise NotFound()
    try:
        rt.gateway.commands.require_executable(
            row["command"]
        )  # class X / unknown never executes, whatever is stored
    except ForbiddenAutonomousAction:
        raise PolicyViolation(details={"reason": "class_x_forbidden_autonomous_action"}) from None
    handler = rt.gateway.handlers.get(row["feature_id"])
    if handler is None or auth.scope.role not in handler.spec.roles:
        raise NotAuthorised()  # the role held NOW may no longer use this feature
    av = availability(conn, auth.scope.society_id, row["feature_id"], handler.spec.uses_model)
    if (
        not av.allowed
    ):  # kill switch / rollback also stop open proposals; the ordinary form is the path
        raise PolicyViolation(
            details={"reason": av.reason or "ai_disabled", "fallback": "ordinary_form"}
        )
    caller = caller_of(auth, "en")
    now_versions = _target_versions_now(
        conn, rt, caller, row["command"], row["feature_id"], row["target_ids"]
    )
    stored = StoredProposal(
        society_id=auth.scope.society_id, actor_id=row["actor_id"], actor_role=row["actor_role"], command=row["command"], risk_class=row["risk_class"],
        payload=row["payload"], target_ids=row["target_ids"], target_versions=row["target_versions"], expires_at=row["expires_at"],
        state=row["state"], payload_hash=row["payload_hash"],
    )  # fmt: skip
    try:
        verify_confirmation(
            stored, presented_hash=body.payload_hash, now=rt.now(), confirmer_id=auth.principal.person_id, confirmer_role=auth.scope.role,
            allowed_roles=spec.allowed_roles, approver_roles=spec.approver_roles, current_target_versions=now_versions,
        )  # fmt: skip
    except ConfirmationRejected as exc:
        raise _rejection(exc.code) from None
    if body.expected_target_versions is not None and list(body.expected_target_versions) != list(
        row["target_versions"]
    ):
        raise StaleVersion(details={"reason": "target_changed", "new_proposal_required": True})
    # budget re-check (AI-SYS-04): confirming an existing draft makes NO model call and costs nothing, so an exhausted budget does not block
    # the user's own, already-paid-for draft (declining or exhausting AI never reduces service); kill switch and feature switch were checked above.
    final_payload, target_ids, target_versions, edited = executors.apply_edits(
        conn, auth, row, body.edits, now_versions
    )
    executors.require_complete(row["command"], final_payload)
    external_key = f"ai-proposal-{proposal_id}"
    receipt = executors.execute(conn, auth, rt, spec, proposal_id, row, final_payload, external_key)
    outcome = Outcome.EDITED if edited else Outcome.ACCEPTED

    def apply(c: Connection) -> MutationResult:
        c.execute(
            text(
                "UPDATE action_proposals SET state = 'confirmed', confirmed_by = :by, confirmed_role = :role, confirmed_at = now(), edited = :ed,"
                " final_payload = CAST(:fp AS jsonb), result = CAST(:res AS jsonb), version = version + 1 WHERE id = :id AND state = 'proposed'"
            ),
            {"by": auth.principal.person_id, "role": auth.scope.role, "ed": edited, "fp": _json(final_payload), "res": _json(receipt), "id": proposal_id},
        )  # fmt: skip
        c.execute(
            text(
                "UPDATE ai_runs SET outcome = :o, decided_at = now(), version = version + 1 WHERE id = :r"
            ),
            {"o": outcome.value, "r": row["ai_run_id"]},
        )
        return MutationResult(
            object_id=proposal_id, object_version=int(row["version"]) + 1,
            before={"state": "proposed"}, after={"state": "confirmed", "edited": edited, "command": row["command"]},
            event_payload={"feature_id": row["feature_id"], "command": row["command"], "risk_class": row["risk_class"], "edited": edited, "ai_run_id": str(row["ai_run_id"])},
        )  # fmt: skip

    mutation(
        conn,
        auth.ctx,
        operation="ai.proposal.confirm",
        object_type="action_proposal",
        event_type="AIProposalConfirmed",
        apply=apply,
    )
    return {
        "request_id": str(auth.request_id), "proposal_id": str(proposal_id), "state": "confirmed", "command": row["command"], "outcome": outcome.value,
        "edited": edited, "target_ids": [str(t) for t in target_ids], "target_versions": list(target_versions), "result": receipt,
        "effect": row["estimated_effect"],
    }  # fmt: skip


# ====================================================================================== feedback
def feedback(conn: Connection, auth: AuthContext, body: FeedbackBody) -> dict[str, Any]:
    try:
        run_id = uuid.UUID(body.run_id)
    except ValueError:
        raise NotFound() from None
    run = (
        conn.execute(
            text("SELECT id, actor_id, proposal_id FROM ai_runs WHERE id = :id FOR UPDATE"),
            {"id": run_id},
        )
        .mappings()
        .first()
    )
    if run is None or run["actor_id"] != auth.principal.person_id:
        raise NotFound()
    proposal = None
    if run["proposal_id"] is not None:
        proposal = (
            conn.execute(
                text("SELECT id, state, version FROM action_proposals WHERE id = :p FOR UPDATE"),
                {"p": run["proposal_id"]},
            )
            .mappings()
            .first()
        )
    if proposal is not None and proposal["state"] == "proposed" and body.outcome != "rejected":
        raise PolicyViolation(
            details={"reason": "confirm_the_proposal_instead", "proposal_id": str(proposal["id"])}
        )
    if conn.execute(
        text("SELECT 1 FROM ai_feedback WHERE ai_run_id = :r AND actor_id = :a"),
        {"r": run_id, "a": auth.principal.person_id},
    ).first():
        raise AlreadyDecided()
    redacted, counts = None, {}
    if body.correction:
        vault = pii.TokenVault()
        red = pii.redact(body.correction, vault)
        redacted, counts = (
            red.text,
            vault.counts,
        )  # the vault is dropped: the tokens can never be re-identified
    fid = uuid7()
    conn.execute(
        text("INSERT INTO ai_feedback (id, society_id, ai_run_id, actor_id, outcome, correction_redacted, redaction_counts)"
             " VALUES (:id, :s, :r, :a, :o, :c, CAST(:rc AS jsonb))"),
        {"id": fid, "s": auth.scope.society_id, "r": run_id, "a": auth.principal.person_id, "o": body.outcome, "c": redacted, "rc": _json(counts)},
    )  # fmt: skip
    rejected_proposal = False
    if body.outcome == "rejected":
        conn.execute(
            text(
                "UPDATE ai_runs SET outcome = 'rejected', decided_at = now(), version = version + 1 WHERE id = :r AND outcome IS NULL"
            ),
            {"r": run_id},
        )
        if proposal is not None and proposal["state"] == "proposed":

            def apply(c: Connection) -> MutationResult:
                c.execute(
                    text(
                        "UPDATE action_proposals SET state = 'rejected', version = version + 1 WHERE id = :p AND state = 'proposed'"
                    ),
                    {"p": proposal["id"]},
                )
                return MutationResult(object_id=proposal["id"], object_version=int(proposal["version"]) + 1, before={"state": "proposed"}, after={"state": "rejected"},
                                      event_payload={"ai_run_id": str(run_id)})  # fmt: skip

            mutation(
                conn,
                auth.ctx,
                operation="ai.proposal.reject",
                object_type="action_proposal",
                event_type="AIProposalRejected",
                apply=apply,
            )
            rejected_proposal = True
    return {"request_id": str(auth.request_id), "feedback_id": str(fid), "stored": True, "proposal_rejected": rejected_proposal,
            "feeds_evaluation": True, "correction_redacted": redacted is not None}  # fmt: skip


# ====================================================================================== controls, status, runs
def put_controls(
    conn: Connection, auth: AuthContext, rt: AiRuntime, body: ControlsPut
) -> dict[str, Any]:
    for fid in body.features:
        hits = excluded_matches([fid])
        if hits:
            raise PolicyViolation(
                details={"reason": "excluded_ai_cannot_be_enabled", "capability": hits[0][1]}
            )
        if fid not in rt.gateway.handlers:
            raise NotFound()
    sid = auth.scope.society_id
    changes: dict[str, Any] = {}
    if body.kill_switch is not None:
        cur = (
            conn.execute(
                text(
                    "SELECT id, kill_switch, version FROM ai_society_controls WHERE society_id = :s FOR UPDATE"
                ),
                {"s": sid},
            )
            .mappings()
            .first()
        )

        def apply_kill(c: Connection) -> MutationResult:
            if cur is None:
                oid = uuid7()
                c.execute(text("INSERT INTO ai_society_controls (id, society_id, kill_switch, reason, updated_by) VALUES (:id, :s, :k, :r, :u)"),
                          {"id": oid, "s": sid, "k": body.kill_switch, "r": body.reason, "u": auth.principal.person_id})  # fmt: skip
                return MutationResult(
                    oid,
                    1,
                    None,
                    {"kill_switch": body.kill_switch},
                    {"kill_switch": bool(body.kill_switch)},
                )
            c.execute(text("UPDATE ai_society_controls SET kill_switch = :k, reason = :r, updated_by = :u, updated_at = now(), version = version + 1 WHERE id = :id"),
                      {"k": body.kill_switch, "r": body.reason, "u": auth.principal.person_id, "id": cur["id"]})  # fmt: skip
            return MutationResult(
                cur["id"],
                int(cur["version"]) + 1,
                {"kill_switch": cur["kill_switch"]},
                {"kill_switch": body.kill_switch},
                {"kill_switch": bool(body.kill_switch)},
            )

        mutation(
            conn,
            auth.ctx,
            operation="ai.controls.kill_switch",
            object_type="ai_society_controls",
            event_type="AIControlsChanged",
            apply=apply_kill,
            reason=body.reason,
        )
        changes["kill_switch"] = body.kill_switch
    for fid, fc in body.features.items():
        if (
            fc.prompt_version_pin is not None
            and fc.prompt_version_pin not in rt.gateway.prompts.versions(fid)
        ):
            raise InvalidSchema.for_fields(
                [(f"features.{fid}.prompt_version_pin", "unknown_prompt_version")]
            )
        cur = conn.execute(text("SELECT id, state, prompt_version_pin, daily_limit, version FROM ai_feature_controls WHERE society_id = :s AND feature_id = :f FOR UPDATE"),
                           {"s": sid, "f": fid}).mappings().first()  # fmt: skip
        new_state = fc.state or (cur["state"] if cur else "enabled")
        pin = (
            None
            if fc.clear_prompt_version_pin
            else (fc.prompt_version_pin or (cur["prompt_version_pin"] if cur else None))
        )
        limit = (
            None
            if fc.clear_daily_limit
            else (
                fc.daily_limit
                if fc.daily_limit is not None
                else (cur["daily_limit"] if cur else None)
            )
        )

        def apply_feature(
            c: Connection,
            fid: str = fid,
            cur: Any = cur,
            new_state: str = new_state,
            pin: Any = pin,
            limit: Any = limit,
        ) -> MutationResult:
            if cur is None:
                oid = uuid7()
                c.execute(text("INSERT INTO ai_feature_controls (id, society_id, feature_id, state, prompt_version_pin, daily_limit, reason, updated_by)"
                               " VALUES (:id, :s, :f, :st, :p, :l, :r, :u)"),
                          {"id": oid, "s": sid, "f": fid, "st": new_state, "p": pin, "l": limit, "r": body.reason, "u": auth.principal.person_id})  # fmt: skip
                return MutationResult(
                    oid,
                    1,
                    None,
                    {
                        "feature_id": fid,
                        "state": new_state,
                        "prompt_version_pin": pin,
                        "daily_limit": limit,
                    },
                    {"feature_id": fid, "state": new_state},
                )
            c.execute(text("UPDATE ai_feature_controls SET state = :st, prompt_version_pin = :p, daily_limit = :l, reason = :r, updated_by = :u, updated_at = now(), version = version + 1 WHERE id = :id"),
                      {"st": new_state, "p": pin, "l": limit, "r": body.reason, "u": auth.principal.person_id, "id": cur["id"]})  # fmt: skip
            return MutationResult(cur["id"], int(cur["version"]) + 1, {"state": cur["state"], "prompt_version_pin": cur["prompt_version_pin"], "daily_limit": cur["daily_limit"]},
                                  {"feature_id": fid, "state": new_state, "prompt_version_pin": pin, "daily_limit": limit}, {"feature_id": fid, "state": new_state})  # fmt: skip

        mutation(
            conn,
            auth.ctx,
            operation="ai.controls.feature",
            object_type="ai_feature_controls",
            event_type="AIControlsChanged",
            apply=apply_feature,
            reason=body.reason,
        )
        changes.setdefault("features", {})[fid] = {
            "state": new_state,
            "prompt_version_pin": pin,
            "daily_limit": limit,
        }
    return {
        "request_id": str(auth.request_id),
        "applied": changes,
        "takes_effect": "immediately; no app update or deploy is needed",
    }


def status(conn: Connection, auth: AuthContext, rt: AiRuntime) -> dict[str, Any]:
    sid = auth.scope.society_id
    sw = society_switches(conn, sid)
    lat = conn.execute(
        text("SELECT count(*) AS n, percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50, percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,"
             " count(*) FILTER (WHERE simulation) AS sim FROM (SELECT latency_ms, simulation FROM ai_runs WHERE society_id = :s AND model_called ORDER BY created_at DESC LIMIT 200) t"),
        {"s": sid},
    ).mappings().one()  # fmt: skip
    features = []
    for h in rt.gateway.features():
        s = h.spec
        fc = feature_state(conn, sid, s.id)
        features.append({"id": s.id, "name": s.name, "risk_class": s.risk_class.value, "uses_model": s.uses_model, "available": s.available,
                         "unavailable_reason": s.unavailable_reason, "state": fc["state"], "prompt_version_pin": fc["prompt_version_pin"], "daily_limit": fc["daily_limit"]})  # fmt: skip
    return {
        "request_id": str(auth.request_id), "kill_switch": sw["kill_switch"], "kill_reason": sw["kill_reason"],
        "budget": {"quota_per_day": sw["quota_per_day"], "used_today": sw["used_today"], "remaining": max(0, sw["quota_per_day"] - sw["used_today"]),
                   "exhausted": sw["quota_per_day"] > 0 and sw["used_today"] >= sw["quota_per_day"], "set_by": "PUT /v1/societies/{id}/quotas (ai_requests_per_day)"},
        "latency_ms": {"samples": int(lat["n"]), "p50": None if lat["p50"] is None else int(lat["p50"]), "p95": None if lat["p95"] is None else int(lat["p95"]),
                       "simulated_samples": int(lat["sim"]), "slo_p95_ms": 15000, "note": "measured on this society's last runs; simulated runs describe the simulator, not a model"},
        "features": features, "declining_ai_reduces_service": False, "upsell": False,
    }  # fmt: skip


def list_runs(
    conn: Connection,
    auth: AuthContext,
    limit: int,
    before: uuid.UUID | None,
    feature_id: str | None,
) -> dict[str, Any]:
    rows = conn.execute(
        text("SELECT id, actor_role, feature_id, purpose, provider, model, simulation, model_called, prompt_version, schema_version, array_length(source_ids, 1) AS sources,"
             " latency_ms, cost_paise, status, reason, outcome, redaction_counts, diagnostics, proposal_id, created_at FROM ai_runs"
             " WHERE society_id = :s AND (CAST(:b AS uuid) IS NULL OR id < :b) AND (CAST(:f AS text) IS NULL OR feature_id = :f) ORDER BY id DESC LIMIT :lim"),
        {"s": auth.scope.society_id, "b": before, "f": feature_id, "lim": limit + 1},
    ).mappings().all()  # fmt: skip
    page = rows[:limit]
    items = []
    for r in page:
        d = dict(r)
        d["id"], d["proposal_id"] = (
            str(d["id"]),
            str(d["proposal_id"]) if d["proposal_id"] else None,
        )
        d["created_at"] = d["created_at"].astimezone(dt.UTC).isoformat()
        d["sources"] = d["sources"] or 0
        items.append(d)
    return {"items": items, "next_before": items[-1]["id"] if len(rows) > limit and items else None}


def list_drafts(conn: Connection, auth: AuthContext, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("SELECT id, kind, title, content, source_proposal_id, status, created_at FROM ai_drafts WHERE owner_id = :o AND status = 'draft' ORDER BY created_at DESC, id DESC LIMIT :l"),
        {"o": auth.principal.person_id, "l": limit},
    ).mappings()  # fmt: skip
    return [{"id": str(r["id"]), "kind": r["kind"], "title": r["title"], "content": r["content"], "source_proposal_id": str(r["source_proposal_id"]),
             "status": r["status"], "created_at": r["created_at"].astimezone(dt.UTC).isoformat()} for r in rows]  # fmt: skip


_ = DependencyUnavailable
