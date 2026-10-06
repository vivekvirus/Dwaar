"""Database guards of ai_runs, action_proposals, ai_drafts, ai_feedback and the control tables (migrations 0700-0702; PRD 8.2, ARCH-01, DB-02)."""

from __future__ import annotations

import json

import pytest
from psycopg import errors

from tests.integration.ai._support import AW

pytestmark = pytest.mark.req("AI-SYS-01", "AI-SYS-04", "ARCH-01")

AI_TABLES = (
    "ai_runs",
    "action_proposals",
    "ai_drafts",
    "ai_feedback",
    "ai_society_controls",
    "ai_feature_controls",
)


@pytest.fixture
def seeded(aw: AW) -> AW:
    aw.set_quota(100)
    owner = aw.person("owner1", unit="A-101", kind="owner")
    aw.draft(owner, "AI-R07", {"text": "hello neighbours", "target_language": "hi"})
    aw.call(
        aw.vw.secretary,
        "PUT",
        "/v1/ai/controls",
        json={"kill_switch": False, "features": {"AI-R07": {"daily_limit": 5}}},
    )
    return aw


def test_every_ai_table_forces_row_level_security_with_the_standard_policy_and_the_common_columns(
    seeded: AW,
) -> None:
    for t in AI_TABLES:
        rls, force = seeded.rows(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s", (t,)
        )[0]
        assert rls and force, t
        policies = {
            r[0]
            for r in seeded.rows(
                "SELECT polname FROM pg_policy WHERE polrelid = %s::regclass", (t,)
            )
        }
        assert "dwaar_society_isolation" in policies, t
        cols = {
            r[0]
            for r in seeded.rows(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s", (t,)
            )
        }
        assert {"society_id", "retention_class", "legal_hold_id"} <= cols, t
        assert seeded.rows(
            "SELECT has_table_privilege('dwaar_app', %s, 'DELETE'), has_table_privilege('dwaar_worker', %s, 'DELETE')",
            (t, t),
        ) == [(False, False)], t


def test_missing_or_foreign_context_sees_zero_rows(seeded: AW) -> None:
    db = seeded.vw.idh.db
    for t in AI_TABLES:
        with db.app_conn() as conn:
            assert conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] == 0, (
                t
            )  # no society context: nothing
        with db.app_conn(seeded.other.id) as conn:
            assert conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] == 0, (
                t
            )  # another society: nothing
    with db.app_conn(seeded.soc.id) as conn:
        assert conn.execute("SELECT count(*) FROM ai_runs").fetchone()[0] == 1
    with pytest.raises(errors.InsufficientPrivilege), db.app_conn(seeded.other.id) as conn:
        conn.execute(
            "INSERT INTO ai_runs (society_id) VALUES (%s)", (seeded.soc.id,)
        )  # also column grants: id/columns not null; refused either way
    with (
        pytest.raises(
            (errors.InsufficientPrivilege, errors.NotNullViolation, errors.CheckViolation)
        ),
        db.app_conn(seeded.other.id) as conn,
    ):
        conn.execute(
            "INSERT INTO ai_runs (society_id, actor_id, actor_role, feature_id, purpose, provider, model, simulation, model_called, prompt_version, schema_version, latency_ms, status)"
            " SELECT %s, id, 'x', 'AI-R07', 'p', 'p', 'm', true, false, 'v', '1', 0, 'ok' FROM iam.persons LIMIT 1",
            (seeded.soc.id,),
        )


def test_class_x_and_forbidden_domain_commands_cannot_be_stored_at_all(seeded: AW) -> None:
    (row,) = seeded.rows(
        "SELECT society_id, ai_run_id, actor_id, actor_role, feature_id, intent, payload_hash, labels, expires_at FROM action_proposals LIMIT 1"
    )
    base = row
    sql = (
        "INSERT INTO action_proposals (society_id, ai_run_id, actor_id, actor_role, feature_id, intent, command, risk_class, payload, payload_hash, labels, expires_at)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '{}'::jsonb, %s, '{}'::jsonb, %s)"
    )

    def attempt(command: str, risk: str) -> None:
        # a fresh run per attempt: the (society, run) pair is unique
        with seeded.vw.idh.db.admin_conn() as conn:
            run = conn.execute("SELECT id FROM ai_runs LIMIT 1").fetchone()[0]
            conn.execute(
                "DELETE FROM action_proposals"
            )  # admin only: simulate a clean slate for the unique run constraint
            conn.execute(
                sql,
                (base[0], run, base[2], base[3], base[4], base[5], command, risk, base[6], base[8]),
            )

    with pytest.raises(errors.CheckViolation, match="risk_class"):
        attempt("ai.save_draft", "X")  # class X is not storable
    for forbidden in (
        "gate.open",
        "gate.allow_entry",
        "payment.execute",
        "payment.approve",
        "vote.cast",
        "export.personal_data",
        "rights.restrict",
        "tax.file",
        "journal.post",
        "bill.release",
        "fine.levy",
        "service.suspend",
        "access.grant",
        "settlement.release",
        "ledger.post",
    ):
        with pytest.raises(errors.CheckViolation, match="no_forbidden_domain"):
            attempt(forbidden, "B")
    attempt("ai.save_draft", "B")  # a legitimate command is accepted (the harness itself works)


def test_a_stored_proposal_is_immutable_and_a_decided_one_is_final(seeded: AW) -> None:
    db = seeded.vw.idh.db
    sid = seeded.soc.id
    (pid,) = seeded.rows("SELECT id FROM action_proposals")[0]
    for column, value in (
        ("command", "'gate.open'"),
        ("payload", "'{}'::jsonb"),
        ("payload_hash", "'sha256:' || repeat('0', 64)"),
        ("target_ids", "'{}'"),
        ("risk_class", "'C'"),
        ("actor_id", "actor_id"),
        ("expires_at", "now()"),
    ):
        with pytest.raises(errors.InsufficientPrivilege), db.app_conn(sid) as conn:
            conn.execute(f"UPDATE action_proposals SET {column} = {value} WHERE id = %s", (pid,))
    with pytest.raises(errors.InsufficientPrivilege), db.app_conn(sid) as conn:
        conn.execute("DELETE FROM action_proposals WHERE id = %s", (pid,))
    with pytest.raises(errors.CheckViolation, match="decision_shape"), db.admin_conn() as conn:
        conn.execute(
            "UPDATE action_proposals SET state = 'confirmed'"
        )  # 'confirmed' needs who, when, role and receipt together
    with db.app_conn(sid) as conn:  # the decision columns can move once ...
        conn.execute(
            "UPDATE action_proposals SET state = 'rejected', version = version + 1 WHERE id = %s",
            (pid,),
        )
    with pytest.raises(errors.CheckViolation, match="already rejected"), db.app_conn(sid) as conn:
        conn.execute(
            "UPDATE action_proposals SET state = 'proposed' WHERE id = %s", (pid,)
        )  # ... and never back
    with pytest.raises(errors.CheckViolation), db.app_conn(sid) as conn:
        conn.execute("UPDATE action_proposals SET state = 'confirmed' WHERE id = %s", (pid,))


def test_ai_runs_can_only_have_their_outcome_updated_and_never_deleted(seeded: AW) -> None:
    db = seeded.vw.idh.db
    sid = seeded.soc.id
    (rid,) = seeded.rows("SELECT id FROM ai_runs")[0]
    for column, value in (
        ("model", "'x'"),
        ("cost_paise", "5"),
        ("input_hash", "NULL"),
        ("diagnostics", "'[]'::jsonb"),
        ("simulation", "false"),
        ("prompt_version", "'v9'"),
    ):
        with pytest.raises(errors.InsufficientPrivilege), db.app_conn(sid) as conn:
            conn.execute(f"UPDATE ai_runs SET {column} = {value} WHERE id = %s", (rid,))
    with db.app_conn(sid) as conn:
        conn.execute(
            "UPDATE ai_runs SET outcome = 'rejected', decided_at = now() WHERE id = %s", (rid,)
        )
    with pytest.raises(errors.CheckViolation), db.app_conn(sid) as conn:
        conn.execute("UPDATE ai_runs SET outcome = 'maybe' WHERE id = %s", (rid,))
    with pytest.raises(errors.InsufficientPrivilege), db.app_conn(sid) as conn:
        conn.execute("DELETE FROM ai_runs WHERE id = %s", (rid,))
    with pytest.raises(errors.CheckViolation, match="simulation_cost"), db.admin_conn() as conn:
        conn.execute(
            "UPDATE ai_runs SET cost_paise = 5"
        )  # a simulator run can never carry a cost: nothing was bought


def test_ai_runs_has_no_column_that_could_hold_a_raw_prompt(seeded: AW) -> None:
    cols = {
        r[0]: r[1]
        for r in seeded.rows(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'ai_runs'"
        )
    }
    assert not {
        c
        for c in cols
        if any(
            w in c
            for w in (
                "prompt_text",
                "input_text",
                "raw",
                "body",
                "content",
                "message",
                "response",
                "output",
            )
        )
    } - {"output_tokens"}
    text_cols = {c for c, t in cols.items() if t == "text"}
    assert text_cols <= {
        "actor_role",
        "feature_id",
        "purpose",
        "provider",
        "model",
        "prompt_version",
        "schema_version",
        "status",
        "reason",
        "outcome",
        "input_hash",
        "retention_class",
    }
    (diag,) = seeded.rows("SELECT diagnostics::text FROM ai_runs")[0]
    assert all(
        set(d)
        <= {
            "code",
            "severity",
            "count",
            "reasons",
            "flags",
            "segment",
            "stage",
            "error",
            "kind",
            "why",
            "detail",
            "tool_calls_attempted",
            "fields",
        }
        for d in json.loads(diag)
    )


def test_drafts_are_owner_private_through_the_api_because_the_platform_allows_only_society_policies(
    seeded: AW,
) -> None:
    """The core catalog guard allows only app.society_id in policies, so privacy of a draft inside the society is the API's job (owner filter)."""
    owner = seeded.people["owner1"]
    other = seeded.person("owner2", unit="A-102", kind="owner")
    (pid,) = seeded.rows("SELECT id FROM action_proposals")[0]
    seeded.confirm(
        owner,
        {
            "id": str(pid),
            "payload_hash": seeded.rows("SELECT payload_hash FROM action_proposals")[0][0],
        },
    )
    assert len(seeded.call(owner, "GET", "/v1/ai/drafts").json()["items"]) == 1
    for who in (other, seeded.vw.secretary):
        assert seeded.call(who, "GET", "/v1/ai/drafts").json()["items"] == []
    assert {
        r[0]
        for r in seeded.rows("SELECT polname FROM pg_policy WHERE polrelid = 'ai_drafts'::regclass")
    } == {"dwaar_society_isolation"}


def test_feedback_is_append_only_and_one_per_actor_and_run(seeded: AW) -> None:
    owner = seeded.people["owner1"]
    (rid,) = seeded.rows("SELECT id FROM ai_runs")[0]
    assert (
        seeded.call(
            owner,
            "POST",
            "/v1/ai/feedback",
            json={"run_id": str(rid), "outcome": "rejected", "correction": "no"},
        ).status_code
        == 200
    )
    db = seeded.vw.idh.db
    with (
        pytest.raises((errors.InsufficientPrivilege, errors.RaiseException, errors.CheckViolation)),
        db.app_conn(seeded.soc.id) as conn,
    ):
        conn.execute("UPDATE ai_feedback SET outcome = 'accepted'")
    with (
        pytest.raises((errors.InsufficientPrivilege, errors.RaiseException)),
        db.app_conn(seeded.soc.id) as conn,
    ):
        conn.execute("DELETE FROM ai_feedback")
    with pytest.raises(errors.UniqueViolation), db.admin_conn() as conn:
        conn.execute(
            "INSERT INTO ai_feedback (society_id, ai_run_id, actor_id, outcome) SELECT society_id, ai_run_id, actor_id, 'accepted' FROM ai_feedback"
        )


def test_control_tables_accept_only_known_states_and_pins(seeded: AW) -> None:
    sid = seeded.soc.id
    with pytest.raises(errors.CheckViolation), seeded.vw.idh.db.admin_conn() as conn:
        conn.execute("UPDATE ai_feature_controls SET state = 'auto'")
    with pytest.raises(errors.CheckViolation), seeded.vw.idh.db.admin_conn() as conn:
        conn.execute("UPDATE ai_feature_controls SET prompt_version_pin = '../../etc/passwd'")
    with pytest.raises(errors.CheckViolation), seeded.vw.idh.db.admin_conn() as conn:
        conn.execute("UPDATE ai_feature_controls SET feature_id = 'face_match'")
    assert seeded.rows(
        "SELECT feature_id, state, daily_limit FROM ai_feature_controls WHERE society_id = %s",
        (sid,),
    ) == [("AI-R07", "enabled", 5)]
