"""Scoped retrieval, confirmation binding and the class-X / excluded-AI registry (AI-SYS-02, AI-SYS-04, PRD 10.2, 11.5, INV-03, INV-06)."""

from __future__ import annotations

import dataclasses
import datetime as dt
import uuid

import pytest

from dwaar_ai_gateway.binding import (
    ConfirmationRejected,
    StoredProposal,
    compute_hash,
    verify_confirmation,
)
from dwaar_ai_gateway.config import GatewayConfig
from dwaar_ai_gateway.features import build_handlers
from dwaar_ai_gateway.guardrails import (
    EXCLUDED_AI,
    FORBIDDEN_DOMAINS,
    GUARDRAILS,
    X_CLASS_COMMANDS,
    CommandSpec,
    ForbiddenAutonomousAction,
    default_commands,
    excluded_matches,
)
from dwaar_ai_gateway.pipeline import Gateway
from dwaar_ai_gateway.policy import authorise_sources
from dwaar_ai_gateway.testing import OTHER_SOC, PERSON, SOC, UNIT_A, UNIT_B, doc
from dwaar_ai_gateway.types import Caller, RiskClass, SourceDoc

pytestmark = pytest.mark.req("AI-SYS-02", "AI-SYS-04")


# ---------------------------------------------------------------------------------------------- scoped retrieval
def test_every_candidate_is_rechecked_for_society_status_role_and_unit() -> None:
    caller = Caller(SOC, PERSON, "tenant", unit_ids=frozenset({UNIT_A}))
    docs = [
        doc("ok", "visible to everyone in my unit", unit=UNIT_A),
        doc("other-soc", "another society's ticket about something private", society=OTHER_SOC),
        doc("neighbour", "the next flat's private ticket text", unit=UNIT_B),
        SourceDoc("gone", SOC, "ticket", "deleted ticket text here", status="deleted"),
        SourceDoc("old", SOC, "document", "superseded rule text version one", status="superseded"),
        SourceDoc("arch", SOC, "document", "archived rule text version zero", status="archived"),
        SourceDoc(
            "cmte",
            SOC,
            "document",
            "committee only minutes of the meeting",
            visible_to_roles=frozenset({"secretary", "committee"}),
        ),
    ]
    d = authorise_sources(caller, docs)
    assert [x.source_id for x in d.allowed] == ["ok"]
    assert sorted(e["reason"] for e in d.excluded) == sorted(
        [
            "other_society",
            "unit_not_covered",
            "not_published",
            "not_published",
            "not_published",
            "role_not_visible",
        ]
    )
    assert d.critical  # a foreign-society document at this layer is a critical diagnostic
    assert all(len(e["ref"]) == 12 for e in d.excluded)  # hashed reference, never the id or text
    assert d.fingerprints  # excluded text is fingerprinted so an echo can be detected


def test_society_wide_callers_see_all_units_of_their_own_society_only() -> None:
    caller = Caller(SOC, PERSON, "estate_mgr", society_wide=True)
    d = authorise_sources(
        caller,
        [
            doc("a", "ticket text for unit a here", unit=UNIT_A),
            doc("b", "ticket from another society entirely", society=OTHER_SOC),
        ],
    )
    assert [x.source_id for x in d.allowed] == ["a"]


# ---------------------------------------------------------------------------------------------- binding
NOW = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)
TARGET = uuid.UUID("0192f3a1-0000-7000-8000-0000000000c1")


def stored(**over: object) -> tuple[StoredProposal, dict]:
    base = dict(society_id=SOC, actor_id=PERSON, command="ai.save_draft", risk_class="B", payload={"kind": "translation", "t": "x"},
                target_ids=[TARGET], target_versions=[2], expires_at=NOW + dt.timedelta(minutes=30))  # fmt: skip
    base.update(over)
    h = compute_hash(
        **{
            k: base[k]
            for k in (
                "society_id",
                "actor_id",
                "command",
                "risk_class",
                "payload",
                "target_ids",
                "target_versions",
                "expires_at",
            )
        }
    )  # type: ignore[arg-type]
    sp = StoredProposal(actor_role="owner_occ", state="proposed", payload_hash=h, **base)  # type: ignore[arg-type]
    kw = dict(presented_hash=h, now=NOW, confirmer_id=PERSON, confirmer_role="owner_occ", allowed_roles=frozenset({"owner_occ"}), approver_roles=frozenset({"secretary"}), current_target_versions=[2])  # fmt: skip
    return sp, kw


def test_the_matching_confirmation_passes() -> None:
    sp, kw = stored()
    verify_confirmation(sp, **kw)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda sp, kw: (
                dataclasses.replace(sp, payload={"kind": "translation", "t": "EVIL"}),
                kw,
            ),
            "hash_mismatch",
        ),
        (lambda sp, kw: (sp, {**kw, "presented_hash": "sha256:" + "1" * 64}), "hash_mismatch"),
        (lambda sp, kw: (sp, {**kw, "now": NOW + dt.timedelta(hours=1)}), "expired"),
        (lambda sp, kw: (dataclasses.replace(sp, state="confirmed"), kw), "already_decided"),
        (lambda sp, kw: (sp, {**kw, "confirmer_id": uuid.uuid4()}), "wrong_actor"),
        (
            lambda sp, kw: (
                sp,
                {
                    **kw,
                    "confirmer_role": "tenant",
                    "allowed_roles": frozenset({"owner_occ", "tenant"}),
                },
            ),
            "role_changed",
        ),
        (
            lambda sp, kw: (
                dataclasses.replace(sp, actor_role="tenant"),
                {**kw, "allowed_roles": frozenset({"x"})},
            ),
            "role_changed",
        ),
        (lambda sp, kw: (sp, {**kw, "current_target_versions": [3]}), "target_changed"),
        (lambda sp, kw: (sp, {**kw, "current_target_versions": [2, 2]}), "target_changed"),
        (
            lambda sp, kw: (sp, {**kw, "allowed_roles": frozenset({"secretary"})}),
            "role_not_allowed",
        ),
    ],
)
def test_revalidation_failures(mutate, code: str) -> None:  # type: ignore[no-untyped-def]
    sp, kw = stored()
    sp, kw = mutate(sp, kw)
    with pytest.raises(ConfirmationRejected) as exc:
        verify_confirmation(sp, **kw)
    assert exc.value.code == code


def test_class_c_needs_a_different_person_with_an_approver_role() -> None:
    sp, kw = stored(risk_class="C")
    for confirmer, role in ((PERSON, "secretary"), (uuid.uuid4(), "tenant")):
        with pytest.raises(ConfirmationRejected) as exc:
            verify_confirmation(sp, **{**kw, "confirmer_id": confirmer, "confirmer_role": role})
        assert exc.value.code == "approver_required"
    verify_confirmation(sp, **{**kw, "confirmer_id": uuid.uuid4(), "confirmer_role": "secretary"})


def test_hash_covers_command_targets_versions_actor_society_and_expiry() -> None:
    sp, _ = stored()
    base = dict(society_id=SOC, actor_id=PERSON, command="ai.save_draft", risk_class="B", payload={"a": 1}, target_ids=[TARGET], target_versions=[2], expires_at=NOW)  # fmt: skip
    h0 = compute_hash(**base)  # type: ignore[arg-type]
    for k, v in (("society_id", OTHER_SOC), ("actor_id", uuid.uuid4()), ("command", "ticket.create"), ("risk_class", "C"), ("payload", {"a": 2}),
                 ("target_ids", [uuid.uuid4()]), ("target_versions", [3]), ("expires_at", NOW + dt.timedelta(seconds=1))):  # fmt: skip
        assert compute_hash(**{**base, k: v}) != h0, k  # type: ignore[arg-type]
    assert sp.payload_hash.startswith("sha256:")


# ---------------------------------------------------------------------------------------------- class X
def test_no_class_x_command_can_be_registered_as_executable_or_proposed() -> None:
    reg = default_commands()
    for name in X_CLASS_COMMANDS:
        with pytest.raises(ForbiddenAutonomousAction):
            reg.require_executable(name)
        with pytest.raises(ValueError, match="class X"):
            reg.register(
                CommandSpec(name, RiskClass.B, True, "x", allowed_roles=frozenset({"secretary"}))
            )
    with pytest.raises(ValueError, match="never be executable"):
        CommandSpec("anything.x", RiskClass.X, True, "x", allowed_roles=frozenset({"secretary"}))
    for domain in (
        FORBIDDEN_DOMAINS
    ):  # even a NEW name in a money/gate/vote domain cannot be executable unless it is class X
        with pytest.raises(ValueError, match="reserved"):
            CommandSpec(
                f"{domain}.new_action",
                RiskClass.B,
                True,
                "x",
                allowed_roles=frozenset({"secretary"}),
            )
    assert {c.name for c in reg.executable()} == {
        "ai.save_draft",
        "notice.create_draft",
        "ticket.create",
        "ticket.apply_triage",
        "shift.save_handover",
    }
    assert all(c.risk_class is not RiskClass.X for c in reg.executable())
    for needed in (
        "gate.open",
        "payment.execute",
        "vote.cast",
        "export.personal_data",
        "rights.restrict",
        "tax.file",
        "journal.post",
        "bill.release",
    ):
        assert needed in X_CLASS_COMMANDS  # PRD 10.2 class X + G2


def test_unknown_commands_are_refused_too() -> None:
    with pytest.raises(ForbiddenAutonomousAction) as exc:
        default_commands().require_executable("sql.run")
    assert exc.value.reason == "command_not_in_allow_list"


def test_every_feature_names_an_allow_listed_non_x_command_and_the_gateway_refuses_to_start_otherwise() -> (
    None
):
    gw = Gateway(GatewayConfig(environment="test"))
    for h in gw.features():
        assert h.spec.risk_class is not RiskClass.X
        if h.spec.command:
            assert gw.commands.require_executable(h.spec.command).risk_class is not RiskClass.X
    handlers = build_handlers()
    bad = handlers["AI-R07"]
    bad.spec = dataclasses.replace(bad.spec, command="gate.open")
    with pytest.raises(ForbiddenAutonomousAction):
        Gateway(GatewayConfig(environment="test"), handlers=handlers)
    handlers = build_handlers()
    handlers["AI-R07"].spec = dataclasses.replace(handlers["AI-R07"].spec, risk_class=RiskClass.X)
    with pytest.raises(ForbiddenAutonomousAction):
        Gateway(GatewayConfig(environment="test"), handlers=handlers)


def test_no_feature_registry_command_config_or_schema_name_enables_an_excluded_capability() -> None:
    """PRD 11.5: excluded AI cannot be enabled by prompt or setting. Scan every identifier the gateway exposes."""
    gw = Gateway(GatewayConfig(environment="test"))
    names: list[str] = []
    for h in gw.features():
        names += [
            h.spec.id,
            h.spec.name,
            h.spec.purpose,
            h.spec.command or "",
            *h.spec.input_schema.get("properties", {}).keys(),
        ]
    names += gw.commands.names()
    names += [f.name for f in dataclasses.fields(GatewayConfig)]
    for h in gw.features():
        if h.spec.uses_model:
            bundle = gw.prompts.load(h.spec.id)
            names += list(bundle.schema.get("properties", {}))
    hits = [(n, cap) for n, cap in excluded_matches(names) if n not in X_CLASS_COMMANDS]
    assert hits == []
    # ... while the scanner itself works on realistic switch names
    for bad in ("face_match", "facial_recognition_enabled", "emotion_score", "criminality_score", "credit_score_share", "sms_read_feed", "auto_fine", "payment_execute",
                "tax_filing", "cast_vote", "statutory_vote_decision", "suspend_water", "ad_targeting", "lead_scoring", "gate_decision", "open_gate"):  # fmt: skip
        assert excluded_matches([bad]), bad
    assert {e["id"] for e in EXCLUDED_AI} >= {
        "facial_recognition",
        "automatic_fines",
        "payment_execution",
        "tax_filing",
        "statutory_vote_decision",
        "ad_targeting_lead_scoring",
    }


def test_guardrails_g1_to_g12_are_all_stated() -> None:
    assert list(GUARDRAILS) == [f"G{i}" for i in range(1, 13)]
