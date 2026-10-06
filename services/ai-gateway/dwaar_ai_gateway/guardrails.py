"""Guardrails G1..G12, permission class X and excluded AI as DATA that tests scan.

REQ: PRD 10.2 (class X: gate opening, money movement, vote casting, personal-data export, rights restriction, tax filing are
FORBIDDEN autonomous actions), 10.4 (G1..G12), 11.5 (excluded AI cannot be enabled by prompt or setting), INV-03, INV-06.

How the guarantees are built (and tested in ``tests/integration/ai/test_guardrails.py``):
* The COMMAND of a proposal is chosen by the server's feature registry, never by the model. A model output that names a command is
  schema-invalid and ignored.
* ``CommandRegistry`` cannot hold an executable class-X command, and refuses a non-X command in a forbidden domain (gate, payment,
  vote, journal, tax, export, rights, fine, service, access, bill). So "gate.open" can exist only as a non-executable X entry.
* There is no setting, feature id, command, schema property or environment variable for any excluded capability; ``excluded_matches``
  is what the scan test uses.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from .types import RiskClass

GUARDRAILS: Final[Mapping[str, str]] = {
    "G1": "AI never decides gate access; it may pre-fill, suggest or flag",
    "G2": "AI never posts journals, releases bills, approves payments or files tax data",
    "G3": "AI never messages residents on its own, except translations of approved notices, grounded concierge answers and approved reminder templates",
    "G4": "No facial recognition of residents, visitors, staff or children in M1 to M3",
    "G5": "No marketing profiling; collections predictions are internal, use payment history only, never restrict essentials",
    "G6": "Minimise and redact personal data before any model call",
    "G7": "Rule, bill and policy answers require citations with version and effective date; abstain and escalate when evidence is missing or conflicting",
    "G8": "Respond in the user's language; always offer the original text for translations",
    "G9": "Every flag or score carries a plain-language reason",
    "G10": "Legal and compliance answers are informational and recommend counsel when uncertain",
    "G11": "No customer data used for training; sub-processors disclosed",
    "G12": "Safety-critical domains (lifts, electrical, gas, fire) limited to approved manuals and SOPs; no certification or diagnosis of safety",
}

#: PRD 11.5: capabilities that cannot be enabled by prompt or setting. ``patterns`` match identifiers (feature ids, command names,
#: configuration keys, schema property names, environment variable names) after lower-casing and replacing non-alphanumerics by "_".
EXCLUDED_AI: Final[tuple[dict[str, Any], ...]] = (
    {"id": "autonomous_gate_decision", "prd": "11.5", "patterns": (r"gate_(decision|decide|open|actuat)", r"(auto|autonomous)_(gate|entry|allow|admit)", r"open_gate", r"appearance_(based|decision)")},
    {"id": "facial_recognition", "prd": "11.5/G4", "patterns": (r"(^|_)facial?(_|$)", r"face_(match|recogni|id|attendance|credential)", r"biometric_(face|credential)")},
    {"id": "criminality_emotion_trust_scoring", "prd": "11.5", "patterns": (r"crimin", r"emotion", r"trustworth", r"(^|_)mood(_|$)")},
    {"id": "resident_credit_scoring_shared", "prd": "11.5/G5", "patterns": (r"credit_scor", r"creditworth", r"defaulter_(score|list_public)")},
    {"id": "reading_resident_sms_notifications", "prd": "11.5", "patterns": (r"(^|_)sms_(read|feed|scan|inbox)", r"notification_(feed|read|scan|listener)", r"read_(sms|messages|notifications)")},
    {"id": "automatic_fines", "prd": "11.5", "patterns": (r"auto(matic)?_?fine", r"fine_(auto|levy|issue)", r"levy_fine")},
    {"id": "payment_execution", "prd": "11.5/G2", "patterns": (r"payment_(exec|release|approve|initiate)", r"(execute|release|approve)_payment", r"money_(move|transfer)")},
    {"id": "tax_filing", "prd": "11.5/G2", "patterns": (r"tax_fil", r"file_(tax|gst|tds|return)", r"(^|_)efile(_|$)")},
    {"id": "statutory_vote_decision", "prd": "11.5", "patterns": (r"vote_(cast|decid|result_auto)", r"cast_vote", r"statutory_vote", r"auto_vote")},
    {"id": "essential_service_suspension", "prd": "11.5/INV-08", "patterns": (r"suspend_(water|power|lift|service|electric)", r"service_suspen", r"restrict_(entry|water|lift|service|access)")},
    {"id": "ad_targeting_lead_scoring", "prd": "11.5/INV-05", "patterns": (r"ad_target", r"lead_scor", r"marketing_(profil|segment)", r"(^|_)advert", r"upsell")},
)  # fmt: skip

_NORMALISE: Final = re.compile(r"[^a-z0-9]+")


def _norm(name: str) -> str:
    return _NORMALISE.sub("_", name.lower()).strip("_")


def excluded_matches(names: Iterable[str]) -> list[tuple[str, str]]:
    """``(name, excluded_capability_id)`` for every identifier that names an excluded capability."""
    hits: list[tuple[str, str]] = []
    for name in names:
        norm = _norm(name)
        for cap in EXCLUDED_AI:
            if any(re.search(p, norm) for p in cap["patterns"]):
                hits.append((name, str(cap["id"])))
    return hits


class ForbiddenAutonomousAction(Exception):
    """A class-X action, an excluded capability or an unknown command was asked for. Never executed."""

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"{name}: {reason}")
        self.name = name
        self.reason = reason


#: first segment of a command name that only class X may use (money, gate, votes, ledger, tax, exports, rights, fines ...)
FORBIDDEN_DOMAINS: Final = frozenset(
    {
        "gate",
        "payment",
        "vote",
        "journal",
        "tax",
        "export",
        "rights",
        "fine",
        "service",
        "access",
        "bill",
        "settlement",
        "ledger",
    }
)
#: the class-X catalogue (PRD 10.2): registered so a request for one gets a precise refusal, never an executor
X_CLASS_COMMANDS: Final = (
    "gate.open", "gate.allow_entry", "payment.execute", "payment.approve", "settlement.release", "vote.cast",
    "export.personal_data", "rights.restrict", "tax.file", "journal.post", "bill.release", "fine.levy", "service.suspend",
)  # fmt: skip


@dataclass(frozen=True)
class CommandSpec:
    """One command the deterministic service layer may run after a human confirms (AI-SYS-04 'allowed command')."""

    name: str
    risk_class: RiskClass
    executable: bool
    description: str
    allowed_roles: frozenset[str] = frozenset()
    approver_roles: frozenset[str] = (
        frozenset()
    )  # class C: a DIFFERENT person with one of these roles must confirm
    target_kind: str | None = None  # "unit" | None
    port: str | None = (
        None  # narrow interface to a module that may not exist yet; None = self-contained
    )

    def __post_init__(self) -> None:
        domain = self.name.split(".", 1)[0]
        if self.risk_class is RiskClass.X and self.executable:
            raise ValueError(f"{self.name}: a class X command can never be executable")
        if self.risk_class is not RiskClass.X and domain in FORBIDDEN_DOMAINS:
            raise ValueError(
                f"{self.name}: domain {domain!r} is reserved for non-executable class X entries"
            )
        if self.executable and not self.allowed_roles:
            raise ValueError(f"{self.name}: an executable command needs allowed roles")
        if self.risk_class is RiskClass.C and not self.approver_roles:
            raise ValueError(f"{self.name}: class C needs approver roles")


class CommandRegistry:
    def __init__(self) -> None:
        self._items: dict[str, CommandSpec] = {}
        for name in X_CLASS_COMMANDS:
            self._items[name] = CommandSpec(
                name, RiskClass.X, False, "forbidden autonomous action (PRD 10.2 class X)"
            )

    def register(self, spec: CommandSpec) -> None:
        existing = self._items.get(spec.name)
        if existing is not None and existing.risk_class is RiskClass.X:
            raise ValueError(f"{spec.name} is a class X command and cannot be replaced")
        self._items[spec.name] = spec

    def get(self, name: str) -> CommandSpec | None:
        return self._items.get(name)

    def names(self) -> list[str]:
        return sorted(self._items)

    def executable(self) -> list[CommandSpec]:
        return sorted((s for s in self._items.values() if s.executable), key=lambda s: s.name)

    def require_executable(self, name: str) -> CommandSpec:
        """The ONE door every proposal and every confirmation passes through."""
        spec = self._items.get(name)
        if spec is None:
            raise ForbiddenAutonomousAction(name, "command_not_in_allow_list")
        if spec.risk_class is RiskClass.X:
            raise ForbiddenAutonomousAction(name, "class_x_forbidden_autonomous_action")
        if not spec.executable:
            raise ForbiddenAutonomousAction(name, "command_not_executable")
        return spec


def default_commands() -> CommandRegistry:
    residents = frozenset({"owner_occ", "owner_nr", "tenant", "family"})
    committee = frozenset({"secretary", "committee", "estate_mgr", "treasurer"})
    reg = CommandRegistry()
    reg.register(
        CommandSpec(
            "ai.save_draft", RiskClass.B, True,
            "Save the confirmed AI draft (translation, poll wording, notice draft, complaint draft) as the caller's own draft; nothing is published or sent",
            allowed_roles=residents | committee | {"guard_sup"},
        )
    )  # fmt: skip
    reg.register(
        CommandSpec(
            "notice.create_draft", RiskClass.B, True,
            "Create a DRAFT notice in the notices module; publishing needs its own approval (AI-C01)",
            allowed_roles=committee, port="notice_draft",
        )
    )  # fmt: skip
    reg.register(
        CommandSpec(
            "ticket.create", RiskClass.B, True,
            "Submit the resident-confirmed complaint through the ticket API (AI-R02; never auto-submitted)",
            allowed_roles=residents, target_kind="unit", port="ticket_create",
        )
    )  # fmt: skip
    reg.register(
        CommandSpec(
            "ticket.apply_triage", RiskClass.B, True,
            "Apply a staff-confirmed triage suggestion (category, priority, team, parent incident) (AI-F01)",
            allowed_roles=committee, port="ticket_triage",
        )
    )  # fmt: skip
    reg.register(
        CommandSpec(
            "shift.save_handover", RiskClass.B, True,
            "Save the supervisor-confirmed shift handover summary (AI-G08)",
            allowed_roles=frozenset({"guard_sup", "estate_mgr", "secretary"}), port="shift_handover",
        )
    )  # fmt: skip
    return reg
