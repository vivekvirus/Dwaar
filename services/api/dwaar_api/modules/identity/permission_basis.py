"""Where every MODULE-LOCAL permission's role set comes from: a PRD 5.2 matrix cell, an analogy, or nothing the PRD says (for the owner to confirm).

REQ: PRD 5.1 / 5.2 (the permission matrix is the contract), IAM-13, INV-01; ADR-0011 (matrix as data), ADR-0006 (module registry).

The PRD matrix has ten role columns and twelve capability rows. Modules declare finer actions (``parcel.collect.supervised``, ``notification.cascade.restart``)
and roles the matrix has no column for (GUARD_SUP, ORG_ADMIN). Rather than let each module invent role sets silently, every permission that is not
generated from the matrix itself (``matrix.*``) or identity's own (``iam.*``) is classified HERE, as data:

* ``cells``    the PRD 5.2 (capability, verb) cells the role set is DERIVED from (``matrix.roles_for``);
* ``extra``    roles the module adds that no cell gives (mostly GUARD_SUP, which has no column in 5.2): PRD-silent, to be confirmed;
* ``narrowed`` roles a cell gives that this action deliberately withholds (stricter than the matrix; allowed, but listed);
* ``analogy``  True when the capability has NO row in 5.2 and the cells of a neighbouring row were borrowed (parcels follow "Gate operations", documents
               and polls follow "Notices", notification settings follow "Gate operations"): the cell is not specified FOR THIS capability.

INVARIANT (tested): ``registered roles == (union of cells - narrowed) | extra`` for EVERY classified permission, and every non-matrix, non-iam permission
in the registry is classified. A role set can therefore not drift, and a new permission cannot appear without a reviewed line here.
``docs/permissions-gaps.md`` is the owner-facing rendering of every entry with ``analogy`` or ``extra`` or ``narrowed`` (a test keeps it in step).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from . import matrix


@dataclass(frozen=True)
class Basis:
    cells: tuple[tuple[str, str], ...] = ()
    extra: frozenset[str] = frozenset()
    narrowed: frozenset[str] = frozenset()
    analogy: bool = False
    note: str = ""

    def roles(self) -> frozenset[str]:
        derived: frozenset[str] = frozenset()
        for capability, verb in self.cells:
            derived |= matrix.roles_for(capability, verb)
        return (derived - self.narrowed) | self.extra

    @property
    def needs_owner_confirmation(self) -> bool:
        return bool(self.extra or self.narrowed or self.analogy or not self.cells)


def _b(
    *cells: tuple[str, str],
    extra: str = "",
    narrowed: str = "",
    analogy: bool = False,
    note: str = "",
) -> Basis:
    return Basis(tuple(cells), frozenset(extra.split()), frozenset(narrowed.split()), analogy, note)


GO_R: Final = ("gate_ops", "read")
GO_M: Final = ("gate_ops", "manage")
GO_O: Final = ("gate_ops", "read_own")
SC_M: Final = ("society_config", "manage")
SC_R: Final = ("society_config", "read")
VP_O: Final = ("visitor_passes", "read_own")
UR_O: Final = ("unit_register", "read_own")
UR_M: Final = ("unit_register", "manage")
UR_R: Final = ("unit_register", "read")
UR_MASK: Final = ("unit_register", "read_masked")
N_R: Final = ("notices", "read")
N_D: Final = ("notices", "draft")
N_M: Final = ("notices", "manage")
H_C: Final = ("helpdesk", "create")
H_M: Final = ("helpdesk", "manage")
H_R: Final = ("helpdesk", "read")
H_O: Final = ("helpdesk", "read_own")
AL_R: Final = ("audit_log", "read")

SUP = "guard_sup"
SOC_RO = "auditor committee treasurer"

#: action -> basis. Keep sorted by module. Every line is a reviewed decision.
BASIS: Final[dict[str, Basis]] = {
    # ------------------------------------------------------------------------------------------ AI (PRD 10, 11: no matrix row)
    "ai.audit.read": _b(AL_R, narrowed="committee treasurer", analogy=True, note="the AI run log is an audit record: the auditor and the secretary read it"),
    "ai.controls.manage": _b(SC_M, analogy=True, note="kill switch, feature switches and prompt pin are society configuration"),
    "ai.providers.read": _b(SC_M, extra="org_admin", analogy=True, note="provider status names a missing dependency: admins only; the platform operator may also look"),
    "ai.status.read": _b(SC_R, narrowed="treasurer", analogy=True, note="latency and budget of AI features: society configuration readers except the treasurer"),
    "ai.use": _b(N_R, extra=SUP, analogy=True, note="any member who can read notices may ask for a draft; the guard supervisor may use the handover feature"),
    # ------------------------------------------------------------------------------------------ documents (follow Notices)
    "document.draft": _b(N_D, analogy=True, note="PRD has no document vault row: follows Notices"),
    "document.manage": _b(N_M, analogy=True, note="publish and withdraw: the secretary, as for notices"),
    "document.read": _b(N_R, analogy=True, note="per-document access levels narrow this further (owners, committee, managers)"),
    # ------------------------------------------------------------------------------------------ edge (slice 3)
    "edge.policy.publish": _b(SC_M, extra=SUP, note="publishing the gate policy is a configuration act; the supervisor may force a refresh"),
    "edge.status.read": _b(GO_R, narrowed="guard", extra=SUP, note="gateway status: read-mostly roles and the supervisor"),
    # ------------------------------------------------------------------------------------------ gate (slice 2)
    "gate.configure": _b(SC_M),
    "gate.configure.read": _b(GO_R, extra=SUP),
    "gate.destination.read": _b(GO_M, extra=SUP),
    "gate.device.decide": _b(SC_M, extra=SUP, note="PRD 5.1: GUARD_SUP has device status and local override"),
    "gate.device.read": _b(GO_R, narrowed="guard", extra=SUP),
    "gate.device.request": _b(GO_M, extra=SUP),
    "gate.exception.authorise_entry": _b(extra=SUP, note="PRD 5.1: GUARD_SUP is the authorised emergency override"),
    "gate.exception.manage": _b(SC_M, extra=SUP, note="PRD 5.1: GUARD_SUP handles security exceptions"),
    "gate.exception.raise": _b(GO_M, extra=SUP),
    "gate.exception.read": _b(GO_R, narrowed="guard", extra=SUP),
    "gate.history.read": _b(GO_R, GO_O, extra=SUP),
    "gate.invitation.create": _b(VP_O),
    "gate.invitation.redeem": _b(GO_M, extra=SUP),
    "gate.request.create": _b(GO_M, extra=SUP),
    "gate.request.decide": _b(GO_O),
    "gate.request.read": _b(GO_M, GO_O, extra=SUP),
    "gate.standing_rule.manage": _b(VP_O),
    "gate.standing_rule.read": _b(GO_R, GO_O, narrowed="guard", extra=SUP),
    "gate.visit.manage": _b(GO_M, extra=SUP),
    "gate.visit.observe": _b(GO_M, extra=SUP),
    "gate.visit.read": _b(GO_R, extra=SUP),
    # ------------------------------------------------------------------------------------------ helpdesk (PRD 5.2 row "Helpdesk tickets": exact)
    "helpdesk.emergency.manage": _b(H_M, narrowed="estate_mgr", note="the society's emergency procedure is the secretary's to record"),
    "helpdesk.emergency.read": _b(H_C, H_R, H_O),
    "helpdesk.settings.manage": _b(H_M),
    "helpdesk.settings.read": _b(H_R),
    "helpdesk.sla.read": _b(H_R),
    "helpdesk.support.create": _b(H_O, note="UX-07 support request: the O cells (a not-yet-verified member has no grant; the module authorises from the access overview)"),
    "helpdesk.ticket.act": _b(H_O, H_M),
    "helpdesk.ticket.create": _b(H_C, H_O),
    "helpdesk.ticket.manage": _b(H_M),
    "helpdesk.ticket.read": _b(H_R, H_O),
    # ------------------------------------------------------------------------------------------ notices (PRD 5.2 row "Notices": exact except emergency)
    "notice.draft": _b(N_D),
    "notice.emergency": _b(extra="secretary estate_mgr guard_sup", note="PRD 9.8 COM-05 says 'privileged roles only' and names none"),
    "notice.manage": _b(N_M),
    "notice.read": _b(N_R),
    "notice.receipts.read": _b(N_D, analogy=True, note="who may see delivery and read counts: the drafting roles"),
    # ------------------------------------------------------------------------------------------ notifications and calling (no matrix row)
    "notification.action": _b(GO_O, analogy=True, note="approve or deny a visitor from a notification = the household's own gate decision"),
    "notification.budget.manage": _b(SC_M, analogy=True),
    "notification.budget.read": _b(SC_R, narrowed="auditor treasurer", extra=SUP, analogy=True),
    "notification.call.read": _b(GO_R, extra=SUP, analogy=True),
    "notification.call.start": _b(GO_M, extra=SUP, analogy=True, note="CALL-01: the guard or supervisor requests a masked call; the server picks the callee"),
    "notification.cascade.restart": _b(extra=SUP, note="starts attempt n+1 of the cascade (max 5); never extends the expiry"),
    "notification.device.manage": _b(UR_O, analogy=True, note="a household member's own push tokens and diagnostics"),
    "notification.health.read": _b(GO_R, narrowed="guard", extra=SUP, analogy=True),
    "notification.inbox.read": _b(UR_O, analogy=True),
    "notification.metrics.read": _b(GO_R, narrowed="guard", extra=SUP, analogy=True),
    "notification.preferences.manage": _b(UR_O, analogy=True),
    "notification.provider.read": _b(SC_R, narrowed="auditor committee treasurer", analogy=True, note="names a missing dependency: secretary and estate manager only"),
    "notification.settings.manage": _b(GO_O, analogy=True, note="who is notified: only members who may decide for the unit (the service narrows a plain family member out)"),
    "notification.settings.read": _b(GO_R, GO_O, narrowed="guard", analogy=True),
    "notification.status.read": _b(GO_R, extra=SUP, analogy=True),
    "notification.template.manage": _b(SC_M, analogy=True),
    "notification.template.read": _b(SC_R, narrowed="auditor treasurer", analogy=True),
    # ------------------------------------------------------------------------------------------ parcels (follow Gate operations)
    "parcel.collect.supervised": _b(extra=SUP, note="PAR-03: a supervised alternate proof is the local authority's act"),
    "parcel.consent": _b(GO_O, analogy=True),
    "parcel.expect": _b(GO_O, analogy=True),
    "parcel.handle": _b(GO_M, extra=SUP, analogy=True),
    "parcel.pickup_token.issue": _b(GO_O, analogy=True),
    "parcel.read": _b(GO_R, GO_O, extra=SUP, analogy=True),
    "parcel.report.create": _b(GO_M, extra=SUP, analogy=True),
    "parcel.report.read": _b(GO_R, extra=SUP, analogy=True),
    "parcel.resolve": _b(GO_R, narrowed="committee", extra=SUP, analogy=True, note="refuse or return: the gate staff and the two managers; 'lost' needs the supervisor or the secretary (service)"),
    # ------------------------------------------------------------------------------------------ polls (follow Notices)
    "poll.draft": _b(N_D, analogy=True),
    "poll.manage": _b(N_M, analogy=True),
    "poll.read": _b(N_R, analogy=True),
    "poll.respond": _b(N_R, narrowed="committee estate_mgr secretary treasurer", analogy=True, note="residents only; eligibility (all members or owners) is the poll's"),
    # ------------------------------------------------------------------------------------------ shifts and guard profile (no matrix row, no GUARD_SUP column)
    "guard.profile.read": _b(GO_R, narrowed="committee", extra=SUP, analogy=True),
    "guard.profile.write": _b(GO_M, extra="guard_sup secretary", analogy=True),
    "guard.training.record": _b(GO_M, extra=SUP, analogy=True),
    "shift.handover.acknowledge": _b(GO_M, extra=SUP, analogy=True),
    "shift.manage": _b(GO_R, narrowed="committee guard", extra=SUP, analogy=True, note="schedule shifts: the supervisor and the two managers"),
    "shift.operate": _b(GO_M, extra=SUP, analogy=True),
    "shift.override.grant": _b(extra=SUP, note="Appendix C: the supervisor's override, capped at the end of the shift"),
    "shift.read": _b(GO_R, extra=SUP, analogy=True),
    # ------------------------------------------------------------------------------------------ society and units (slice 1)
    "society.configure": _b(SC_M),
    "society.create": _b(extra="org_admin platform_admin", note="platform operators only (IAM-13)"),
    "society.read": _b(SC_R),
    "society.view": _b(SC_R, UR_O, UR_MASK),
    "unit.import": _b(UR_M),
    "unit.read": _b(UR_R, UR_O, UR_MASK),
    "unit.write": _b(UR_M),
    # ------------------------------------------------------------------------------------------ staff (domestic workers: no matrix row)
    "staff.attendance.correct": _b(extra="estate_mgr guard_sup owner_occ secretary tenant", note="a correction is a recorded act of the household or a manager, never the guard alone"),
    "staff.attendance.read": _b(extra="estate_mgr family guard_sup owner_occ secretary tenant", note="a household sees its own engagements' attendance"),
    "staff.attendance.record": _b(GO_M, extra=SUP, analogy=True, note="STAFF-02: the guard records an observation"),
    "staff.consent.capture": _b(extra="estate_mgr guard guard_sup secretary", note="STAFF-04: consent is captured before any data (an assisted-tablet act)"),
    "staff.engagement.manage": _b(extra="estate_mgr owner_occ secretary tenant", note="STAFF-01/03: the household manages its OWN engagements; society roles any"),
    "staff.payroll.decide": _b(extra="owner_occ tenant", note="only a deciding member of THAT household; the secretary has no payroll permission"),
    "staff.payroll.propose": _b(extra="estate_mgr owner_occ tenant"),
    "staff.payroll.read": _b(extra="estate_mgr owner_occ tenant"),
    "staff.read": _b(extra="estate_mgr family guard guard_sup owner_occ secretary tenant", note="register entries are masked; a guard sees only staff authorised right now"),
    "staff.register.manage": _b(extra="estate_mgr guard_sup secretary", note="STAFF-01: registering a worker needs a consent receipt first"),
}  # fmt: skip

#: prefixes of permissions that are NOT classified here: generated from the matrix itself, or identity's own (reviewed with ADR-0011)
GENERATED_PREFIXES: Final = ("matrix.", "iam.")
