# Permission gaps for the owner to confirm

Status: **review needed**. Generated from `services/api/dwaar_api/modules/identity/permission_basis.py` (the data the tests enforce) at the end of slice 4.
This is a single reviewed table of every permission the PRD §5.2 matrix does **not** fully specify. Nothing here is a legal or product decision: each
row is a build-team default, kept module-local, that the owner should confirm, change or reject. Change a role set by editing the module's
`permissions.py` **and** the matching line in `permission_basis.py`; `tests/integration/identity/test_permission_basis.py` fails if the two disagree or if a
permission appears with no reviewed line.

## How to read it

* **PRD 5.2 has ten role columns** (SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, GUARD, AUDITOR, OWNER_OCC, OWNER_NR, TENANT, FAMILY) and twelve capability rows
  (society configuration, unit and member register, verify tenancy, gate operations, visitor passes, helpdesk tickets, bill runs, journals, meetings, notices,
  privacy, audit log). **GUARD_SUP has no column** (PRD 5.1 describes it in words: security exceptions, device status, authorised emergency override), and
  there is no row for notifications, parcels, shifts, staff, documents, polls, AI or the edge gateway.
* **Derived from** names the 5.2 `capability.verb` cells the role set is computed from (`matrix.roles_for`). *derived* = the PRD gives exactly this set;
  *by analogy* = the capability has no row and a neighbouring row's cells were borrowed; *PRD silent* = no cell applies at all.
* **Added roles** are given by no cell (mostly GUARD_SUP, ORG_ADMIN). **Withheld** are roles a cell would give that this action deliberately does not.
* Rows whose set equals a PRD cell exactly and whose capability the PRD names (for example `helpdesk.ticket.manage`, `notice.read`) are listed at the end:
  nothing to confirm.

Scope kinds (UNIT for the household's own unit, SOCIETY for society-wide roles) and the finer rules the services apply on top (a guard sees only the
current gate, a household only its own unit, a non-resident owner only what that person raised) are in the module ADRs, not repeated here.

## Open questions behind several rows

1. **GUARD_SUP** needs a column in the matrix. Until then every grant to it is a gap row below. Proposed: the actions listed under *Added roles = guard_sup*.
2. **Emergency broadcast (COM-05)**: PRD says "privileged roles only". Declared: SECRETARY, ESTATE_MGR, GUARD_SUP.
3. **Staff payroll adjustments**: only a deciding member of that household decides; the secretary has no payroll permission at all. Confirm.
4. **AUDITOR** has no access to notices, documents, polls, helpdesk or notifications under the printed matrix: unchanged here (an audit-report access level would need a matrix change).
5. **Parcels** follow "Gate operations"; PRD 5.2 has no parcel row, no cell for delegated-family pickup and none for declaring a parcel lost.


## Guard supervisor and other roles with no column in PRD 5.2 (slice 2/3 gate and edge permissions)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `edge.policy.publish` | guard_sup, secretary | society_config.manage | guard_sup | - | derived | publishing the gate policy is a configuration act; the supervisor may force a refresh | [ ] |
| `edge.status.read` | committee, estate_mgr, guard_sup, secretary | gate_ops.read | guard_sup | guard | derived | gateway status: read-mostly roles and the supervisor | [ ] |
| `gate.configure.read` | committee, estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | - | derived |  | [ ] |
| `gate.destination.read` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.device.decide` | guard_sup, secretary | society_config.manage | guard_sup | - | derived | PRD 5.1: GUARD_SUP has device status and local override | [ ] |
| `gate.device.read` | committee, estate_mgr, guard_sup, secretary | gate_ops.read | guard_sup | guard | derived |  | [ ] |
| `gate.device.request` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.exception.authorise_entry` | guard_sup | none | guard_sup | - | PRD silent | PRD 5.1: GUARD_SUP is the authorised emergency override | [ ] |
| `gate.exception.manage` | guard_sup, secretary | society_config.manage | guard_sup | - | derived | PRD 5.1: GUARD_SUP handles security exceptions | [ ] |
| `gate.exception.raise` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.exception.read` | committee, estate_mgr, guard_sup, secretary | gate_ops.read | guard_sup | guard | derived |  | [ ] |
| `gate.history.read` | committee, estate_mgr, family, guard, guard_sup, owner_occ, secretary, tenant | gate_ops.read, gate_ops.read_own | guard_sup | - | derived |  | [ ] |
| `gate.invitation.redeem` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.request.create` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.request.read` | family, guard, guard_sup, owner_occ, tenant | gate_ops.manage, gate_ops.read_own | guard_sup | - | derived |  | [ ] |
| `gate.standing_rule.read` | committee, estate_mgr, family, guard_sup, owner_occ, secretary, tenant | gate_ops.read, gate_ops.read_own | guard_sup | guard | derived |  | [ ] |
| `gate.visit.manage` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.visit.observe` | guard, guard_sup | gate_ops.manage | guard_sup | - | derived |  | [ ] |
| `gate.visit.read` | committee, estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | - | derived |  | [ ] |

## Notifications and calling (slice 4, ADR-0020)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `notification.action` | family, owner_occ, tenant | gate_ops.read_own | - | - | by analogy | approve or deny a visitor from a notification = the household's own gate decision | [ ] |
| `notification.budget.manage` | secretary | society_config.manage | - | - | by analogy |  | [ ] |
| `notification.budget.read` | committee, estate_mgr, guard_sup, secretary | society_config.read | guard_sup | auditor, treasurer | by analogy |  | [ ] |
| `notification.call.read` | committee, estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | - | by analogy |  | [ ] |
| `notification.call.start` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy | CALL-01: the guard or supervisor requests a masked call; the server picks the callee | [ ] |
| `notification.cascade.restart` | guard_sup | none | guard_sup | - | PRD silent | starts attempt n+1 of the cascade (max 5); never extends the expiry | [ ] |
| `notification.device.manage` | family, owner_nr, owner_occ, tenant | unit_register.read_own | - | - | by analogy | a household member's own push tokens and diagnostics | [ ] |
| `notification.health.read` | committee, estate_mgr, guard_sup, secretary | gate_ops.read | guard_sup | guard | by analogy |  | [ ] |
| `notification.inbox.read` | family, owner_nr, owner_occ, tenant | unit_register.read_own | - | - | by analogy |  | [ ] |
| `notification.metrics.read` | committee, estate_mgr, guard_sup, secretary | gate_ops.read | guard_sup | guard | by analogy |  | [ ] |
| `notification.preferences.manage` | family, owner_nr, owner_occ, tenant | unit_register.read_own | - | - | by analogy |  | [ ] |
| `notification.provider.read` | estate_mgr, secretary | society_config.read | - | auditor, committee, treasurer | by analogy | names a missing dependency: secretary and estate manager only | [ ] |
| `notification.settings.manage` | family, owner_occ, tenant | gate_ops.read_own | - | - | by analogy | who is notified: only members who may decide for the unit (the service narrows a plain family member out) | [ ] |
| `notification.settings.read` | committee, estate_mgr, family, owner_occ, secretary, tenant | gate_ops.read, gate_ops.read_own | - | guard | by analogy |  | [ ] |
| `notification.status.read` | committee, estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | - | by analogy |  | [ ] |
| `notification.template.manage` | secretary | society_config.manage | - | - | by analogy |  | [ ] |
| `notification.template.read` | committee, estate_mgr, secretary | society_config.read | - | auditor, treasurer | by analogy |  | [ ] |

## Parcels (slice 4, ADR-0021)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `parcel.collect.supervised` | guard_sup | none | guard_sup | - | PRD silent | PAR-03: a supervised alternate proof is the local authority's act | [ ] |
| `parcel.consent` | family, owner_occ, tenant | gate_ops.read_own | - | - | by analogy |  | [ ] |
| `parcel.expect` | family, owner_occ, tenant | gate_ops.read_own | - | - | by analogy |  | [ ] |
| `parcel.handle` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy |  | [ ] |
| `parcel.pickup_token.issue` | family, owner_occ, tenant | gate_ops.read_own | - | - | by analogy |  | [ ] |
| `parcel.read` | committee, estate_mgr, family, guard, guard_sup, owner_occ, secretary, tenant | gate_ops.read, gate_ops.read_own | guard_sup | - | by analogy |  | [ ] |
| `parcel.report.create` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy |  | [ ] |
| `parcel.report.read` | committee, estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | - | by analogy |  | [ ] |
| `parcel.resolve` | estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | committee | by analogy | refuse or return: the gate staff and the two managers; 'lost' needs the supervisor or the secretary (service) | [ ] |

## Staff register, attendance, payroll (slice 4, ADR-0021)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `staff.attendance.correct` | estate_mgr, guard_sup, owner_occ, secretary, tenant | none | estate_mgr, guard_sup, owner_occ, secretary, tenant | - | PRD silent | a correction is a recorded act of the household or a manager, never the guard alone | [ ] |
| `staff.attendance.read` | estate_mgr, family, guard_sup, owner_occ, secretary, tenant | none | estate_mgr, family, guard_sup, owner_occ, secretary, tenant | - | PRD silent | a household sees its own engagements' attendance | [ ] |
| `staff.attendance.record` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy | STAFF-02: the guard records an observation | [ ] |
| `staff.consent.capture` | estate_mgr, guard, guard_sup, secretary | none | estate_mgr, guard, guard_sup, secretary | - | PRD silent | STAFF-04: consent is captured before any data (an assisted-tablet act) | [ ] |
| `staff.engagement.manage` | estate_mgr, owner_occ, secretary, tenant | none | estate_mgr, owner_occ, secretary, tenant | - | PRD silent | STAFF-01/03: the household manages its OWN engagements; society roles any | [ ] |
| `staff.payroll.decide` | owner_occ, tenant | none | owner_occ, tenant | - | PRD silent | only a deciding member of THAT household; the secretary has no payroll permission | [ ] |
| `staff.payroll.propose` | estate_mgr, owner_occ, tenant | none | estate_mgr, owner_occ, tenant | - | PRD silent |  | [ ] |
| `staff.payroll.read` | estate_mgr, owner_occ, tenant | none | estate_mgr, owner_occ, tenant | - | PRD silent |  | [ ] |
| `staff.read` | estate_mgr, family, guard, guard_sup, owner_occ, secretary, tenant | none | estate_mgr, family, guard, guard_sup, owner_occ, secretary, tenant | - | PRD silent | register entries are masked; a guard sees only staff authorised right now | [ ] |
| `staff.register.manage` | estate_mgr, guard_sup, secretary | none | estate_mgr, guard_sup, secretary | - | PRD silent | STAFF-01: registering a worker needs a consent receipt first | [ ] |

## Shifts, handovers, guard profile and training (slice 4, ADR-0021)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `guard.profile.read` | estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | committee | by analogy |  | [ ] |
| `guard.profile.write` | guard, guard_sup, secretary | gate_ops.manage | guard_sup, secretary | - | by analogy |  | [ ] |
| `guard.training.record` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy |  | [ ] |
| `shift.handover.acknowledge` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy |  | [ ] |
| `shift.manage` | estate_mgr, guard_sup, secretary | gate_ops.read | guard_sup | committee, guard | by analogy | schedule shifts: the supervisor and the two managers | [ ] |
| `shift.operate` | guard, guard_sup | gate_ops.manage | guard_sup | - | by analogy |  | [ ] |
| `shift.override.grant` | guard_sup | none | guard_sup | - | PRD silent | Appendix C: the supervisor's override, capped at the end of the shift | [ ] |
| `shift.read` | committee, estate_mgr, guard, guard_sup, secretary | gate_ops.read | guard_sup | - | by analogy |  | [ ] |

## Notices, documents, polls (slice 4, ADR-0022)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `document.draft` | committee, estate_mgr, secretary | notices.draft | - | - | by analogy | PRD has no document vault row: follows Notices | [ ] |
| `document.manage` | secretary | notices.manage | - | - | by analogy | publish and withdraw: the secretary, as for notices | [ ] |
| `document.read` | committee, estate_mgr, family, owner_nr, owner_occ, secretary, tenant, treasurer | notices.read | - | - | by analogy | per-document access levels narrow this further (owners, committee, managers) | [ ] |
| `notice.emergency` | estate_mgr, guard_sup, secretary | none | estate_mgr, guard_sup, secretary | - | PRD silent | PRD 9.8 COM-05 says 'privileged roles only' and names none | [ ] |
| `notice.receipts.read` | committee, estate_mgr, secretary | notices.draft | - | - | by analogy | who may see delivery and read counts: the drafting roles | [ ] |
| `poll.draft` | committee, estate_mgr, secretary | notices.draft | - | - | by analogy |  | [ ] |
| `poll.manage` | secretary | notices.manage | - | - | by analogy |  | [ ] |
| `poll.read` | committee, estate_mgr, family, owner_nr, owner_occ, secretary, tenant, treasurer | notices.read | - | - | by analogy |  | [ ] |
| `poll.respond` | family, owner_nr, owner_occ, tenant | notices.read | - | committee, estate_mgr, secretary, treasurer | by analogy | residents only; eligibility (all members or owners) is the poll's | [ ] |

## Helpdesk (slice 4, ADR-0022)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `helpdesk.emergency.manage` | secretary | helpdesk.manage | - | estate_mgr | derived | the society's emergency procedure is the secretary's to record | [ ] |

## AI (slice 4, ADR-0023)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `ai.audit.read` | auditor, secretary | audit_log.read | - | committee, treasurer | by analogy | the AI run log is an audit record: the auditor and the secretary read it | [ ] |
| `ai.controls.manage` | secretary | society_config.manage | - | - | by analogy | kill switch, feature switches and prompt pin are society configuration | [ ] |
| `ai.providers.read` | org_admin, secretary | society_config.manage | org_admin | - | by analogy | provider status names a missing dependency: admins only; the platform operator may also look | [ ] |
| `ai.status.read` | auditor, committee, estate_mgr, secretary | society_config.read | - | treasurer | by analogy | latency and budget of AI features: society configuration readers except the treasurer | [ ] |
| `ai.use` | committee, estate_mgr, family, guard_sup, owner_nr, owner_occ, secretary, tenant, treasurer | notices.read | guard_sup | - | by analogy | any member who can read notices may ask for a draft; the guard supervisor may use the handover feature | [ ] |

## Society and units (slice 1)

| Action | Roles registered | Derived from (PRD 5.2) | Added roles | Withheld | Basis | Note | Owner confirms |
|---|---|---|---|---|---|---|---|
| `society.create` | org_admin, platform_admin | none | org_admin, platform_admin | - | PRD silent | platform operators only (IAM-13) | [ ] |

## Exactly the PRD cell (nothing to confirm)

| Action | Derived from |
|---|---|
| `gate.configure` | society_config.manage |
| `gate.invitation.create` | visitor_passes.read_own |
| `gate.request.decide` | gate_ops.read_own |
| `gate.standing_rule.manage` | visitor_passes.read_own |
| `helpdesk.emergency.read` | helpdesk.create, helpdesk.read, helpdesk.read_own |
| `helpdesk.settings.manage` | helpdesk.manage |
| `helpdesk.settings.read` | helpdesk.read |
| `helpdesk.sla.read` | helpdesk.read |
| `helpdesk.support.create` | helpdesk.read_own |
| `helpdesk.ticket.act` | helpdesk.read_own, helpdesk.manage |
| `helpdesk.ticket.create` | helpdesk.create, helpdesk.read_own |
| `helpdesk.ticket.manage` | helpdesk.manage |
| `helpdesk.ticket.read` | helpdesk.read, helpdesk.read_own |
| `notice.draft` | notices.draft |
| `notice.manage` | notices.manage |
| `notice.read` | notices.read |
| `society.configure` | society_config.manage |
| `society.read` | society_config.read |
| `society.view` | society_config.read, unit_register.read_own, unit_register.read_masked |
| `unit.import` | unit_register.manage |
| `unit.read` | unit_register.read, unit_register.read_own, unit_register.read_masked |
| `unit.write` | unit_register.manage |
