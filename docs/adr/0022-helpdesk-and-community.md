# ADR-0022: Helpdesk, notices, document vault and opinion polls (slice 4)

- Status: accepted
- Date: 2026-10-06
- Deciders: Viz (owner), build team (slice 4, helpdesk and community engineer)
- Related: PRD 9.7 (OPS-01..OPS-04, OPS-09), 9.8 (COM-01..COM-06), UX-07, SEC-03, SEC-04, 5.2 (rows "Helpdesk tickets", "Notices"), 8.2, 12,
  14, INV-01, INV-05, INV-06, INV-07, INV-10, G12, D-24 / GOV-01; ADR-0004 (RLS), ADR-0005 (audit/outbox/idempotency), ADR-0006 (registry),
  ADR-0011 (permissions), ADR-0012 (seed); code: `dwaar_api/modules/helpdesk/`, `dwaar_api/modules/community/`, migrations `0530-0532`
  (helpdesk) and `0560-0562` (community), seed steps `s530_helpdesk.py`, `s570_community.py`; tests: `tests/integration/helpdesk/`,
  `tests/integration/community/`.

## Context

Slice 4 adds the two resident-facing, text-and-files modules: a helpdesk (tickets with SLA clocks) and community communication
(notices, a document vault, opinion polls). Dispatch (push, SMS, WhatsApp, voice) belongs to the notifications module and model calls to
the ai-gateway, both built in parallel: these modules emit outbox events and expose seams, and call neither. Assets, preventive
maintenance, work orders (M2), amenity booking (M2) and binding votes (M2 governance, gated by an approved legal pack) are NOT built.

## Decisions

### 1. Helpdesk schema and state machine (OPS-01)

`tickets` (PRD 8.2 plus `ticket_no`, `block_id`, `hazard_kind`, `routing`, `raised_channel`, `sla_started_at`, `ack_at`, `sla_paused_since`,
`feedback_due_at`, `closed_basis`, `reopen_count`), history tables `ticket_events`, `ticket_priority_history`, `ticket_sla_log`,
`ticket_sla_breaches` (all append-only, DB-02) and `ticket_links`; configuration `helpdesk_settings` and `emergency_procedures`.
Every table is society-owned with composite foreign keys and RLS in its own migration.

States: `draft -> submitted -> triaged -> assigned -> in_progress -> awaiting_material | awaiting_resident -> resolved -> closed`, plus
`cancelled` and reopen. Moves are explicit (`TRANSITIONS`); anything else is 409 `stale_version` with a `reason` (PRD 12.2 has no other
409 code for "state changed under you"). Each mutation locks the row, updates with `WHERE version = :v` and goes through
`core.audit.mutation` (one outbox event per ticket version). A draft has no clock and is visible to its raiser only; an unsafe
observation is never left as a draft.

### 2. SLA clocks, pauses, priority history (OPS-01)

Targets are configuration (`helpdesk_settings.sla`, labelled `pilot_default` until a society changes it): emergency 2-minute acknowledgement,
urgent 15 minutes, normal 4 working hours, normal resolution 2 working days (PRD 9.7). The emergency/urgent/low RESOLUTION targets are
placeholders `[TBD]` (the PRD gives none). A target is `{"mode": "clock"|"working", "minutes"|"days"}` evaluated by pure functions in
`sla.py` on the society business calendar (weekdays, opening hours, holidays, timezone; default Mon-Sat 09:00-18:00 Asia/Kolkata).
A configuration change affects tickets submitted after it.

* Entering `awaiting_*` starts a pause (reason = the state, approver recorded: the actor, or a named other person); leaving it extends the
  resolution due instant by the stopped time (clock or working time) and writes a resume row with before/after. The log is append-only.
* `ticket_priority_history` records every priority, who set it, the APPROVER, the rule (`initial|hazard_rule|manual|triage`) and the targets
  it implied counted from the ORIGINAL start with completed pauses added back. Lowering an emergency or urgent priority needs a different
  approver (422 `approver_required`). The approver must have standing in the society; their ROLE is not verified (no cheap way to ask:
  recorded as a limit).
* Breaches are rows keyed by (ticket, clock): written BEFORE a priority change or pause (`before_change`), when an acknowledgement or
  resolution is late (`met_late`) and by the sweep (`sweep`). A later downgrade cannot remove them.
* `service.sweep_society` (idempotent, system context) records due breaches and closes tickets whose feedback window elapsed; it is also run
  lazily on ticket reads. A worker hook-up is a blocked request (the worker package belongs to the platform owner).

### 3. Scope, visibility and duplicates (OPS-02)

Scope `private` (household unit), `block`, `society`. Audience rules live in `views.py` and are used for both single reads and list
filters: the household (not a non-resident owner, who sees only what that person raised) sees its private tickets; every other resident sees
block and society tickets as STATUS ONLY (number, category, title, state, priority, dates: no description, photos, raiser, assignee, notes);
an unauthorised ticket is 404, identical to an unknown id. `support_privacy` tickets are visible to the raiser and the secretary only.

Duplicate detection PROPOSES: `duplicates.TrigramProposer` (pg_trgm) selects candidates only from the SAME scope and, for private tickets, the
SAME unit (block tickets: same block). The seam for AI-F01 grouping is `DuplicateProposer` / `register_proposer`; every proposal from any
proposer is re-filtered by `enforce_same_audience`, and the database refuses a link or a merge across scope or household (triggers
`ticket_links_same_scope`, `tickets_parent_scope`). `POST /v1/tickets/{id}/merge` closes the merged ticket with `closed_basis = merged`; it
copies no text to the survivor. Merging across households is 422 `merge_scope_mismatch`. Proposals are stored as links in state `proposed`; only
a manager's merge changes anything (INV-06).

### 4. Closure and reopen (OPS-04)

Resolution sets `feedback_due_at` (default 48 h). A resident or household member confirms (`closed_basis = resident_confirmed`); a manager may
close on their behalf (`manager_closed`); otherwise the sweep closes (`feedback_window_elapsed`, system actor). Reopen is allowed within the
reopen window (default 7 days, from `resolved_at`), by the raiser, the household (not a non-resident owner) or a manager, and goes to
`assigned` (or `triaged`). It does NOT restart or edit anything: `sla_*`, `ack_at`, priority history and every breach row stay as they were.
A reopened ticket is still judged against its ORIGINAL resolution target (the sweep flags it if that has passed): this is the
literal reading of "reopen with original SLA history retained"; a product owner who wants a fresh clock per reopen must say so.

### 5. Hazards and emergency procedure (OPS-09, G12)

`hazards.py` is deterministic: keyword phrases (English, plus MACHINE-DRAFTED Hindi and Marathi, flagged for native review), an
`unsafe_observation` flag the form asks, and the category. A match forces priority `emergency` (category `gas`/`fire_safety` alone: at least
`urgent`), sets `hazard_kind` and routing `qualified_contractor`. The response of `POST /v1/tickets` carries the society's own procedure and
accountable contacts (`emergency_procedures`, edited by the secretary, or an explicit "not configured" with i18n keys), plus
`no_rescue_guarantee` and `no_repair_instructions`. The platform authors no repair or safety steps. Hazardous or beyond-competence work
cannot be assigned to in-house staff (422 `contractor_required`). The outbox gets `TicketEmergencyAlert` (own aggregate `ticket_alert`) with
the 2-minute target for the notifications module.

### 6. UX-07

`POST /v1/societies/{id}/support-requests` authorises from the access overview, not from a grant: a person whose membership is pending,
disputed, re-verifying or verified may raise a private, household-level `support_privacy` ticket (a pending member has no effective grant,
ADR-0011, so `require` cannot be used). Anyone else, including a rejected member, gets the generic 404. Such a member gets no other helpdesk
route.

### 7. Notices (COM-01..COM-03, COM-05)

`notices` (thread, audience, state) and `notice_versions` (one row per REVISION). Triggers make a revision immutable once approved and
allow only forward moves; CHECK constraints require an approver for anything past draft, so an AI draft can never skip approval even
for a writer that bypasses the application (COM-03). Publishing needs an approved revision, then supersedes the previous published one.
Audience scope: society, block, unit or role (roles match the caller's authorising role only, a limit when one person holds several).
`notice_receipts` and `notice_deliveries` are append-only records; this module never dispatches: the notifications module calls
`record_delivery_attempt` and reacts to `NoticePublished` / `EmergencyBroadcastIssued`.

Translations (COM-02) are rows beside the original; the view always includes the original. For legal and safety notices every existing
translation and every declared target language must be `reviewed` by a person (a human translation by a different person) before publication,
and unreviewed translations are never shown to readers; routine notices show unreviewed translations labelled. A reviewed text is immutable
(trigger). Machine drafts enter only through `add_translation(origin="machine_draft")` (the ai-gateway integration), never the HTTP route.

Emergency broadcast (COM-05): `secretary`, `estate_mgr`, `guard_sup` (the printed matrix leaves "privileged roles" unspecified: a request),
plain text only (no links, attachments, sponsor fields: unknown fields are 400 and a trigger refuses links and AI drafts on the emergency
channel; ad detection in general is NOT claimed), published at once with the issuer recorded as the approver, rate-limited per person (3/hour)
and per society (6/hour). Validation runs before the allowance is spent and replays of one Idempotency-Key spend nothing.

### 8. Document vault (COM-04, SEC-03, SEC-04)

`documents` / `document_versions` with effective date, authority, access level (`all_residents`, `owners`, `committee`, `managers`),
sha256 and size. A file is uploaded as the raw request body (`PUT .../content`; type from `Content-Type` checked against magic bytes, size
cap, display name sanitised, no archive type). Storage goes through `ObjectStore` (`LocalDiskStore`, `simulation=true`, random 256-bit keys
never returned by the API); scanning through `MalwareScanner`: the default `UnconfiguredScanner` NEVER says clean (state `unavailable`) so
nothing can be published; `StubScanner` (EICAR only, `simulation=true`) is accepted only in local/test. Publishing requires a stored, hashed,
CLEAN file (CHECK constraint too); a published version is immutable (trigger) and a correction is a new version.

Downloads: `POST .../download-url` runs the current access check (role, access level, state, clean) and returns `/v1/downloads/{token}`:
HMAC-signed, 120 s default (max 900), binds person and session, contains no id and no storage key. The URL route is public (the URL is the
short-lived capability) but on every use it re-resolves the person's CURRENT grants with the issuing session (so revoked memberships, sessions or
tightened access levels and withdrawn versions kill outstanding URLs), re-checks the stored bytes against the recorded sha256 and answers
every failure with the same 404. Not built: a real object store, a real scanner, multipart uploads, per-download single use.

### 9. Opinion polls (COM-06)

`polls` is CHECKed `is_binding = false` with a fixed `label_key`; nothing resembling a ballot, meeting, quorum or resolution exists (a test
inspects routes, columns and tables). One answer per person (409 `already_decided`); eligibility `all_members` or `owners_only` (owner roles);
results are counts only, with visibility `live`, `after_close` or `managers_only`; who answered what is never returned. The neutral-wording
hook (`wording.NeutralWordingChecker`, default `RuleBasedChecker`, seam `register_checker` for AI-C12) stores flags; a flagged poll opens only
with a recorded override reason from the secretary.

### 10. Permissions

Declared module-locally from the identity matrix (`matrix.roles_for`), compared cell by cell with PRD 5.2 in tests. Helpdesk: manage = SECRETARY,
ESTATE_MGR (F); read = F + TREASURER, COMMITTEE (R); create = F + GUARD; own = the four household roles (UNIT scope); AUDITOR none. Notices
(and documents and polls, which have no matrix row): read = all but GUARD and AUDITOR; draft = SECRETARY, COMMITTEE, ESTATE_MGR; manage = SECRETARY.
Resident roles hold UNIT-scoped grants; society roles society-wide ones. All new routes take the society from `X-Society-Id` (or the path for
support requests) and answer foreign or unknown ids with the identical 404.

## Consequences

- New routes (see the slice report) break the AT-01 route inventory until classified; the AT-01 "no file/export/search routes yet" tripwire fails
  on `/v1/documents` and `/v1/downloads`: expected.
- The raised request-body limit for `/v1/documents` (`app.state.body_limits`) is the only change to shared behaviour, registered by this module.
- Idempotent responses may not contain floats (ADR-0005): similarities and settings numbers are strings.
- A person holding several roles is judged by the role of the grant that authorised the request (a core limitation).
- `iam.society_people` answers "has standing in this society" for assignees and approvers; it does not say which role.

## Alternatives considered

- Judging breach by recomputed due dates instead of rows: loses the history when the priority changes. Rejected for immutable breach rows.
- A single `Conflict` code per rule: PRD 12.2 lists four 409 codes; we reuse `stale_version` with `details.reason`, and `already_decided` for
  the second poll answer.
- Multipart upload: needs a dependency on the framework's form parsing and a different body-limit story; a raw body is simpler and hashes
  byte for byte.
- Authenticated-only download route: simpler, but then a signed URL adds nothing; the chosen route is public with re-checked, short-lived access.
