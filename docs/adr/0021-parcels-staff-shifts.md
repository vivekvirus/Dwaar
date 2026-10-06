# ADR-0021: Parcels, staff and shift handover (slice 4)

- Status: accepted
- Date: 2026-10-06
- Deciders: Viz (owner), build team (slice 4, backend)
- Related: PRD 9.5 (PAR-01..05, PAR-08), 9.6 (STAFF-01..05, SHIFT-01/02), GATE-09/11, UX-08/09, PRIV-03/04, 8.1/8.2, AT-12, AT-13, INV-06/07/08;
  ADR-0004 (RLS), ADR-0005 (audit/outbox/idempotency), ADR-0006 (registry/authz), ADR-0013 (visits), ADR-0017/0019 (edge);
  code: `dwaar_api/modules/{parcels,staff,shifts}/`, migrations `0400`, `0430`, `0460`, seed steps `s470_parcels`, `s480_staff`, `s490_shifts`;
  tests: `tests/integration/{parcels,staff,shifts}/`, `tests/acceptance/test_at12*.py`, `test_at13*.py`

## Context

Three small modules share one theme: what the gate holds (parcels), who works for whom (staff) and who is on duty (shifts). Each needs history that
cannot be rewritten (custody, attendance, handovers), a clear separation of facts that look alike (a courier's claim is not custody, an attendance
record is not permission, an ended shift is not a signed handover) and data minimisation (no face, masked ID, consent first).

## Decisions

### 1. Parcels (migration 0400)

- `parcels` holds the whole lifecycle: `expected` (the resident's pre-approval by brand and window, PAR-01) -> `received_at_gate` -> `stored` ->
  `pickup_pending` -> `collected`, with `refused`, `returned`, `lost_exception`. Deviation from the PRD list: a withdrawn pre-approval is `cancelled`
  (the PRD gives a resident no way to take an expectation back, and a row that stays `expected` forever is a lie).
- **Custody is a chain** (`custody_transfers`, append-only). Each link names its predecessor (`prev_seq`), `UNIQUE (parcel, prev_seq)` makes a fork
  impossible, a trigger requires `from_party` to equal the predecessor's `to_party`, and `parcels.custodian/custody_seq` are the head of the chain,
  moved in the same transaction. "Exactly one current custodian" therefore holds in the database, not only in the service (tested with raw inserts
  and with 8 racing threads). `refused` does not move custody (the guard still holds it); `returned` moves it to `carrier:<name>`; `lost_exception`
  to `lost`.
- **Concurrency**: every transition is `SELECT ... FOR UPDATE` on the parcel row followed by a guarded UPDATE; the loser of a race re-reads a terminal
  state and is denied.
- **AT-13**: a denied pickup raises inside the idempotent transaction (so nothing it did survives) and the route then appends the denial to
  `parcel_pickup_attempts` in its OWN transaction. History therefore shows granted and denied attempts, and custody is untouched. `409
  already_decided` with `details.reason = already_collected`.
- **Pickup**: single-use token (192 bits, only the SHA-256 is stored, shown once, 24 h default, a new token replaces the old one), or a SUPERVISED
  alternate proof (`guard_sup` only; kinds `photo_id_checked`, `supervisor_vouched`, `household_confirmed_by_call`). A family collector (or issuer)
  needs delegated authority (`memberships.is_primary_approver`, reusing `visits.common.household`). PAR-08: any proof kind naming a screenshot is
  refused by name (`screenshot_not_accepted`) and the pre-approval `source=order_screenshot` is refused (`order_screenshot_not_available`; AI-R04 is M2).
- **PAR-04**: `courier_observations` (append-only, `external` is a CHECK-enforced true) never touches `parcels`; the parcel view keeps
  `in_society_custody` and `courier_claims` apart; a delivery VISIT creates no parcel.
- **PAR-05**: `parcel_reminders` is unique per (parcel, `h24`|`h48`); `jobs.send_due_reminders` writes the reminder, audit and `ParcelReminderDue` event
  only when it inserted the row (`ON CONFLICT DO NOTHING` inside the mutation savepoint), so re-runs and concurrent runs produce one event. The clock is
  injected. `jobs.build_parcel_actors(broker, db)` registers the Dramatiq actor on a caller-supplied broker (`StubBroker` in tests). Custody reports
  (`parcel_custody_reports`, append-only) store the physical count against the system count, per-bin differences and the system's parcel ids; a
  shortfall never marks anything lost.
- Not built: PAR-06 (label OCR, M2), PAR-07 (partner token contract, M3, disabled), AI-R04. A test asserts there is no partner/OCR surface.

### 2. Staff (migration 0430)

- **Consent first (STAFF-04, PRIV-03/04).** `staff_consents` is the consent_receipt: language, notice version, channel, purposes, the staff member's own
  recorded action (a guard tap is not consent; `staff_action_recorded` is CHECK-true), who assisted, when, withdrawal. It carries no personal data.
  `POST /v1/staff` needs a usable receipt and every captured datum needs its purpose in it (`consent_scope_missing`); a withdrawn receipt blocks
  registration, ID, photo, credentials, engagements and attendance. One receipt covers one person. IVR assist is M2: the API accepts only
  `assisted_tablet`; `service.simulate_ivr_consent` is the labelled simulator hook (`channel=ivr_assisted`, `simulation=true`, enforced by a CHECK).
- **Data minimisation.** The ID number is accepted as INPUT only and reduced to `XXXX XXXX 1234` (Aadhaar, 12 digits validated; already-masked input
  accepted) or `XXXX AB12` at once; a CHECK refuses an unmasked value. Police verification is a status column, never a document. The staff table keeps the
  society's own copy of the display name (the global `iam.persons` row is reachable only through reviewed definers).
- **No face matching (STAFF-05).** Credentials are `code` (8 characters, shown once) or `card` (UID reported by the reader); both stored as keyed,
  society-bound HMACs. A tripwire test (`test_no_face_matching.py`) fails on any face/biometric/selfie/embedding word in columns, tables, routes,
  request models and the OpenAPI property names.
- **No global blacklist.** Nothing in the schema crosses a society or a household; tests assert no such column or route exists.
- **Engagements (STAFF-01/03).** One row per (staff person, household) with its own valid hours (days + window in Asia/Kolkata) and dates; an
  EXCLUDE constraint forbids two overlapping live engagements for the same pair. Ending updates exactly one row. The household manages its OWN unit
  (UNIT scope), society roles any. A household identifies the person by the opaque `staff_ref` printed on the card.
- **Visibility.** Society roles see the register (masked ID, status); a household sees only staff engaged by its own units, with its own engagements
  only; a GUARD sees only staff authorised right now and only the destinations (`authorisation.authorised_engagements`); anything else is 404.
- **AT-12 / edge.** `authorisation.edge_staff_input(conn, now)` is the function the edge publisher can consume (opaque ids, valid hours, a list of
  recently ended engagements, a digest) and `StaffEngagementEnded` carries `remaining_live_engagements`. The edge module is NOT edited here; wiring the
  input into the manifest is a request (see the slice report).
- **Attendance (STAFF-02).** Observation only; unique `client_event_id` makes a retry one event; outside the valid hours it is still recorded
  (`authorised_now=false`, no engagement link, and the guard learns nothing about the person). Corrections are append-only rows (void / amend time /
  amend direction) with who, role, why and when; the read model overlays them. Payroll adjustments are integer paise, proposed by one party and
  effective only when a deciding member of THAT household approves (first decision wins); the secretary has no payroll permission at all.

### 3. Shifts (migration 0460)

- `shifts` (scheduled -> active -> ended; one active shift per guard), `shift_checklists` (append-only; start and end), `shift_handovers`
  (pending -> acknowledged | escalated), `shift_overrides`, `guard_profiles` (language per guard, UX-08: en/hi/mr; Kannada is refused until M2),
  `guard_training_completions` (UX-09, append-only, `practice_mode` CHECK-true).
- **Checklists never block** (INV-08). The start checklist records what the terminal reported (battery, network, relay and sensor health, keys) as
  reported, what it did not report as `not_reported` (relay and sensor health stay placeholders until the edge reports them, EDGE-08/09), and what the
  server knows (policy age from the edge status when available, pending visits, unresolved incidents, parcels). The end checklist counts parcels and
  unresolved inside records against the guard's count.
- **Handover.** Created when the shift ends, with the deterministic open-items list (kinds in a fixed order, then by id, a cap per kind that SAYS when
  it cuts). `acknowledged` needs BOTH guards or the supervisor (a CHECK in the database). A guard starting at the gate becomes the incoming guard of an
  open handover. **A missing next guard escalates and locks nothing**: `jobs.escalate_unacknowledged` only sets `state=escalated` and emits
  `HandoverEscalated`; a test proves egress, new requests and parcels keep working and that neither the visits nor the edge module read any shift table.
- **SHIFT-02 / INV-06.** The payload orders `summary` before `open_items` and says so in `display_order`; the open items are always present. The summary
  is advisory text stored through `service.attach_summary` or a provider registered with `service.set_summary_provider` (the AI-G08 hook, called only
  at handover creation, failures swallowed). This module never calls a model.
- **Appendix C.** A supervisor override's `valid_until` is capped to the shift's planned end; ending the shift revokes it, the sweep revokes
  expired ones; `service.active_override(conn, gate_id)` is the function a later gate/edge change can read.
- `GET /v1/shifts/current` is the GATE-09/GATE-11 shift context (pending queue, parcels, inside records, incidents, overstay alerts, language).

### 4. Cross-cutting

- Every write is `core.audit.mutation` (audit + outbox in the savepoint); outbox allows one event per aggregate version, so each mutation bumps the
  row's version and aggregates without a version (claims, reminders, corrections, custody reports) are their own aggregate at version 1.
- Permissions are module-local (PRD 5.2 has no parcel, staff or shift row; PRD 5.1 gives `GUARD_SUP` no column). Parcel sets derive from the matrix
  "Gate operations" row. Matrix gaps are listed as requests in the slice report.
- Workers: `dwaar_worker` gets SELECT on parcels/custody, INSERT on `parcel_reminders`, column UPDATE on `shift_handovers (state, escalated_at,
  escalation_reason, version)` and `shift_overrides (revoked_at, revoke_reason, version)`; every society table is FORCE RLS via the core helper.
- i18n: namespaces `parcels`, `staff`, `shifts` in en/hi/mr; hi and mr are `machine_drafted`, none human reviewed; `staff` (the consent notice) is added to
  `human_review_required`. The generated `packages/i18n/src/{keys,catalogs}.ts` are NOT regenerated here (not owned by this slice).

## Honest limits

- No real gate, tablet, reader or courier took part: everything runs in simulation against a real PostgreSQL. Check-in codes and pickup tokens are
  not hardened against shoulder-surfing beyond rate limiting and single use.
- The seeded staff re-use the person rows of the last plain owner-occupiers (`mh.bulk35`, `mh.bulk36`, `ka.bulk28`) because
  `tests/acceptance/test_seed_dataset.py` fixes the person count to the dataset (not owned here); their register entries carry invented names.
  Seeded `started_at`/`ended_at` of shifts are the seeding moment (the service stamps the database clock).
- Staff need a phone number to exist as a person (`iam.persons.phone_token` is mandatory); a worker without any phone cannot be registered yet.
- The guard "current gate" restriction is not applied to parcels (a guard sees the society's open parcels, as in visits); the shift's gate is only used
  by the shifts module.
- Nothing computes payroll or pays anyone: an approved adjustment is the household's recorded decision.
