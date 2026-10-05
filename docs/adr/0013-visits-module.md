# ADR-0013: Visits module (gates, devices, passes, approval requests, visits, observations, exceptions)

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team (slice 2, backend)
- Related: PRD 9.2 (GATE-01..GATE-14), 9.3 (authority split), 5.1/5.2, 8.1/8.2, 12.1-12.4, 16 (AT-02, AT-03, AT-04), INV-03, INV-07, INV-01;
  ADR-0004 (RLS), ADR-0005 (audit/outbox/idempotency), ADR-0006 (registry/authz), ADR-0010/0011/0012;
  code: `dwaar_api/modules/visits/`, migrations `0200-0205`, seed step `s400_visits.py`;
  tests: `tests/integration/visits/`, `tests/acceptance/test_at0[1-4]*.py`

## Context

Slice 2 is the first place where a resident, a guard and a gate device meet. Three facts must stay separate and truthful
(INV-07): a household PERMISSION (an approval), an OBSERVED movement (entry, exit) and a DESTINATION (a stop). The decision of
a household is a race by nature (two family phones), and the answer to "may this person come in" may never default to yes
(INV-03).

## Decisions

### 1. Schema (migrations 0200-0205), every society table through `dwaar_enable_society_rls`

`gates`, `lanes`, `devices`, `gate_policies` (0200) · `invitations`, `invitation_windows` (0201) · `visits`, `visit_stops` (0202) ·
`approval_requests`, `approval_decisions` (0203) · `access_events` (0204) · `exceptions` (0205). Composite foreign keys
`(society_id, x_id)` make a cross-society reference impossible for gates, lanes, devices, units, visits, requests and events.
Runtime roles get column-level `UPDATE` only. Deviations from PRD 8.2, all tightenings or additions:

- `access_events` uniqueness is `(society_id, device_id, seq)` and `(society_id, event_id)` (the PRD says `(event_id)`): a global unique
  index on a tenant table is an existence oracle (ADR-0004); UUIDv7 ids do not collide.
- `devices.public_key` (Ed25519, base64url) and `key_id` exist now; `cert_fingerprint` stays NULL until slice 3. A key is unique per
  society, not globally, for the same reason. `devices.state` adds the enrolment states `pending_approval|active|rejected|revoked`.
- `approval_decisions` carries `valid`, `decider_role`, `client_action_id`, `request_version`, `reverses_decision_id`; the PRD's "unique
  (request_id) for the first valid decision" is the partial unique index `WHERE valid`. A later reversal is a row with
  `decision = 'reverse'` and `valid = false`.
- `visits` has `exited_at` (observed exit), `exit_basis` and `exit_reconciled_at`; CHECK constraints make a manufactured exit time
  impossible (`reconciled_unknown` has `exited_at IS NULL`). `confidence_inside` is `none|observed|stale|unknown`.
- `exceptions.actor_id` is nullable with `raised_by_system` (detections such as an overstay have no human actor); one overstay
  exception per visit is a unique index, which makes the detection job idempotent.
- `gate_policies` (not in the PRD DDL): one lazily created row per society holding the approval expiry, permission validity, override
  validity, overstay overrides and the society-wide monotonic **revocation version**.

### 2. Invitations (GATE-01, GATE-08)

The QR text is `base64url(canonical JSON).ed25519:<signature>` (`dwaar_common.signing`), payload `{v, typ, iid, sid, n, nbf, exp, kid[, g]}`:
opaque ids, validity, nonce; no phone, unit label, name or address. Verification is signature first, then the database decides
(state, revocation, windows, uses, gate). Every "not mine / bad signature / unknown / wrong nonce" is the same `invalid_pass`; only a
verified pass of THIS society earns a precise reason (`revoked`, `consumed`, `expired`, `not_yet_valid`, `wrong_gate`).
"Never a permanent OTP" is enforced in the schema (window <= 7 days, span <= 366 days, `max_uses` <= 100) and in the API: a recurring
pass is a list of explicit windows (each <= 24 h, up to 62). The 6-digit code is stored only as a keyed hash, shown once, unique among a
unit's live codes, valid only with its destination unit, and its redemption is rate-limited per `(society, unit)` and per `(society,
guard)` BEFORE any lookup. Consumption is `UPDATE invitations SET uses = uses + 1 ... WHERE uses < max_uses AND state = 'active'`: two
desks cannot both consume a single-use pass (tested with 8 racing threads). Revocation `DELETE /v1/invitations/{id}` allocates the next value
of the society's counter (`gate_policies.revocation_version`, row-locked, strictly increasing), cancels visits authorised from the pass
that have not entered, and is naturally idempotent (a second call returns the first version). The visitor number is accepted as input
only and stored as `visitor_contact_token = HMAC(society|E.164)` (domain-separated, per society); nothing stores, returns, audits,
events or logs it (GATE-08, GATE-13, a test greps every table, response and log record).

Keys: `DWAAR_PASS_SIGNING_KEY` (Ed25519 seed, base64url), `DWAAR_PASS_KEY_ID` (optional), `DWAAR_VISITOR_HMAC_KEY` (32 bytes, base64url).
Local/test derive labelled placeholders; any other environment without them answers 503 on the endpoints that need a key
(the application still starts). They are NOT yet in `.env.example` (shared file, see the report).

### 3. Unannounced visitor and the decision (GATE-02, GATE-03, PRD 12.3)

`POST /v1/approval-requests` (guard) records the destination, the visitor notice version and language and the consent flag
(`consent_given` is mandatory: refusing consent means no request), creates the visit (`requested`), its first stop and a `pending` request that expires
after the society policy (pack default 90 s from `dwaar_packs.cascade_config`, overridable only inside the pack bounds 60-180 s; the
cascade plan is copied onto the request, `auto_allow_on_timeout` is `false` and cannot be represented). A unit with nobody who can decide
is refused (`no_household_approver`).

`POST /v1/approval-requests/{id}/decision` is one transaction whose first write is the compare-and-swap
`UPDATE ... WHERE state = 'pending' AND version = :expected AND expires_at > clock_timestamp()`. Concurrent household members serialise
on the row lock; the loser's UPDATE re-evaluates against the committed row, matches nothing and gets `409 already_decided` with the canonical
result of the winner in `details.canonical` (the other device learns the outcome in the same answer), `409 request_expired` after expiry,
`409 stale_version` for a wrong expected version of a still pending request. Only the winner inserts the decision row. The canonical response
is exactly PRD 12.3 (`request_id` = the approval request id, `entry_observed` false until an entry is observed). The core idempotency layer
rewrites a body `request_id` to the correlation id on replay; `deps.restore_canonical` puts the approval request id back (the correlation id
stays in `X-Request-ID`). `client_action_id` is the business key: the same action under a new Idempotency-Key returns the original answer.
Expiry is persisted BEFORE the decision transaction (own transaction), so a late approval fails with 409 without rolling the expiry and its
`ApprovalEscalated` event back. Expiry is lazy (every read and decide) and by `approvals.expire_due_requests(conn, ctx)`, an idempotent function
(`FOR UPDATE SKIP LOCKED`, re-check inside the UPDATE) that `visits.sweep` calls together with permission expiry, overstay detection and pass expiry.

Who may decide: members of THAT unit's household that live there (occupying owner, tenant); a family member only when delegated
(`memberships.is_primary_approver`); a non-resident owner never (INV-04); an unknown household is 404, an undelegated family member 403.
Events: `ApprovalRequested` (v1), `ApprovalDecided` (approve, deny, guard cancel, reversal), `ApprovalEscalated` (expiry, reason `expired`, with the
guard-assisted options). One event per aggregate version; exactly one outcome event per request, so a notification worker can stop alerting.
A reversal (`POST .../reversal`) is a NEW decision event and is refused once an entry was observed. Nothing ever approves after a denial or expiry.

### 4. Visits, stops, observations (GATE-04, GATE-05, INV-07)

An approved stop authorises that stop only; `POST /v1/visits/{id}/stops` creates a stop AND a new approval request; a household sees only its
own stops of a multi-destination visit. `POST /v1/visits/{id}/observations` appends an `access_events` row (gate, device, event id, device
`seq`, clock uncertainty, canonical payload hash) and ALWAYS records the fact: an entry for a visit that is not authorised (or outside its
permission window, widened by the stated clock uncertainty) leaves the visit untouched and opens an `unauthorised_entry` exception. The device must be
`active` and bound to the gate; the same `event_id` with the same content is deduplicated, with other content is 409; a taken `(device, seq)` is 409. Exit needs
an `exit_basis`: `scanned` and `observed` store the observed time; `reconciled_unknown` stores NO exit time, sets `inside_confidence = unknown` and opens
an `exit_unknown` exception. Exits are never gated (GATE-07 essential egress): any visit can be marked exited and an exit without a matching entry says so in an exception.
Overstay (GATE-11): a time-boxed kind (delivery 20 min, cab 15, service 240, vendor 240; configurable inside bounds, service 2-8 hours; a per-booking
`expected_minutes` overrides) still inside past its threshold gets one overstay exception and `inside_confidence = stale`.

### 5. Exceptions and emergency or manual entry (GATE-07)

States `open -> supervisor_review -> resolved | escalated` (compare-and-swap on state and version). A plain guard raises ordinary exceptions; emergency
and manual entry need the local authority (permission `gate.exception.authorise_entry`, role `guard_sup`), a reason of at least 5 characters, create a visit
authorised by `supervisor_override` that expires on the policy's override validity (never open-ended) and ALWAYS leave an exception. The supervisor who authorised
it cannot resolve it (maker != checker; a secretary can) and an escalated exception is closed by the secretary.

### 6. Permissions

Declared module-locally in `visits/permissions.py`; resident and society role sets are derived from the identity matrix with `matrix.roles_for`
(a test compares them with PRD 5.2 cell by cell). `GUARD_SUP` has no column in 5.2, so its actions are declared here (device status, exceptions, emergency
override). Requests to fold them into the matrix data are in the slice report. History (`gate.history.read`, UNIT scope): the household that lives
there sees the unit's visits (other stops of a multi-stop visit are hidden); OWNER_NR is refused (403, or 404 when the person lives elsewhere as an
occupying owner: the `decide()` quirk of slice 1); secretary, committee and estate manager need a `purpose` and the read is audited (IAM-04); the guard names
the gate and sees active visits of that gate, masked (no invitation link, no consent detail, no contact token, no resident identity, GATE-13).

### 7. Devices (SOC-05 subset)

`POST /v1/societies/{id}/devices` is an enrolment REQUEST (guard or supervisor) with the device's public key; `.../decision` approves or rejects it and is refused for the
requester (service and CHECK constraint); `.../revoke` closes an active device. The PRD's `POST /v1/devices/enrol` with a CSR and a certificate is slice 3.

## Consequences

- The sweep functions run as `dwaar_app`: `dwaar_worker` has no INSERT on `outbox`, so a worker cannot use `mutation()` yet (blocked request: a core
  grant, or the worker holds an app-role connection for these jobs). The functions take an already-scoped connection and are role-agnostic.
- A guard's "current gate" is the gate the guard names (`gate_id`); binding a guard to a gate is the shift module (slice 4).
- No endpoint sets the family delegation flag; the seed does it through an audited mutation.
- Visit and decision rows are history: they are never deleted by the API; erasure belongs to the privacy engine.
