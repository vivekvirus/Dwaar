# ADR-0017: Edge sync and signed policy snapshots (cloud side of the on-site gateway)

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team (slice 3, backend)
- Related: PRD 9.3 (EDGE-01..10, authority split, outage runbook), 9.2 (GATE-05/06/07/14), 12.1 / 12.3 / 12.4, 7.4 (offline ordering), 13 (edge
  policy publisher), 14 (NFR-02..10), 16 (AT-05..AT-08), Appendix C; INV-01, INV-03, INV-07; ADR-0004 (RLS), ADR-0005 (audit/outbox), ADR-0006
  (registry), ADR-0013 (visits); code: `services/api/dwaar_api/modules/edge/`, migrations `0300-0313`, seed step `s450_edge.py`; contract:
  `docs/contracts/edge-sync.md`; tests: `tests/integration/edge/`

## Context

The gate is authoritative for what physically happened; the cloud is authoritative for who may enter (PRD 9.3). The cloud therefore does two
things for an edge gateway: it **publishes** signed, monotonically versioned policy snapshots (identity, residents, passes, revocations,
standing rules, timings), and it **ingests** the gateway's append-only observations without ever letting an observation become permission.
The edge agent (`services/edge`) is built in parallel against `docs/contracts/edge-sync.md`.

## Decisions

### 1. Device authentication: per-device Ed25519 request signature (not mTLS)

Each request carries `X-Dwaar-Device`, `X-Dwaar-Timestamp` (+-120 s) and `X-Dwaar-Signature` over `METHOD \n PATH?QUERY \n TIMESTAMP \n sha256(body)`.
The device's public key (slice 2, at enrolment) is read on **every** request through the reviewed `SECURITY DEFINER` function
`edge.device_for_auth` over `edge.device_directory` (migration 0312). The society is not known before the lookup and every society table is FORCE
RLS, so the directory follows the identity module's pattern (`iam.person_access_index`): a global index with `society_ref` (not `society_id`), kept in
step by triggers on `devices` in the same transaction as every change, with NO table privilege for any runtime role. Nothing is cached, so a
revocation is visible to the very next request (tested). All authentication failures are one identical 401; a valid signature from a pending/rejected/revoked device is 403 with no data. A per-IP
bucket guards the pre-authentication path, a per-device bucket the rest (`dwaar_rate_limit_take`). Logs carry a reason code and a hash of the
claimed device id, never a header, a signature, a key or a timestamp. **Not claimed:** mTLS with per-device certificates (EDGE-09) is a
deployment-layer control; a captured request can replay inside the 120 s window, which is harmless because both endpoints are idempotent
(tested). Verification is Ed25519; there is no secret-dependent comparison in this code.

### 2. Policy snapshots (migration 0300, `snapshot.py`)

`policy_snapshots` (PRD 8.2) is append-only with `UNIQUE (society_id, seq)` and a trigger that forces `seq = previous + 1` (a rollback, a hole or a
duplicate fails even for the owner role). The signature covers the canonical JSON (`dwaar_common` rules, no floats) of the snapshot minus the
signature; the row stores the manifest exactly as signed. `publish_policy` is idempotent: it builds the manifest, hashes it (SHA-256 of the canonical
JSON) and writes a snapshot only when the content changed, the issuer key rotated (`key_rotation`), the last one is older than the refresh interval
(`refresh`, 6 h) or `force`. Registry changes and the snapshot commit together with audit + outbox (`PolicyPublished`, via `core.audit.mutation`).
`valid_until = issued_at + policy_age_limit` (72 h, EDGE-05). Triggers: `handle_domain_event(event_type)` (the worker calls it for the outbox events in
`POLICY_RELEVANT_EVENTS`), `publish_for_society` (periodic refresh), `POST /v1/societies/{id}/edge/policy/publish` (admin), and, **until a worker
exists**, an opportunistic publish on `GET /v1/edge/policy` (`DWAAR_EDGE_PUBLISH_ON_POLL`, default on) so a revocation can never wait for a job that
is not running. This makes one GET a write by the system actor; it is switchable and documented.

Issuer key: `PolicySigner` protocol, `SimulatedKmsSigner` (labelled `simulation=True`, seed from `DWAAR_EDGE_POLICY_SIGNING_KEY`; local/test derive a
public-label key). Rotation: new active signer plus `DWAAR_EDGE_RETIRED_KEYS` (public halves); `GET /v1/edge/keys` lists both so edges verify old and new.

Manifest (data minimisation, EDGE-04): gates, lanes, devices, residents, invitations, standing rules, timing from the cascade/offline pack (INV-10,
unapproved pack defaults, labelled by the pack itself), revocations sorted newest first. Residents carry keyed opaque `credential_ref` / `person_ref`
(`edge_credential_refs`, HMAC with `DWAAR_EDGE_REF_KEY`); a membership that stops being effective is revoked with the next value of the society's
revocation counter (the same counter as invitation revocations, `gate_policies.revocation_version`); a membership that comes back gets a NEW reference
(generation + 1), so "newest deny" can neither lock out a re-verified resident nor resurrect a revoked reference. Tombstones stay 30 days (EDGE-10).
A committee hold shows as `suspended`; a dispute does not (IAM-05). Visitor aliases are masked (`A*** S***`). Invitation entries carry one additive
`windows` list (a recurring pass is a list of windows; the outer bounds alone would admit a milk vendor at 15:00).

Standing rules (GATE-14, migration 0301, `standing_rules.py`): per unit, `leave_at_gate` or `allow_window` with validated params (category, ISO
weekdays, local HH:MM window that may wrap midnight); only a member who lives in the unit and may decide for it creates or ends one (INV-04; reuses
`visits.common.member_standing`); at most 20 active per unit. A rule pre-authorises a category inside a window, never a person.

### 3. Sync ingestion (migration 0310, `sync.py`) - EDGE-07 exactly

One batch = one transaction (the answer follows the commit), one savepoint per event. Per event: parse (`EdgeEvent`) -> verify the signature with the
authenticated device's key -> wrong society / wrong device -> deduplicate `(device, seq)` and `event_id` (same content = `duplicate`; any conflict =
`quarantined`, both observations kept) -> payload hygiene (size, forbidden keys) -> permitted transition -> record + audit + outbox atomically.

* `edge_events` is the idempotency ledger (unique `(device, seq)`, unique `(society, event_id)`); the physical record is `access_events` (slice 2,
  append-only, unique `(device_id, seq)`), written directly with the same columns the visits service writes. `edge_quarantine` keeps what could not be
  processed (bounded, masked, unique per raw hash so a resend adds nothing). Both are append-only.
* The transition table is two pure functions: `decide_transition` (the `entity_id` is a cloud visit) only ever moves a visit that was already
  authorised (INV-07); an entry for an expired, denied or cancelled visit is **recorded** (an `access_events` row) and answered
  `rejected_transition` with an `unauthorised_entry` exception for a supervisor: physical entries are never silently discarded and never become
  permission. `decide_unmatched` handles the other case, which the edge agent produces for every resident, pass, standing-rule and override entry:
  the gateway mints its own movement ids, so no cloud visit exists. Those observations are recorded (no visit, no permission) and judged by the
  payload (decision source, pass known and not revoked before the entry, override, conflict flag, exit matched to an earlier entry of the same
  movement). Exits are never gated (GATE-07); `reconciled_unknown` stores no exit time (GATE-05).
* Quarantined seqs count as disposed for the acknowledgement, so one bad event never freezes the cursor (EDGE-03); the cursor and the gap list are
  computed in SQL and are property-tested against the pure reference `contiguity.compute` for any arrival order.
* A failure while processing one event quarantines that event (`processing_error`) and rolls back only its savepoint; database-level failures
  (deadlock, timeout) fail the batch and the whole batch is retried (it is idempotent). The visits module is not changed: the edge module writes the
  same tables under the same invariants and reuses `visits.exceptions.open_exception`.
* Statuses stay the four of the brief. Re-sent events answer `duplicate` when the original was `accepted`, otherwise the original status again
  (`replayed: true`). Unknown event types are stored in the ledger as `accepted / recorded_not_projected`.

### 4. Clock handling (EDGE-05, `clock.py`)

`clock_uncertainty_ms` is stored on the ledger and the observation. `occurred_at` is never rewritten. Flags (ledger `clock_flag`, one open
`clock_implausible` exception per device and flag): `future` (`occurred_at > received_at + uncertainty + 5 s`), `stale` (older than the policy-age
limit, 72 h), `uncertain` (uncertainty above the 60 s limit). The permission window is widened by the stated uncertainty at most up to the 60 s limit;
an entry with a larger uncertainty is recorded but **not applied** (`rejected_transition: clock_uncertain_review` + exception): a human reviews it
(AT-08 server side). Exits still apply.

### 5. Exceptions and migrations that touch slice 2 tables

Migration 0311 replaces `exceptions_kind_check` to add `clock_implausible` and `edge_quarantine` (all slice 2 kinds unchanged). Migration 0312 adds
the `edge` schema, the directory and an AFTER trigger on `devices` (no RLS policy of `devices` changes; the existing catalog guards stay green). No visits
source file was edited.

### 6. Metrics for OBS-02 (`metrics.py`)

In-process counters (`events_total{status}`, `quarantined_total{reason}`, `batches_total`, `policy_polls_total`, `auth_failures_total{reason}`,
`rate_limited_total`) with a Prometheus text renderer (no `/metrics` route yet) and per-device gauges computed from the database on demand
(`GET /v1/societies/{id}/edge/status`: sync age, policy age, edge backlog estimate, cloud outbox backlog, latest policy age and time to expiry).
No SLO is claimed from them.

### 7. Seed (opt-in)

`s450_edge.py` enrols a gateway per society (`Main gate edge gateway` with a key derived from the public label, `simulation=true`), two standing
rules and the first snapshot. It runs only with `DWAAR_SEED_EDGE=1`: the slice 2 seed tests assert the exact device list and audit counts of the
visits seed, so a default-on extra device would break tests this slice does not own (reported as a blocked request).

## Measured on this machine (synthetic, in-process client, real PostgreSQL, empty database; not a certification)

500-event batch of about 300 KiB: entries for authorised visits 4.0 s (125 events/s); recorded-only 2.0 s (250/s); the heaviest path (every event
flagged for review: observation + ledger + exception + audit + outbox) 4.8 s (105/s); a resend of an acknowledged batch 0.5 s (950/s). NFR-10
(60,000 events in 10 minutes at 5 Mbps) is NOT claimed: it needs the field set-up. `tests/integration/edge/test_performance.py` records the numbers.

## Consequences / open issues

- `publish_on_poll` rebuilds the manifest on every device poll (it is a no-write call when nothing changed, but it reads every effective membership).
  That is fine for pilot-sized societies and wrong for 50,000 credentials (NFR-02 sizing): switch it off and let a worker publish before then. Snapshot
  storage grows by one full manifest per change and per 6 h refresh; a retention rule for old snapshots belongs to the privacy/retention slice.
- No worker runs `handle_domain_event` or the periodic refresh yet (`dwaar_worker` has no INSERT on `outbox`, so it cannot use `mutation()`; the
  functions are role-agnostic and also run as `dwaar_app`). Publish-on-poll covers the gap.
- Edge-local movements are not projected onto `visits` (so a pass entry does not yet appear in the unit's visitor history, AT-02) nor onto
  `invitations.uses`; cloud-side single-use accounting across gates stays with the edge arbiter (PRD 9.3) until a projection is specified.
- Edge-side behaviour (AT-05 gate-bound passes, AT-06 72 h outage, AT-07 partition, AT-08 clock rollback on the device) is NOT evidenced here; this
  ADR covers the cloud half only.
- The reference and issuer keys are not yet in `.env.example` (shared file). Real KMS/HSM adapter, mTLS, and a worker-driven refresh are
  `blocked-external` or later slices.

## Routes added (for the AT-01 route inventory, which this slice may not edit)

`tests/acceptance/test_at01_cross_society_isolation.py::test_route_inventory` fails for ANY new route until it is classified. Proposed
classification (owner of that file to apply):

- `GLOBAL_ROUTES` (no society in the path; the society comes from the signed device row; covered by `tests/integration/edge/`):
  `GET /v1/edge/me`, `GET /v1/edge/keys`, `GET /v1/edge/policy`, `POST /v1/edge/sync/batches`.
- `CASES` (society path, probed like the others): `GET {SOC}/edge/policy`, `GET {SOC}/edge/status`, `GET {SOC}/edge/quarantine`,
  `POST {SOC}/edge/policy/publish` (Meera is secretary: authorised), `GET {SOC}/standing-rules`, `POST {SOC}/standing-rules`
  (`meera_authorised=False`, household only; body `unit_id` is taken from the body and is checked against the caller's grants: 404 for a foreign
  unit), `DELETE {SOC}/standing-rules/{rule_id}` (`foreign=("rule_id",)`, `meera_authorised=False`).

## Update (slice 3 integration, ADR-0019)

Items above that changed: edge-local pass entries ARE now projected onto `visits` and `invitations.uses` (decision 3 and the open issues); the seed step is ON by default
(decision 7) and its gateways are unbound society gateways; `/v1/edge/keys` also publishes `pass_keys`; the stale-clock rule allows for an outage; the worker runs the publisher and
the visits sweep (`services/worker`, migrations 0010, 0104, 0206, 0314; publish-on-poll stays the default until a deployment sets `DWAAR_EDGE_PUBLISH_ON_POLL=false`); the issuer and
reference keys are in `.env.example` and generated by `make setup`. AT-05..AT-08 now also run end to end against this cloud (`tests/acceptance/test_at0{5,6,7,8}_e2e.py`).
