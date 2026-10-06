# Edge sync contract (cloud <-> on-site gateway)

Status: implemented by `services/api/dwaar_api/modules/edge/` (ADR-0017). Authority: PRD 9.3 (EDGE-01..10), 12.1, 12.3, 12.4.
Everything the edge agent was told in the shared brief holds. This file only adds detail and lists every **additive** point. Where the
brief was ambiguous the cloud behaviour below is the contract.

## 0. Additions and clarifications to the shared brief (all additive)

1. Signature header value is `ed25519:<base64url, no padding>` (the `dwaar_common.signing` form). A bare base64url value is also accepted.
2. Invitation entries in the policy manifest carry one **extra** key `windows: [{start, end}]` (explicit ISO-8601 windows, ordered). A
   recurring pass is a list of windows; `window_start`/`window_end` are only the outer bounds. An edge that honours only the outer bounds
   would accept a milk-vendor pass at 15:00. Edges MUST use `windows` when present.
3. Each outcome carries `index` (position in the request `events` array) and, when relevant, `reason`, `original_status`, `exception_id`,
   `access_event_recorded`. Unknown outcome keys must be ignored.
4. `GET /v1/edge/keys` (device-signed) lists the policy issuer public keys (`active` and `retired`) so an edge can verify snapshots and
   survive key rotation. A real deployment pins the first key at provisioning; local development derives it (section 8).
5. `GET /v1/edge/me` (device-signed) returns the device record, society, key id, policy cursor, sync cursor and `server_time` (the edge may
   use it as one input to its clock-uncertainty estimate; it is not a trusted time source).
6. Batch body may carry `schema_version` (int, default 1). Any other value is refused with 400 `invalid_schema`.
7. Quarantined events keep their `seq`; for acknowledgement they count as **disposed** (see 4.3). Statuses stay the four of the brief
   (`accepted | duplicate | quarantined | rejected_transition`); there is no separate `rejected` status: a wrong-society or wrong-schema
   event is `quarantined` with a reason.
8. Resident `status` may be `active | suspended | revoked` (`suspended` = committee hold). `revoked` entries stay for a tombstone retention
   period (default 30 days, EDGE-10) and are also listed in `revocations`.

## 1. Device authentication (EDGE-09 note)

Every request carries

| Header | Value |
|---|---|
| `X-Dwaar-Device` | device UUID (devices table, slice 2) |
| `X-Dwaar-Timestamp` | UTC ISO-8601 (`2026-10-05T13:41:07Z` or with milliseconds), at most **120 s** from cloud time either way |
| `X-Dwaar-Signature` | Ed25519 signature over the canonical bytes below, with the device's registered private key |

Canonical bytes (UTF-8): `METHOD "\n" PATH_WITH_QUERY "\n" TIMESTAMP "\n" sha256_hex(body)` where `METHOD` is upper case, `PATH_WITH_QUERY` is
the request target exactly as sent (`/v1/edge/policy?after=12`), `TIMESTAMP` is the header string byte for byte, and `body` is the raw
request body (empty for GET: `e3b0c442...b855`).

* Unknown device, bad/missing signature, stale or malformed timestamp, malformed headers: **401** `unauthenticated` (identical body, no hint which).
* Valid signature but the device is not `active` (pending, rejected, revoked): **403** `not_authorised`, no data. Revocation takes effect on the
  next request (the device row is read on every request, nothing is cached).
* More than the per-device budget: **429** `rate_limited` with `Retry-After`. Default 60 requests burst, 5/s sustained (config).
* A captured request can be replayed inside the 120 s window. Both endpoints are idempotent so a replay creates nothing; this is a
  documented limit, not a claim of replay-proof transport. Real mTLS with per-device certificates (EDGE-09) is a deployment-layer
  control and is NOT implemented or claimed here.
* Errors use the PRD 12.2 body `{request_id, code, message, message_key, details}`.

## 2. `GET /v1/edge/policy?after={seq}`

* 200 with the **latest** signed snapshot when its `seq > after`; 204 (no body) when there is nothing newer (`after == latest`).
* 409 `stale_version` (`details.reason = "cursor_ahead_of_cloud"`, `details.latest_seq`) when `after > latest`: a device must never be
  told to roll back; it should alert and ask for guard-assisted verification.
* `after` omitted = 0. The value is recorded as "policy sequence this device has applied" (sync metrics).
* While no worker exists the cloud publishes a fresh snapshot on a poll if content changed or the last one is older than the refresh
  interval (config `publish_on_poll`, default on). The worker takes this over later.

Snapshot (signature is over the canonical JSON of everything except `signature`):

```json
{
  "schema_version": 1, "society_id": "...", "seq": 17,
  "issued_at": "2026-10-05T09:00:00Z", "valid_until": "2026-10-08T09:00:00Z", "issuer_key_id": "ed-0123456789abcdef",
  "manifest": {
    "gates":   [{"id": "...", "kind": "mixed"}],
    "lanes":   [{"id": "...", "gate_id": "...", "direction": "in|out|both"}],
    "devices": [{"id": "...", "kind": "terminal", "gate_id": "...|null", "status": "active|revoked"}],
    "residents": [{"credential_ref": "cr_...", "person_ref": "pr_...", "unit_id": "...", "status": "active|suspended|revoked",
                   "valid_from": "...", "valid_until": "...|null", "revocation_version": 0}],
    "invitations": [{"id": "...", "gate_id": "...|null", "window_start": "...", "window_end": "...", "windows": [{"start": "...", "end": "..."}],
                     "max_uses": 1, "uses_remaining": 1, "revoked_version": 0, "nonce": "...", "kind": "guest", "visitor_alias": "T*** V***"}],
    "standing_rules": [{"unit_id": "...", "rule_kind": "leave_at_gate|allow_window", "params": {...}, "effective_from": "YYYY-MM-DD", "effective_to": "YYYY-MM-DD|null"}],
    "timing": {"approval_expiry_s": 90, "cascade_steps": [...], "guest_offline_max_s": 7200, "resident_offline_validity_s": 259200,
               "clock_uncertainty_limit_ms": 60000, "policy_age_limit_s": 259200},
    "revocations": [{"ref": "...", "version": 41}]
  },
  "signature": "ed25519:..."
}
```

* `seq` is monotonic per society and gapless; the edge applies atomically and rejects any `seq <= applied`.
* `valid_until = issued_at + policy_age_limit_s` (72 h by default, EDGE-05). A refresh (same content, new `seq`) is issued every 6 h.
* Data minimisation (EDGE-04): no phone, no name beyond a masked alias, no finance. `credential_ref` / `person_ref` are keyed opaque references.
  `revocations` is sorted by `version` descending and is the first thing to apply; a revoked ref is also present in `residents`/`invitations`
  with status/`revoked_version` set. A re-activated membership gets a **new** `credential_ref`.
* Resident `valid_until` is the membership end (null = open). The offline validity of a credential is
  `min(valid_until, time of last applied snapshot + resident_offline_validity_s)`; after that: guard-assisted verification, never lockout from home.
* `standing_rules.params` (GATE-14): `{visit_kind: guest|delivery|service|cab|vendor|staff, category?: str, action: leave_at_gate|allow|hold|deny,
  days: [1..7 ISO weekday], start_local: "HH:MM", end_local: "HH:MM", tz: "Asia/Kolkata"}`; a window may wrap midnight. An `allow_window`
  rule never replaces guard confirmation of identity: it only pre-authorises the category inside the window. Evaluated locally by the edge.

## 3. `GET /v1/edge/me`, `GET /v1/edge/keys`

`me`: `{device: {id, society_id, kind, name, gate_id, state, key_id, simulation, last_seen_at}, policy: {latest_seq, applied_seq, latest_issued_at},
sync: {highest_contiguous_seq, last_sync_at}, server_time}`. `keys`: `{keys: [{key_id, public_key (b64url), status, simulation}]}`.

## 4. `POST /v1/edge/sync/batches`

Body `{device_id, cursor?, schema_version?, events: [EdgeEvent wire form]}`; `device_id` must equal the authenticated device (else 400).
At most **500 events** and **1,048,576 bytes** (1 MiB) of body; larger: **413** `invalid_schema` (`details.reason = payload_too_large | too_many_events`),
nothing is stored. `cursor` is accepted and ignored by the server (the server's `highest_contiguous_seq` is the cursor).

### 4.1 Per-event algorithm (EDGE-07), inside ONE database transaction per batch, one savepoint per event

1. Parse against the shared `EdgeEvent` model. Invalid -> `quarantined` (`schema_invalid`; `schema_version_mismatch` if the event names another version).
2. Verify the event signature with the **device's** registered key (and `payload_hash`). Invalid -> `quarantined` (`bad_signature`).
3. Reject another society (`wrong_society`), another device (`wrong_device`) -> `quarantined`. The event is never written into the claimed society.
4. Deduplicate by `(device_id, event_id)` and `(device_id, seq)`:
   * same `event_id`, same content already stored -> `duplicate` (original `accepted`) or the original status repeated with `original_status` set;
   * same `seq` with a different `event_id`, or the same `event_id` with other content -> `quarantined` (`seq_conflict` / `event_id_conflict` /
     `payload_mismatch`); both observations are preserved, nothing is overwritten.
5. Payload checks (`payload_too_large`, `pii_in_payload`: a key that names a phone, name, OTP, bank field...) -> `quarantined`.
6. Enforce the permitted transition (`EntryObserved`, `ExitObserved`). The physical observation is **always** recorded as an `access_events` row
   (append-only, unique `(device_id, seq)`) even when no state change is allowed. `entity_id` is looked up as a **cloud visit** first
   (an approved visit, a redeemed pass); when no visit has that id it is an **edge-local movement** (the gateway mints movement ids for residents,
   passes, standing rules and overrides) and the observation is judged by its payload:
   * cloud visit, entry for an `authorised` visit inside its window -> `accepted` (visit becomes `inside`);
   * cloud visit, entry for one that is expired, denied, cancelled or not authorised -> `rejected_transition` (`entry_without_authorisation`),
     `access_event_recorded: true`, `exception_id` for supervisor review (`unauthorised_entry`). Observation never creates permission;
   * cloud visit, exit: any visit may be exited (essential egress); `reconciled_unknown` stores no exit time; an exit without an observed entry opens an exception;
   * cloud visit, entry/exit event with `clock_uncertainty_ms` above the policy limit (60 s) -> recorded, state unchanged, `rejected_transition`
     (`clock_uncertain_review`) + exception (an uncertain-clock EXIT still applies);
   * edge-local movement, `decision_source` `cached_policy | rfid | anpr | guard_assisted` -> `accepted` (`edge_entry_recorded`), no visit is created and
     no permission either; `payload.invitation_id` is checked against the passes the cloud knows: unknown -> `rejected_transition`
     (`entry_unknown_invitation`), revoked before `occurred_at` (by more than the stated, capped uncertainty) -> `rejected_transition`
     (`entry_after_revocation`), both with an `unauthorised_entry` exception;
   * edge-local movement, `decision_source = supervisor_override` -> `accepted` + a `manual_entry` exception (GATE-07); `payload.conflict` -> `accepted`
     + an `other` exception;
   * edge-local movement, `decision_source` `resident_app | ivr` (a remote decision that can only be verified against a cloud visit) ->
     `rejected_transition` (`entry_unknown_visit`) + exception;
   * exit of an edge-local movement whose entry the cloud holds -> `accepted` (`edge_movement_exit`); with no matching entry ->
     `rejected_transition` (`exit_without_entry`) + exception (still recorded);
   * any other `type` -> `accepted` with `reason: recorded_not_projected` (stored in the ledger, not interpreted).
7. Commit record + audit row + outbox row atomically, then answer. Event ids are never regenerated by the cloud.

A bad event never blocks the later events of the batch or of later batches. An unexpected server-side failure while processing one event
quarantines that event (`processing_error`) instead of failing the batch. Not done yet: the cloud does not project edge-local movements onto
`visits` (visitor history of a pass entry) nor onto `invitations.uses`; single-use accounting stays with the edge arbiter (PRD 9.3).

`payload` fields read for observations: `lane_id?`, `gate_id?` (default: the lane's gate, then the device's gate; one must resolve),
`decision_source?` (default `cached_policy`; one of `cached_policy, resident_app, ivr, guard_assisted, supervisor_override, rfid, anpr`),
`credential_kind?` (default `none`; `qr, code, guard_assisted, resident_app, rfid, anpr, none`), `exit_basis?` (exit only; `scanned | observed |
reconciled_unknown`, default `observed`).

### 4.2 Response

```json
{"outcomes": [{"index": 0, "event_id": "...", "seq": 18452, "status": "accepted|duplicate|quarantined|rejected_transition", "reason": "...?"}],
 "highest_contiguous_seq": 18452, "gaps": [[18460, 18462]], "policy_cursor": {"latest_seq": 17}}
```

### 4.3 Acknowledgement and gaps

* Device sequences start at **1**. `highest_contiguous_seq` = the largest `N` such that every seq `1..N` is **disposed**: stored in the
  ledger (`accepted`, `rejected_transition`) or in quarantine. `0` = nothing yet. An event with `seq = 0` is stored but is not part of the
  acknowledgement arithmetic. `gaps` lists inclusive `[from, to]` ranges of missing seqs below the highest seq seen
  (at most 200 ranges). Arrival order does not matter; a late event fills its gap and the cursor jumps.
* The edge may delete its local copy of every event with `seq <= highest_contiguous_seq`, and of any event whose outcome it has read as
  `accepted/duplicate/rejected_transition/quarantined`.
* Re-sending a whole batch is safe and creates no rows; concurrent batches of one device are serialised by the cloud.

## 5. Clock handling (EDGE-05, server side)

`clock_uncertainty_ms` is stored with every event. `occurred_at` is **never** rewritten. An event is flagged (stored on the ledger row, one open
`clock_implausible` exception per device and flag at a time) when `occurred_at > received_at + clock_uncertainty_ms + 5 s` (`future`),
`received_at - occurred_at > policy_age_limit_s` (`stale`), or `clock_uncertainty_ms > clock_uncertainty_limit_ms` (`uncertain`).

## 6. Rate and size limits

Body 1 MiB, 500 events, per-device token bucket (`DWAAR_EDGE_RATE_CAPACITY`, `DWAAR_EDGE_RATE_REFILL_PER_S`), one event payload at most 2,048 bytes of canonical JSON (larger: that event is quarantined as `payload_too_large`).

## 7. Errors worth coding against

`401 unauthenticated`, `403 not_authorised`, `400 invalid_schema` (bad body/limits), `413 invalid_schema` (size), `409 stale_version`
(policy cursor ahead of cloud), `429 rate_limited`, `503 dependency_unavailable` (retry with backoff and jitter).

## 8. Local development only (simulation)

Everything below is derived from public labels and is **never** accepted outside `DWAAR_ENV=local|test`.

* Seed society `mh` has an edge gateway device named `Main gate edge gateway` (active, gate `Main Gate`, `simulation=true`).
  `python -m dwaar_api.modules.edge.localdev` prints its ids, the Ed25519 seed (`sha256(b"dwaar-local-edge-device|mh:Main gate edge gateway")`,
  base64url) and the policy issuer public key (`sha256(b"dwaar-local-edge-policy-issuer")` as seed).
* Production: `DWAAR_EDGE_POLICY_SIGNING_KEY` (seed, b64url), `DWAAR_EDGE_POLICY_KEY_ID`, `DWAAR_EDGE_RETIRED_KEYS` (`id:pubkey,...`),
  `DWAAR_EDGE_REF_KEY` (32 bytes b64url). Missing in non-local environments: the edge endpoints answer 503, the application still starts.
