# ADR-0018: Edge gateway (store, policy, decision engine, clock, outbox/sync, local API)

- Status: accepted (slice 3, edge side)
- Date: 2026-10-05
- Deciders: Viz (owner), build team (slice 3, edge)
- Related: PRD 7.2, 7.4, 9.2 (GATE-01/02/05/06/07/08/14), 9.3 (EDGE-01..EDGE-10, authority split, outage runbook), 12.3, 14
  (NFR-02/04/09/10), 16 (AT-05..AT-08), Appendix C, D-11/D-12/D-13; INV-03, INV-07, INV-12; ADR-0001/0002/0003;
  code: `services/edge/dwaar_edge/`; tests: `services/edge/tests/unit/`, `tests/integration/edge_gateway/`,
  `tests/acceptance/test_at05..08*.py`

## Context

The gate must keep deciding and recording when the WAN is down for days, when the gateway process restarts, when two gates
cannot see each other, and when a device clock is wrong. The cloud is authoritative for identity, passes and revocations (signed,
monotonic policy snapshots); the gate is authoritative for physical observations (append-only events). A model never decides entry
(INV-03) and nothing admits anyone on a timeout.

## Decisions

### 1. Store (EDGE-01, EDGE-02)
- One SQLite file, WAL, `PRAGMA synchronous=FULL`, verified at open (the process refuses to start if the pragmas are not in force).
  One writer process: an exclusive `flock` on `<db>.lock`; a second process gets `StoreLockedError`. One connection behind an RLock;
  `transaction()` is `BEGIN IMMEDIATE ... COMMIT` and re-entrant. Network-share paths are refused.
- Sensitive columns (outbox wire JSON, policy snapshot blob, pending/decision/override/review details, visitor alias) are sealed with
  the `dwaar_common.crypto` AES-256-GCM envelope; AAD binds society, table, column and row, so a value cannot be moved. Test:
  none of the invented credential refs, nonces or aliases appear in the database or backup files.
- Migrations are checksummed and ordered (`schema_migrations`); a database from a newer gateway is refused. Startup runs
  `PRAGMA integrity_check`, `foreign_key_check` and the torn-write invariant (outbox head never ahead of the device counter).
  `backup()` uses the SQLite backup API, fsyncs and integrity-checks the copy; `restore_backup()` is tested.
- Every mutating operation is ONE transaction: domain change (movement projection / pass ledger), signed outbox event, LAN feed
  row, audit row and the idempotency record. The API returns success only after COMMIT. Crash points inside the transaction are
  killed with a real `SIGKILL` in subprocess tests.
- `fsync_probe()` measures write+fsync latency on the data volume. It cannot prove durability; real verification is a hardware task.

### 2. Signed policy (EDGE-04, EDGE-05)
- Verification order: envelope -> provisioned issuer key by `issuer_key_id` (keys come from commissioning config, never from the
  snapshot) -> Ed25519 signature over `canonical_json(snapshot minus signature)` -> `schema_version` -> typed parse that FORBIDS
  unknown fields -> society -> data minimisation -> validity -> rollback (`seq` must increase; equal `seq` is `duplicate`).
- Data minimisation is enforced by the typed manifest (any unknown member, such as a phone or name, rejects the snapshot) plus a
  scan of the free-form members (`standing_rules[].params`, `visitor_alias`) for personal-data keys and phone/e-mail-like values.
- Apply is one transaction (snapshot row, revocation merge, `policy_seq`, audit); the in-memory `PolicyBundle` is swapped after
  commit. The last three snapshots are kept; at startup the newest verifiable one is loaded (re-verified) and falls back to the
  previous one. Revocations are merged with max-version-wins and never removed ("apply newest known deny").
- Policy age = now minus the later of `issued_at` and the last authenticated cloud confirmation (200 applied or 204 up to date). A
  confirmation is recorded only while the clock is trusted and has not jumped, so a wrong clock cannot make a stale policy look
  fresh. LIMITATION: a 204 is not signed; it relies on the transport being authenticated (mTLS, not in this slice).
- Hard caps: resident offline validity <= 72 h, guest offline entitlement <= 2 h, clock uncertainty limit <= 60 s. Policy timing can
  only tighten them.

### 3. Decision engine (INV-03, GATE-06, GATE-14)
`decide(policy, request, clock_state) -> Decision{allow|deny|needs_guard|needs_supervisor, reason_code, evidence, review_required,
fallback_options}` is pure: it imports no clock, no I/O, no randomness (a test greps the module). There is no branch that maps a
timeout or missing data to `allow`; every non-allow carries the explicit guard options (hold, leave at gate, lobby only, intercom, deny).
- Resident: unknown -> guard; revocation list or `revoked` -> deny; presented version older than the cached one -> deny;
  `suspended` -> guard; credential window and policy age (<= 72 h) are checked with the clock uncertainty as a margin, outside or
  ambiguous -> guard (never an automatic lockout from home).
- Guest pass: nonce (constant-time), revoked version, BOUND GATE (wrong gate -> supervisor), clock trust (below), window, 2 h offline
  entitlement (policy age), uses. Expired / stale -> guard confirmation; never a silent allow.
- Single-use consumption is serialised by the gateway ledger: an allow RESERVES a use (hold, 120 s TTL) in the evaluation
  transaction; the observed entry turns it into `consumed`. A second terminal gets `pass_in_use`, later `pass_replay_consumed`.
  Cloud `uses_remaining` and the ledger are combined with `max`, never added (both count the same uses).
- Restricted standalone (terminal without its gateway): the same engine with `mode=RESTRICTED_STANDALONE`. A pass not bound to this
  gate cannot be guaranteed single-use: `global_single_use_not_guaranteed` (single-use) or `no_escrow_allocation` (multi-use) ->
  supervisor. Optional per-gate escrow (`allocate_escrow`) lets each gate consume only its pre-allocation.
- Exit lanes always return `allow` (`egress_always_permitted`): essential egress is independent of cloud, policy age and clock (GATE-07).
- Standing rules (GATE-14): `allow_window`, `leave_at_gate`, `deny_category` with `category` + `start_local`/`end_local` (IST, may wrap
  midnight). Precedence deny > leave_at_gate > allow; a malformed rule grants nothing; automatic allow needs a trusted clock.
- Photo / ANPR / face "credentials" are not credential kinds: they are denied as `invalid_credential` (GATE-06).

### 4. Clock (EDGE-05, AT-08, PRD 7.4)
Estimate = trusted anchor + monotonic elapsed (anchor comes from the cloud response HTTP `Date` + half the round trip, uncertainty =
RTT/2 + 1 s resolution + drift allowance of 100 ppm). Without an anchor (fresh process) the estimate is `max(wall, persisted high-water
mark)` and uncertainty is reported as the schema maximum (24 h = unknown). A wall clock that steps against the monotonic clock, or
disagrees with the anchor beyond the uncertainty, latches a jump flag until the next trusted sync. Effects:
- guest passes and standing-rule allows: a backwards or forwards jump, uncertainty > the limit (60 s), or no trusted time after a
  restart -> `needs_supervisor`, `review_required`; nothing is reserved;
- residents are NOT locked out: they are decided on the clamped estimate (a backwards wall clock cannot extend a window) and flagged
  `review_required`; with a trusted clock the uncertainty widens window/age boundaries into guard-assisted checks;
- every event records `clock_uncertainty_ms`; the first jump is recorded once as a `ClockAnomalyDetected` event and a review item.

### 5. Outbox and sync (EDGE-03, EDGE-10, NFR-09, NFR-10)
- Device sequence from a counter in `meta` (updated in the same transaction as the event), so pruning acknowledged rows can never
  reuse a number. Events are signed with the device key at creation and stored sealed; resend sends the identical bytes.
- Batches: <= 500 events and <= 1,000,000 bytes (reading "1 MB" strictly). Per-event outcomes are applied atomically
  (`accepted`/`duplicate` -> acked, `quarantined`, `rejected_transition`); `gaps` re-queue acknowledged rows; a quarantined event is
  never resent and never blocks later ones; a single event the cloud refuses with 400/422 is quarantined locally; 413 halves the batch.
- Backoff: exponential with full jitter (`U(0, min(cap, base*2^n))`, cap 300 s). 401/403 keeps events and reports `auth_failed`.
- EDGE-10 ordering: each cycle pulls policy first (tombstones) and then uploads events.
- Request signature (shared contract): `X-Dwaar-Device`, `X-Dwaar-Timestamp`, `X-Dwaar-Signature = ed25519(METHOD\nPATH_WITH_QUERY\nTIMESTAMP\nsha256_hex(body))`.
- Media is deferred: events carry metadata only (payload <= 2,000 bytes of canonical JSON; the cloud quarantines above 2,048).
- 409 `stale_version` on the policy poll (cloud cursor behind the gateway) is never a rollback: the gateway keeps its policy, reports
  `cursor_ahead_of_cloud` in its status and lets policy age drive guard-assisted verification. A 401 on a request whose timestamp is more
  than 60 s from the response's `Date` is retried ONCE stamped with the server's time (a wrong clock must not lock the gateway out of
  the very sync that repairs it); the clock itself is synchronised only from an authenticated 2xx.

### 6. Local API (EDGE-01, GATE-07, Appendix C)
FastAPI, bound to `DWAAR_EDGE_BIND` (default 127.0.0.1; set to the security-LAN address at commissioning); no inbound internet port,
no OpenAPI/docs routes. Bearer tokens are Ed25519-signed by the gateway token key at commissioning, bound to one device and role,
expire and can be revoked; a device the signed policy marks non-active is refused. A guard terminal can act only for its assigned
gate. Endpoints under `/v1/terminal`: `evaluate`, `entries`, `exits`, `guard-decisions`, `overrides` (supervisor; expires at shift end,
capped at 16 h), `emergency-entries` (defined local authority + reason), `fresh-approvals` (explicit fallback, never allows),
`pending`, `inside` (with confidence), `status`, `feed` (long poll), `cache/{gate}`, `tombstones`, `tombstones/ack`, `reconcile`, `review`.
Mutations take an optional `client_action_id` (UUID): replays return the stored result, also under concurrency. The API module
imports no sqlite code; terminals never touch the database file.

### 7. Partition semantics (AT-05/06/07 logic)
`StandaloneTerminal` (terminal logic) verifies the cached signed snapshot itself, keeps a gate-scoped local ledger and queues
observations with its own sequence. On return, `reconcile_standalone` requires tombstones to be processed first (EDGE-10), ignores
duplicate `(device, tseq)` uploads, keeps BOTH observations of a double-used single-use pass and raises a `single_use_conflict`
review item, and drops the personal alias of a tombstoned pass. Reconciled observations are forwarded as gateway-signed events that
keep the terminal's real `occurred_at` and uncertainty.

### 8. Safety
No actuator code. `SimulatedBarrier` refuses `simulation=False`, has no network/serial/GPIO code and nothing calls it; a test asserts its
command log stays empty across boot, decisions, restart. Boot and reconnect only open the store, load policy and sync (HW-03 groundwork).

## Configuration (commissioning; `EdgeConfig.from_env`, no secrets in the repository)
`DWAAR_EDGE_SOCIETY_ID`, `DWAAR_EDGE_DEVICE_ID`, `DWAAR_EDGE_DATA_DIR` (local disk, never a network share), `DWAAR_EDGE_DEVICE_KEY`
(+ `_KEY_ID`: per-device Ed25519 seed, b64url), `DWAAR_EDGE_ISSUER_KEYS` (`id=pubkey,...` pinned policy issuer keys),
`DWAAR_EDGE_PASS_KEYS` (QR signing public keys, optional), `DWAAR_EDGE_PII_KEYS` + `DWAAR_EDGE_PII_ACTIVE_KEY_ID` (field-encryption
master keys), `DWAAR_EDGE_TOKEN_KEY` (signs terminal tokens), `DWAAR_EDGE_CLOUD_URL` (starts the sync worker), `DWAAR_EDGE_BIND` /
`DWAAR_EDGE_PORT` (security-LAN address), `DWAAR_EDGE_SIMULATION` (default true). Tunables with defaults in `EdgeConfig`: hold TTL 120 s,
admission validity 600 s, override cap 16 h, stale terminal 1 h, inside-stale 24 h, retention of decision log 14 d / feed 24 h /
client actions 72 h (`Gateway.run_maintenance`). Run: `python -m dwaar_edge`.

## Contract alignment (docs/contracts/edge-sync.md, ADR-0017)
Implemented as written by the cloud side: lane directions `in|out|both` (also accepts `entry|exit`), invitation `windows` (a recurring
pass is honoured window by window, never by its outer bounds), standing rules with `visit_kind`/`category`/`action`
(`allow|leave_at_gate|hold|deny`)/`days`/`start_local`/`end_local`/`tz` and DATE-valued `effective_from/to` (inclusive local days; a
midnight-wrapping window belongs to the day it started on), `suspended` residents, masked aliases, unknown outcome keys ignored,
`credential_kind`/`decision_source`/`exit_basis` vocabularies. An `allow` standing rule only pre-authorises the category inside the
window: the evidence carries `guard_confirms_identity: true`. Not used: `GET /v1/edge/keys` and `/v1/edge/me` (issuer keys are pinned in
configuration; a rotation needs the new key provisioned), `cursor` (sent as nothing).
Integration notes for the cloud side (not changed here):
- Resident and emergency entries have no cloud visit, so `entity_id` is a gateway-generated movement id and the payload carries
  `credential_kind=resident_app|none` and `decision_source`. The cloud's `decide_transition` currently answers `rejected_transition`
  (`entry_unknown_visit`) with an `unauthorised_entry` exception for every such entry; it should treat a cached-policy resident entry
  (or a supervisor-override/emergency entry) as a recorded observation without a visit.
- Guest-pass entries carry `invitation_id` in the payload (the gateway does not know the cloud visit id); `entity_id` is a movement id.
- Edge-only event types are accepted by the cloud as `recorded_not_projected`.

## Event types produced
`EntryObserved`, `ExitObserved` (payload `gate_id`, `lane_id`, `credential_kind`, `decision_source`, `exit_basis`; flags
`review`, `conflict`, `emergency`, `authority`, `reason`) plus three edge-only types: `GuardDecisionRecorded`,
`SupervisorOverrideRecorded`, `ClockAnomalyDetected`.

## Measurements (build machine, NOT certified hardware)
Machine: 4 vCPU x86_64 VM, virtualised disk (write+fsync p50 ~0.4 ms, which is far faster than an industrial SSD with power-loss
protection would be asked to prove), Python 3.12, loopback networking, one process. Every number is from
`tests/integration/edge_gateway/test_nfr_edge.py` (`DWAAR_BENCH_OUT=<file>` appends the raw JSON); `slow`-marked tests run with `make test`.

| Target | Measured here | How |
|---|---|---|
| NFR-02 decision p95 <= 150 ms, p99 <= 300 ms, 50,000 cached credentials, 20 events/s burst | local API over loopback, 30 bursts of 20 concurrent terminals (600 decisions): two runs on a shared, loaded machine: p50 46.7 / 52.4 ms, **p95 67.1 / 87.1 ms, p99 75.7 / 98.3 ms**, max 82.6 / 108.3 ms. In-process service time (decision + durable decision log + feed, closed loop, n=3000): p50 0.49 ms, p95 0.78 ms, p99 1.9 ms. Pure engine: p95 0.07 ms. Policy apply with 50,000 residents: 1.45 s. Peak RSS 219 MB | most of the 47 ms median is GIL/thread contention of 20 simultaneous client threads plus the server thread pool, not the engine |
| NFR-04 LAN propagation p95 <= 1 s | **p95 8.5 / 8.7 ms** (two runs), p99 9.9 / 11.7 ms, max 11.4 / 20.4 ms (100 samples, terminal B long-polls the feed, terminal A posts an entry) | loopback only; says nothing about a real switch/Wi-Fi |
| NFR-09 72 h / 60,000+ events with restarts | 60,000 entries through the real evaluate+record path over 72 simulated hours with 6 restarts (full integrity check each): **0 lost, 0 duplicates**, order preserved; 1.5-1.6 ms per event (evaluate + record, two durable transactions); restart <= 323 ms; database 158 MB | injected clock; process restarts are close/reopen, hard kills are covered by the SIGKILL tests |
| NFR-10 60,000 events reconciled <= 10 min at 5 Mbps, 2 KB/event | **SIMULATION**: 122 batches, 121.7 MB, virtual time **200.9 s** (ideal) and **268.1 s** (25 % protocol overhead, 200 ms RTT) | throttled fake transport on a virtual clock; real CPU 27-28 s incl. FakeCloud signature verification. Not a measured uplink |
| kill -9 recovery | 8 subprocess tests: 3 crash rounds x 3 loops of free-running kills, plus kills inside the transaction at 3 points and during policy apply: every acknowledged event present, no torn state, sequence contiguous | a process kill is not a power cut |

## Not verified / not done (honest list)
- Real power-loss and fsync-lie behaviour (needs the gateway hardware, EDGE-01/EDGE-08); NFR-02 on the certified gateway.
- mTLS / certificate pinning / A-B signed updates / health telemetry (EDGE-09), TPM-backed keys (D-12): not in this slice. Keys come
  from configuration/environment.
- Real cloud wiring: all sync tests use `FakeCloud`, an in-process fake of the contract.
- NFR-10 is a simulation on a virtual clock, not a measured uplink.
- The Android terminal UI and Room cache (a later slice) mirror `StandaloneTerminal`; its behaviour here is the specification, not the app.
- Fresh remote approval itself (household push cascade) is a cloud flow; the edge only provides the explicit fallback path.
- Backups: `backup()` and `backup_rotating()` exist and are tested; scheduling them is a deployment task.

## Update (slice 3 integration, ADR-0019)

"Real cloud wiring" is no longer a gap: the gateway runs against the real API (`tests/integration/edge_e2e/`). `GET /v1/edge/keys` IS used, once, at commissioning
(`python -m dwaar_edge.provision`), to pin the issuer and guest-pass keys; the gateway still verifies snapshots against pinned keys only. Changes made on this side: `Retry-After` is honoured
(clamped to one hour), a revoked pass no longer reads as fully used (`Invitation.cloud_used`), standalone observations carry the pass's `max_uses` so an expired pass is not judged as a
single-use pass, and `__main__` documents the society-gateway enrolment rule (no gate binding). The "Integration notes for the cloud side" above are resolved by ADR-0019 decision 1.
