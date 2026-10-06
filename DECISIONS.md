# Dwaar decisions

Two logs live here, as required by PRD 19.2 rule 9 and 19.5:

1. **Decision register** (PRD section 3): every default is *adopted* unless a Builder decision below says otherwise.
   Wording is a short paraphrase; the PRD (kept local, see B-001) is the authority.
2. **Builder decisions**: ambiguities and deviations resolved while building, with date and owner. Append new entries
   with the next free `B-` number; never rewrite an old one (supersede it with a new entry that cites it).

Items tagged `[LEGAL]`, `[CA]`, `[VERIFY]`, `[TBD]` in the PRD are configuration, disabled or unapproved by default.

## 1. Decision register (PRD section 3)

| ID | Decision | Default adopted for the build | Flags | Approver | Status |
|---|---|---|---|---|---|
| D-01 | Product name | Dwaar (placeholder name; trademark check pending, alternative noted in PRD) | | Owner | adopted default |
| D-02 | Pilot geography and entity type | Pune, Maharashtra co-operative housing societies; Bengaluru associations only after a Karnataka pack | [LEGAL] | Owner + local advocate | adopted default |
| D-03 | Target size | Societies of roughly 250 to 1,500 units; smaller only with a minimum fee | | Owner | adopted default |
| D-04 | Languages | English, Hindi, Marathi at M1; Kannada at M2; others after evaluation; no all-language accuracy claims | | Owner | adopted default |
| D-05 | Resident app | React Native (Expo) with TypeScript for iOS and Android, plus an accessible web view | | Tech lead | adopted default |
| D-06 | Guard app | Native Android (Kotlin, Room/SQLite) in device-owner kiosk mode; React Native only if kiosk, background and scanner tests pass | | Tech lead | adopted default |
| D-07 | Admin and committee console | Next.js App Router, TypeScript, Tailwind, shadcn/ui | | Tech lead | adopted default |
| D-08 | Backend | Python FastAPI modular monolith with background workers; split services only for proven scale or isolation | | Tech lead | adopted default |
| D-09 | Database and hosting | Managed PostgreSQL in an India region, multi-zone (default Supabase, Mumbai), RLS as defence in depth | | Tech lead | adopted default |
| D-10 | Identifiers | UUIDv7 in native `uuid` columns | | Tech lead | adopted default |
| D-11 | Offline sync | Application event protocol (PRD 9.3) between terminals, edge and cloud; no shared-file SQLite, no CRDTs for money or access; PowerSync only for resident/technician apps after a spike | | Tech lead | adopted default |
| D-12 | Edge gateway | Python service, encrypted SQLite (WAL, `synchronous=FULL`) on a Linux mini-PC with hardware-backed keys | | Tech lead + installer | adopted default |
| D-13 | Offline validity | Resident credentials 72 hours; guest passes at most 2 hours and bound to the assigned gate; supervisor overrides end with the shift | | Security supervisor | adopted default |
| D-14 | Approval request expiry | 90 seconds; never auto-allow | | Owner | adopted default |
| D-15 | Notification cascade | PRD 9.4 timings (push, alternate adult, masked IVR, WhatsApp/SMS link, expiry), all configurable within limits | | Owner | adopted default |
| D-16 | Visitor data visibility | 30 days operational (up to 90 with recorded justification) plus a restricted legal archive of at least one year | [LEGAL] | Counsel + society | adopted default |
| D-17 | Backups | 35-day encrypted rotation; restores re-apply deletion tombstones | | Security lead | adopted default |
| D-18 | AI provider | Provider-neutral adapter; default Anthropic Claude (Sonnet 5.5 for drafting/reasoning, Haiku 4.5 for high-volume extraction, Opus 5.5 only where Sonnet fails evaluation); model, region, retention and training terms need privacy-owner approval | | Privacy owner | adopted default |
| D-19 | Speech | Self-hosted faster-whisper in an India region; evaluate Indic-specialised ASR for Kannada, Odia, Bengali | | Tech lead | adopted default |
| D-20 | Payment partner | RBI-authorised payment aggregator (default Razorpay): UPI, AutoPay, BBPS via a BBPOU when commercially confirmed, per-unit virtual accounts, direct settlement to the society account | | Treasurer + provider | adopted default |
| D-21 | Telephony, SMS, WhatsApp, video | Indian cloud telephony (IVR, masking), DLT-registered SMS, WhatsApp utility templates, a video provider for hybrid meetings; vendors undecided | [TBD] | Owner | adopted default |
| D-22 | Accounting exports | Tally-importable XML and Zoho Books API; one authoritative ledger; no uncontrolled two-way sync | | Treasurer + CA | adopted default |
| D-23 | First hardware adapters | Isolated dry-contact relay for one certified barrier model plus one UHF RFID reader model; ANPR at M3 | | Installer | adopted default |
| D-24 | Binding governance | Disabled until the society's legal pack is approved; opinion polls available | [LEGAL] | Counsel | adopted default |
| D-25 | Amenity restriction for defaulters | Disabled by default; non-essential amenities only, with uploaded legal basis, notice and appeal | [LEGAL] | Counsel | adopted default |
| D-26 | Pricing tiers | Three tiers (Essential, Operations, Township) per contracted flat per month with tier minimums; infrastructure modules priced as add-ons; amounts are configuration (see PRD) | | Owner | adopted default |
| D-27 | Billing unit | All contracted units; a transparent vacancy concession only if justified | | Owner | adopted default |
| D-28 | Payment cost policy | Society absorbs MDR and gateway fees; no surcharge passed to residents; fee shown in the committee cost report | [VERIFY] | Treasurer | adopted default |

## 2. Builder decisions

Format: ID, date, owner, decision, reason / consequence.

### B-001 PRD text kept git-ignored
- Date: 2026-10-05. Owner: Viz.
- The PRD is marked *Confidential draft*, so `docs/prd/Dwaar_Master_PRD_v2.0.txt` stays in the working tree but is
  git-ignored (`docs/prd/README.md` is committed). Builders and `tools/trace_check.py` read it locally.
- Consequence: CI has no PRD. Anything that reads it must skip when absent; committed registers under
  `docs/traceability/` carry paraphrases only. This file paraphrases the register rather than quoting it.

### B-002 Synchronous SQLAlchemy 2 + psycopg 3 and plain checksummed SQL migrations
- Date: 2026-10-05. Owner: Viz.
- Data access is synchronous SQLAlchemy 2.0 (mostly explicit SQL through `text()`/Core) on psycopg 3, not an ORM-heavy or
  async stack. Schema changes are plain ordered SQL files with recorded checksums, not Alembic autogenerate.
- Reason: auditability and correctness over cleverness; RLS, grants and constraints must sit in the same reviewed SQL file
  as the table (PRD 19.2 rule 2). See ADR-0002.

### B-003 Extra packages: `packages/dwaar-common`, `packages/dwaar-packs`, `tools/`
- Date: 2026-10-05. Owner: Viz.
- PRD 19.1 does not list these. `dwaar-common` is the shared Python library (UUIDv7, paise money, time, event envelopes,
  Ed25519 signing, envelope crypto, errors, logging, i18n lookup); `dwaar-packs` loads and validates versioned legal and
  tax packs; `tools/` holds developer scripts and `trace_check.py`. See ADR-0001.

### B-004 pgvector is not installed in the build environment; M2 AI retrieval is deferred
- Date: 2026-10-05. Owner: Viz.
- The build machine has PostgreSQL 16 without `pgvector`. Retrieval-backed AI features (M2) are deferred; the schema
  migrations do not depend on it, and the database bootstrap deliberately does not create the extension. Nothing in M0/M1
  is blocked.

### B-005 Each slice ends with a stop-and-report document; the build continues
- Date: 2026-10-05. Owner: Viz.
- Every slice ends with `docs/reports/slice-N.md` containing the PRD 19.6 stop-and-report content (requirement IDs done,
  tests, open questions, deviations). The build then continues to the next slice unless a genuinely blocking decision
  appears; non-blocking questions are listed in the report instead of halting.

### B-006 Android SDK bootstrap script instead of a preinstalled SDK
- Date: 2026-10-05. Owner: Viz.
- The build environment has no Android SDK. The guard app ships a bootstrap script that downloads and pins the SDK, and its
  business logic lives in a pure-Kotlin module testable on the JVM. Android CI is added later and device-level checks
  (kiosk mode, scanners, fsync on real hardware) stay `blocked-external` until run on real devices.

### B-007 Test harness conventions (platform step)
- Date: 2026-10-05. Owner: Viz.
- pytest uses `--import-mode=importlib` (added to the specified addopts) so identically named test files in different
  packages and services never collide. The harness plugin is `tests._harness.plugin`, loaded with `-p`; the repo root is on
  `pythonpath`, and `python -m pytest` or `uv run pytest` both work.
- `make acceptance MILESTONE=Mx` is cumulative: it runs every `at` test whose matrix milestone is at most `Mx`.
- Evidence is written only for acceptance tests that actually ran; the index lists the rest as "no evidence yet".
- Ruff does not enforce E501 (the formatter wraps code; prose strings may be long) and mypy is strict for source packages,
  the harness and tools. See ADR-0003.

### B-008 Database bootstrap lives outside migrations; the database is created with C collation
- Date: 2026-10-05. Owner: Viz.
- `infra/db/bootstrap_roles.sql` (cluster roles) and `infra/db/create_database.sql` (database, database-level grants,
  trusted extensions `pgcrypto`, `pg_trgm`, `btree_gist`, schema grants) are run by a superuser during provisioning, so
  migrations run as the non-superuser `dwaar_owner` and never need elevated rights.
- Databases are created with `LC_COLLATE 'C'` and `LC_CTYPE 'C.UTF-8'` so ordering is identical on a laptop, in CI and in
  tests; locale-aware ordering for display is done in the application. Revisit if the managed provider cannot offer it.

### B-009 Fix round 1 for W1 verification findings (security and integrity hardening)
- Date: 2026-10-05. Owner: Viz. Findings F01-F32, Q-01..Q-06 (numbering from the verification report).
- **Logging (F01-F04, Q-03, Q-04).** `make api` runs uvicorn with `--no-access-log`; the app additionally detaches uvicorn's own
  handlers. (Round 1 only stripped the query string from `uvicorn.access` and re-enabled it, so the raw PATH and the client
  ip:port still reached the log; B-010 drops that logger instead.)
  The scrubber is deny-by-default for credentials (any key containing token/secret/password/cookie/session/otp ...,
  whole `Authorization`/`Cookie` header values), folds Unicode digits to ASCII and redacts digit runs of 9+ digits in any grouping,
  plus email, PAN, IFSC, UPI VPA and GSTIN. Over-redaction is accepted; UUIDs, ISO dates, IPv4 addresses and long hashes are left
  readable. Numbers under innocuous keys are scrubbed too except under quantity keys (paise, count, ms ...).
  Audit masking additionally masks identity fields by key (email, pan, upi/vpa, ifsc, gstin, dob, address, plate, person-name
  compounds such as `visitor_name`); a bare `name` stays visible (object label). `record_audit(diff=...)` and outbox event
  payloads go through the same masker (outbox: masked, with a warning naming paths only, not rejected, so a write is never blocked).
- **Unique violations (F18).** SQLSTATE 23505 maps to 422 `already_exists` only for constraints registered with
  `register_society_scoped_unique(...)`; any other unique collision is the generic 409 `stale_version`, and 23503 is `not_found`,
  so a globally unique identifier is never an existence oracle for people of other societies. PRD 12.2 has no generic "conflict" code.
  Person/identifier endpoints must still be written as upserts (same answer for new and existing identifiers).
- **RLS (F05-F07).** The catalog guard (`find_rls_violations`) is deny-by-default and semantic: every relation a runtime role can
  touch needs society_id + FORCE RLS or an allowlist entry; matviews/foreign tables are banned; views owned by a bypassing role are
  flagged; policies are evaluated against a foreign society (always-true policies fail); cross-society worker/owner policies must be
  allowlisted by (table, policy). The database itself cannot stop a `GRANT` on a matview (an event trigger needs superuser), so CI is
  the control. `RequestContext.all_settings()` always writes all four GUCs, and the pool resets sessions (`RESET ALL`) on check-in.
  Migration 0008 narrows the idempotency policy to dwaar_app/dwaar_owner, makes outbox delivery columns and `audit_log.at`
  server-set (column-scoped INSERT) and adds `retention_class`/`legal_hold_id` to both tables. Default class `LOG` is a class
  CODE from the retention pack, no duration is encoded. Placing a hold on an append-only row needs an owner-only exception in the
  privacy-engine migration (0700 range); not built yet.
- **Idempotency (F10-F13).** All expiry decisions use the database clock inside SQL and the claim loop is bounded. A retry with the
  same key AND same payload replays the stored response even after `expires_at` while the row exists (the cleanup job decides
  when a key disappears); only a different payload may reclaim an expired key. Default TTL is now 7 days (72 h offline buffer,
  NFR-09). Money-moving endpoints still need a business-level unique key such as `client_action_id`; the HTTP key cannot cover
  arbitrarily old retries. Responses encode `Decimal` as strings and refuse floats. A 1 MiB default body limit (413,
  `Settings.max_request_body_bytes`, per-prefix overrides in `app.state.body_limits`) applies before buffering.
- **Auth (F15, F16).** The verifier requires `iat` and caps `exp - iat` (default 1 h, `DWAAR_ACCESS_TOKEN_MAX_LIFETIME_SECONDS`).
  `create_app` raises `ConfigError` outside local/test without a `session_store`; a DB-backed store belongs to the identity module.
- **Crypto/money (F22, F24, F26).** Phone/money/percent parsers accept ASCII digits only. `VerifierRing.add(..., society_id=,
  device_id=)` binds a key to its tenant/device and `require_binding=True` refuses unbound keys for events; `EdgeEvent.occurred_at`
  is normalised to milliseconds (what the signature covers) and sub-millisecond tampering fails verification; base64url decoding is
  strict and canonical. Rounding modes are validated (`money.div_round` is the single implementation, used by `dwaar_packs`).
- **Packs (F28-F32).** Approval is evidence, not a claim: a pack is binding only if `DWAAR_PACK_APPROVALS` (deployment
  configuration, `id@version=sha256:<content hash>`, produced by `python -m dwaar_packs pin <file>`) pins its exact content;
  `FilePackRepository` serves unproven claims as unapproved. `DWAAR_PACKS_ROOT` is honoured only when `DWAAR_ENV` is local/test.
  Evaluators stamp results with `binding` and `binding_blockers`. Pack data is deeply immutable (`FrozenDict`/`FrozenList`); YAML
  duplicate keys are rejected; override values are shape/range-validated; four offline safety settings have approved upper
  bounds in the cascade pack (resident validity 72 h per D-13, clock uncertainty 60 s and policy age 72 h per EDGE-05, event buffer
  168 h as an engineering ceiling [TBD, owner/security supervisor to confirm]); paise inputs must be ints in signed 64-bit range.
  `dwaar-packs` now depends on `dwaar-common`.
- **Other.** Keyset pagination is NULL-safe (NULLs sort last in both directions; `SortColumn(nullable=False)` keeps the plain
  row-value comparison). API `message_key` is `errors.<code>` (`internal_error` -> `errors.unknown`) and the rate-limit
  placeholder is `{retry_after_seconds}`. Verification tests for fixed findings live in `tests/security/test_w1_*.py`; findings that
  were not part of this round stayed in `tests/security/verify_w1_*.py` (not collected); B-010 fixed and moved them.

### B-010 Fix round 2 for W1 verification findings (R2-01..R2-11, Q2-01..Q2-05, open round-1 findings)
- Date: 2026-10-05. Owner: Viz.
- **Money survives masking (R2-01).** Audit diffs and outbox payloads no longer decide by digit count: a number is masked only
  when its KEY says it is an identifier (`contact`, `*_number`, `*_no`, `ref`, `account`, `card` ...; `dwaar_common.keynames`) and has
  9+ digits; any other number, and any decimal string with a point, is kept. Rs 10 lakh is 100_000_000 paise, nine digits, the
  same shape as a phone number, so a settlement or corpus figure under `credit`, `tds`, `payout` ... used to become `[REDACTED]`
  before `payload_hash` was computed. Digit-only STRINGS under non-quantity keys are still scrubbed (that is how phones travel).
- **Runtime role cannot poison itself (R2-02).** The pooled connections pin `row_security=on`, `default_transaction_read_only=off`,
  `lock_timeout`, `statement_timeout`, `idle_in_transaction_session_timeout` and `search_path` in the startup options (they outrank
  role defaults), and `/readyz` fails (`role_defaults: drift`) if the runtime role has ANY role-level default. PostgreSQL offers no
  way to forbid `ALTER ROLE <self> PASSWORD`; that residual risk is documented in ADR-0004, with detection (the pool fails,
  `/readyz` 503) and recovery (`infra/db/bootstrap_roles.sql` is idempotent and also clears role defaults).
- **Never a superuser (R2-03).** The role is re-verified on EVERY new pooled connection (refused with `ConfigError`) and in every
  `/readyz` (`role` check), so skipping the boot check when the database is down no longer leaves a superuser API running.
- **Catalog guard (R2-04).** `find_rls_violations` now covers every non-system schema, rejects policies that depend on a custom GUC
  other than `app.society_id` or on the connected role, probes policies as each runtime role with attacker-set GUCs, and reports
  runtime roles holding CREATE on a schema or the database.
- **Route registration fails closed (R2-05).** `create_app` refuses a route without `require(...)` (or `public_route(reason)`, or
  at least `current_principal`), a Starlette route added by a hook, and a mutating route with neither `idempotency_required` nor
  `idempotency_exempt(reason)`.
- **Scrubber and masker (R2-06).** One key classifier for text and mappings. New: key material (`*_key` with a qualifier, pepper,
  salt, dsn, database_url ...), URL passwords, bare `code=`/`c=` and "use 482913 to verify", Devanagari OTP phrases, 32+ hex and 40+
  base64 runs unless labelled `sha256:`, comma/slash/underscore/zero-width separated digit runs. 
- **Tax results carry `binding` (R2-07).** `TdsResult` and `GstRwaAssessment` say whether the pack that produced them is enabled,
  approved with registry evidence and effective; a draft figure is labelled in its explanation. `find_legal_pack` prefers an approved pack over a later draft.
- **Verification never raises (R2-08)** and **money parsing is bounded (R2-09)**: canonical JSON is a bounded single pass in RFC 8785
  key order (depth 64, 64-bit ints, no lone surrogates); Decimal parsing works on the digit tuple, no `scaleb`/`int()` of a huge exponent.
- **Worker and API privileges (R2-10, LOCK TABLE, rate limits, purge)** are in migration 0009: column-level grants, a SECURITY DEFINER
  `dwaar_rate_limit_take` with no table privileges for the runtime roles, stale-bucket-only worker housekeeping, and an AFTER DELETE
  statement trigger so every permitted purge, including one that forges the flag, writes a `purge_log` row. Outbox events are unique per aggregate version.
- **Pool and migrations (R2-11).** The pool reset is `DISCARD ALL`; the migration runner serialises on an owner-only table lock
  instead of an advisory lock key (any role can take any advisory key), and detects transaction control structurally.
- **Packaging, docs, traceability (Q2-01..Q2-05).** Wheels ship the SQL migrations (`dwaar_api/migrations`) and the i18n catalogues
  (`dwaar_common/locales`); `uvicorn.access` is dropped; `trace_check` ignores files no runner collects, needs a FUNCTION-level test for
  `done`, and reads a run report when present (`done` is not `verified`); the hi/mr lock-screen text keeps the brand `Dwaar`;
  `BLOCKING_DECISIONS.md` lists every D/Q ID and no longer says shipped packs are unbuilt.
- **Still open (not in this round):** see `tests/security/verify_w1_quality_r2.py` (strict xfail list).

### B-011 Slice 1 finish: matrix reading, simulator environments, MFA denial, seed, real-resolver tests, AT-01/AT-02
- Date: 2026-10-05. Owner: Viz.
- **PRD 5.2 "Unit and member register" prints ten values (F R R R Masked R O O O O): GUARD = Masked, AUDITOR = R.** An earlier
  reading from a text extraction (nine values, AUDITOR = N) was wrong and was corrected after checking the rendered table; identity and
  organisation now agree (`identity/matrix.py`, ADR-0011).
- **The identity simulator is allowed in `local` AND `test`**, not only `local` as BUILD_BRIEF section 3 words it. The core
  already defines `Environment.allows_simulators` as local and test (and `.env.example` says so); the test suites and the
  acceptance scenarios sign in through it with `simulation=true`. It is never mounted in staging or production. The SEED and the
  demo logins stay `DWAAR_ENV=local` only (`python -m dwaar_api.seed` refuses anything else, the tests call it with an explicit
  local environment for a private test database).
- **A secretary (any elevated role) without a fresh TOTP step-up gets 403 `not_authorised`**, not a dedicated code: PRD 12.2 has no
  `mfa_required`. The resolver hands the grant out as `<role>_mfa_pending`, which no permission lists (ADR-0011 section 4);
  `/v1/me` tells the client a step-up is needed. Tested in `tests/acceptance/test_at02_nonresident_owner.py` and the identity suite.
- **Seed (`dwaar_api.seed`)**: a package of steps discovered by file name (`steps/sNNN_*.py`, unique ORDER) so later slices add
  data without editing a shared file. It calls the same service functions as the routes, as `dwaar_app` with the RLS context (only
  the pack loader uses `dwaar_owner`), so audit and outbox rows exist. Ids made through `uuid7()` are deterministic (fixed
  2026-01-01 time, random bits seeded per scope key); membership and case ids still come from `uuid.uuid4()` inside
  `identity.members.create_membership` and are found by natural key on a re-run. Not seeded yet, by design: guard shifts, visits,
  invoices, receipts, bank lines, settlements (their slices own them). No PAN/TAN/GSTIN is invented.
- **The organisation tests now also run against the REAL `PgGrantResolver`** (`RESOLVER_FACTORIES["pg"]` in
  `tests/integration/organisation/_support.py`, real memberships and role grants, the access-index triggers, MFA-verified sessions
  for elevated roles). `platform_admin` has no database representation (`role_grants.role` has no such value; platform roles are
  issued out of band, ADR-0011), so in the `pg` kind it is a documented in-memory overlay. Production needs a real way to hold
  that role before society creation by operators can work through the API (reported as an open question).
- **AT-02 capability naming.** There is no `gate.history` permission string: "visitor history of a unit" is the PRD 5.2
  "Gate operations" own-unit read, `matrix.gate_ops.read_own` (OWNER_NR `N`; OWNER_OCC, TENANT, FAMILY `O`). The denial is proven
  at the permission-service level until slice 2 adds the endpoint; a tripwire test fails when a gate/visitor route appears.
- **README.md got a "Local demo" section** although it is outside the slice's file list: the task asked for the demo logins to be
  documented there. Additive only.

### B-012 Slice 2 visits module deviations (ADR-0013)
- Date: 2026-10-05. Owner: Viz.
- `event_id` and device-key uniqueness are scoped per society, not global, so a probe cannot learn whether another society holds an ID (INV-01).
- The canonical decision response keeps `request_id` = the approval request id (PRD 12.3); the core replay rewrite is undone by `restore_canonical`.
- The guard's "current gate" is the gate the guard names until shifts exist (slice 4); expiry is evaluated lazily and by an idempotent expire job.
- Open: `dwaar_worker` lacks INSERT on `outbox` (sweep/expiry jobs run as `dwaar_app` for now); GUARD_SUP actions to be folded into the identity matrix.


### B-013 Edge-local pass entries are projected onto visits and pass uses; residents and overrides are recorded, not projected (ADR-0019)
- Date: 2026-10-06. Owner: Viz.
- The gateway mints its own movement ids. Decision (PRD EDGE-07, INV-07): every observation is an `access_events` row; legitimate cached-policy resident entries, exits of known movements and
  guard-assisted entries raise **no** exception and create no visit; an accepted entry of a pass the cloud knows becomes one `inside` visit (id `uuid5(society, movement)`, not the movement id), one
  `visit_stops` row and one use of the pass, in one transaction with audit and outbox (`VisitEntered`); a pass already counted out still gets its visit plus a supervisor exception and is never counted
  beyond `max_uses`; unknown or revoked-before-entry passes, remote decisions without a cloud visit, overrides and emergency entries raise supervisor exceptions and stay recorded; the gateway's
  advisory `review` flag stays in the stored payload and does not flood the queue. The projection creates no permission.

### B-014 Trust anchors are provisioned, never taken from a snapshot; pass keys are published beside issuer keys
- Date: 2026-10-06. Owner: Viz.
- `GET /v1/edge/keys` also returns `pass_keys`; `python -m dwaar_edge.provision` fetches both with the device key and prints `DWAAR_EDGE_ISSUER_KEYS` / `DWAAR_EDGE_PASS_KEYS`. First use is trust-on-first-use
  unless the installer compares the printed fingerprints out of band (documented); a rotation needs re-provisioning. mTLS (EDGE-09) remains not implemented.

### B-015 A society gateway is enrolled without a gate binding; the edge seed is default ON
- Date: 2026-10-06. Owner: Viz.
- A gate-bound device may report only for its gate (`device_wrong_gate`), kept as is (an existing test asserts it). The seeded gateways serve societies with more than one gate, so they are enrolled unbound.
  `DWAAR_SEED_EDGE` defaults to on (`0/false/no/off` disables). Slice 2's `test_seed_visits` counts changed with justification: devices 3 -> 5 (two gateways), `device.enrol_request` 3 -> 5,
  `device.approve` 2 -> 4; nothing else of the visits seed changed.

### B-016 Gateway honours Retry-After; a revoked pass does not read as used; a departed pass keeps the limit its observer knew
- Date: 2026-10-06. Owner: Viz.
- Backoff stays exponential with full jitter but never earlier than `Retry-After` (clamped to 3,600 s). `uses_remaining` of a revoked pass is 0 by contract and is not a use count
  (`Invitation.cloud_used`). Standalone observations carry `max_uses` so a pass that left the policy (last window over) is not judged as single-use.

### B-017 The stale-clock flag allows for an outage
- Date: 2026-10-06. Owner: Viz.
- An event is `stale` only when older than `max(policy_age_limit, time since the device's previous batch)`: 72 h and longer outages (NFR-09) no longer produce `clock_implausible` exceptions for honest buffered events;
  a wrong clock (older than the silence itself) is still flagged. First-ever batches keep the 72 h rule.

### B-018 Worker jobs, grants and listing of societies
- Date: 2026-10-06. Owner: Viz.
- `services/worker` runs the policy publisher and the visits sweep as plain functions plus Dramatiq actors (Redis from `DWAAR_REDIS_URL`; `StubBroker` in tests, Redis never started by a test). New additive grants:
  0010 (outbox INSERT, content columns, society context still required), 0104 (`dwaar_active_society_ids()`, SECURITY DEFINER, worker-only, ids only: the worker still cannot read `societies`),
  0206 (invitations UPDATE state/version), 0314 (policy snapshots, credential references, revocation counter). The 0010 slot is the requested core migration; 0104 sits after `societies` exists, in the org range.
  `publish_on_poll` stays the default until a deployment sets it false. `dwaar-worker` depends on `dwaar-api` (uv.lock updated offline); `mypy_path` lists the package roots so one file has one module name.

### B-019 End-to-end evidence is simulated and says which cloud it used
- Date: 2026-10-06. Owner: Viz.
- AT-05..AT-08 run end to end against the real API (`tests/acceptance/test_at0{5,6,7,8}_e2e.py`, parametrised `fakecloud` | `realcloud`, same assertions; REAL-ONLY extras are marked). Evidence JSON records
  `environment.clouds` and a per-test `cloud`; `environment.simulation` stays true. The virtual clock follows monotonic time on both sides; PostgreSQL's own `clock_timestamp()` stays real and the harness moves
  `revoked_at` to virtual time where a scenario needs it (labelled). FakeCloud now conforms on authentication window, caps, seq conflicts, payload size and wrong-society disposal; differences that remain are listed and asserted.

### B-020 Local keys for the edge are generated by `make setup`
- Date: 2026-10-06. Owner: Viz.
- `.env.example` now documents the cloud issuer key, key id, retired keys, reference key, pass signing key, visitor HMAC key, the publish-on-poll switch, per-device rate limits, every gateway commissioning
  variable and the worker variables; the stale placeholder names of the first edge section were removed (nothing read them). `make setup` generates distinct 32-byte keys for each placeholder;
  a test proves the generated values load in the cloud config, the visits config and the gateway config.

### B-021 Slice 4 integration: seed, retention columns, worker grants (ADR-0020..0023)
- Date: 2026-10-06. Owner: Viz.
- **Seed.** The full seed in order was already idempotent for the slice 4 steps; the real non-idempotency was the edge policy: `s450_edge` published the first snapshot BEFORE the staff step, so once the manifest
  carried staff a second run published another one per society. The publish moved to `s485_edge_policy` (after staff, before shifts); `test_seed_edge` still sees one snapshot (`seq == 1`) and two `PolicyPublished`.
  The seeded "active" shift was a calendar-day shift that was already over in the evening (it could not take an override): it now starts three hours ago on the hour and runs 14 h.
- **Domestic staff are dedicated persons.** The staff seed had re-used the person rows of three plain owner-occupiers to keep the person count at 97 (one human = flat owner and cook). Decision: `DOMESTIC_STAFF_PEOPLE`
  (`mh.staff.cook`, `mh.staff.driver`, `ka.staff.cook`, numbers +91 99999 01300..01302), no membership, no grant: 97 -> 100 persons. The exact-count tests derive the count from `all_people()`; new tests assert no
  membership/grant and no register entry that is also a resident.
- **Masked events.** `StaffCredentialIssued` carried `credential_kind` and `DocumentFileUploaded` a hex digest; the outbox guard masks both ([REDACTED] stored). Renamed to `kind`; digest dropped from the event (it lives in
  `document_versions`). A seeded-data test asserts nothing in the outbox is `[REDACTED]`.
- **Retention.** Migration 0710 adds `retention_class` + `legal_hold_id` to 33 slice 4 tables (expand-only; constant defaults, no rewrite). Codes follow the PARENT record. Parents use CONSENT, STAFF, OPS, COM, DOC which are NOT classes of
  `packages/legal-packs/retention`; pinned by `test_retention_codes.py` for the privacy slice to map. `legal_hold_id` is still insertable by the runtime roles on tables with table-level INSERT (as on the slice 2/3 tables): the
  privacy slice must narrow it. The guard `ai_drafts` problem reported at hand-over did not reproduce (the table is society-RLS, private by owner filter); no guard was changed.
- **Worker.** helpdesk sweep, notice publisher, poll closer, parcel reminders and shift sweep are job functions + Dramatiq actors + scheduler cadence (the sweep interval). Only polls lacked a worker grant: 0563 (`state, closes_at, version,
  updated_at`). The custody report is NOT a job (a timer has no physical count). The shifts `summary provider` hook is deliberately unused: it would attach AI text without a person confirming (class B).

### B-022 Edge manifest carries staff engagements and overrides; AT-01 inventory uses the modules' real probes
- Date: 2026-10-06. Owner: Viz.
- The signed manifest gains `staff {entries, ended}` and `overrides` (opaque ids, local valid hours, override expiry), built only in `edge/staff_shift_input.py` from `staff.authorisation.edge_staff_input` and `shifts.service.active_override`.
  The gateway parser accepts them (defaults empty); the gateway's decision engine does NOT use them yet. Staff read errors fail the publish (previous snapshot keeps serving); override read errors are isolated by a savepoint.
  The INV-08 test "visits/edge never read shift tables" now names this ONE reviewed file.
- `DecisionIn.channel` accepts app|ivr|whatsapp|sms|guard_assisted (PRD 8.2); the HTTP route refuses the four the server establishes (422 `channel_set_by_the_server`) so a client cannot forge provenance. `model_construct` is gone.
  `test_payload_is_validated` no longer lists `ivr` as a schema error (it is now a policy refusal, tested separately).
- AT-01: every module exposes `probed_routes()` derived from the tables its own isolation tests iterate; `tests/acceptance/_isolation_inventory.py` resolves them against the live router. A route with no probe, or a probe on no route, fails.
  Helpdesk and community gained the missing probes (settings PUT, lists, creates, emergency broadcast, download token). The files/AI tripwire became real replays (documents, signed downloads, AI proposals/runs/drafts/ticket sources);
  only export and search remain a tripwire. Personas matter: Meera is also a non-resident owner in A, so "no standing in A" probes use farhan.
- Permissions: `identity/permission_basis.py` classifies every non-matrix permission (cells, added roles, withheld roles, analogy); tests enforce equality with the registry; `docs/permissions-gaps.md` lists what the owner must confirm.
- AI ports: AI-F01 and AI-G08 read the real helpdesk and shift data as the caller and apply confirmed proposals through `helpdesk.service.triage` / `shifts.service.attach_summary`. Emergency suggestions are never applied by the port;
  a shift or ticket of another society is 404 before any source is read. `ticket.create` and `notice.create_draft` ports are NOT wired.
- Test fix recorded: `test_a_forged_or_foreign_or_edited_qr_is_refused` replaced the last three signature characters with "AAA", a no-op for ~1 in 64 signatures (failed once in the full run); it now changes one full character.
