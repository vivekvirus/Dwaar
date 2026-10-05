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
