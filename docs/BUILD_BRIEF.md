# Dwaar — Build Brief (read this first)

Authority: **Dwaar Master PRD v2.0** (`docs/prd/Dwaar_Master_PRD_v2.0.txt`, local-only, git-ignored). Requirement IDs and the
acceptance matrix (`AT-01`..`AT-48`) are the contract. Where this brief and the PRD disagree, the PRD wins; record the
conflict in `DECISIONS.md`. Search the PRD text with `grep -n "GATE-07" docs/prd/*.txt` instead of paging a PDF.

## 1. Mission
Ad-free, offline-first community operating platform for Indian gated communities. Build M0 (local demonstrator) then M1
(staffed society pilot) per PRD §4. Do **not** reduce this to a static dashboard or chatbot. Every screen talks to a real API
with real persistence; simulators are labelled `simulation=true` and cannot reach real providers or hardware.

## 2. Non-negotiable invariants (PRD §1) — a violation is a bug even if no test catches it
INV-01 multi-society isolation (server-derived society+role scope on every object/query/cache key/search/file) ·
INV-02 money = integer paise, journals balance, immutable, retries cannot duplicate · INV-03 a deterministic local policy
decides entry; a model can never actuate a gate; no auto-allow on timeout · INV-04 ownership, occupancy, billing liability,
statutory voting are independent relationships · INV-05 no ad/tracking SDKs, no commercial push · INV-06 AI proposes,
deterministic services execute · INV-07 submitted/approved/entered/handed-over/paid/settled are distinct, truthfully shown ·
INV-08 essential services never restricted for debt · INV-09 exports/migration manifests are self-service ·
INV-10 law is configuration (versioned approved packs; never hard-coded interest caps, quorum, notice periods, tax rates,
retention) · INV-11 guards/staff can use every core flow in their language with icons+audio · INV-12 every SLO is
instrumented; claims only from measurements.

## 3. Architecture decisions (defaults from PRD §3 decision register; ADRs in `docs/adr/`)
| Area | Decision |
|---|---|
| Repo | Monorepo exactly as PRD §19.1 (`apps/`, `services/`, `packages/`, `infra/`, `tests/`, `docs/`) **plus** `packages/dwaar-common` (shared Python lib: UUIDv7, money, time, event envelope, Ed25519 signing, envelope crypto, errors) and `tools/` (dev scripts, `trace_check.py`). Record as ADR-0001. |
| Python | 3.12, `uv` workspace (root `pyproject.toml`, members `services/*`, `packages/dwaar-common`). FastAPI + Pydantic v2 + SQLAlchemy 2.0 (**sync**, `psycopg` 3, mostly explicit SQL via `text()`/Core) — correctness and auditability over cleverness. ruff (lint+format), mypy, pytest, hypothesis. |
| DB | PostgreSQL 16 (managed in prod; locally the `postgres` OS user via `runuser`, since root cannot run postgres; CI uses a service container). Extensions: `pgcrypto`, `pg_trgm`, `btree_gist`. `pgvector` is **not installed locally** and only needed for M2 AI retrieval — do not block on it. |
| Roles | `dwaar_owner` (owns objects, runs migrations) · `dwaar_app` (restricted: `NOSUPERUSER NOBYPASSRLS`, no UPDATE/DELETE on append-only tables) · `dwaar_worker` (background jobs; narrowly granted; per-society context for society data). Never connect the API as owner/superuser. |
| RLS | Every society-owned table: `society_id uuid NOT NULL`, composite FKs/checks against cross-society refs (ARCH-01), `ENABLE`+`FORCE ROW LEVEL SECURITY`, policy on `current_setting('app.society_id', true)::uuid`. Context set per transaction with `set_config(..., true)` (`app.society_id`, `app.person_id`, `app.actor_role`, `app.request_id`). RLS is defence-in-depth; the application permission service is the primary gate. Missing context ⇒ **zero rows**, never all rows. |
| Migrations | Plain, ordered, checksummed SQL files in `services/api/migrations/` run by `dwaar_api.core.migrate` (table `schema_migrations`). RLS + constraints + grants live in the **same** migration as the table. Expand-and-contract; never destructive on posted data (RUN-01). Number ranges per area (avoid collisions between parallel builders): `0001-0099` platform core · `0100-0199` org/identity · `0200-0299` devices/policy/visits · `0300-0399` access events/edge sync · `0400-0499` staff/parcels/shifts · `0500-0599` helpdesk/ops/notices/community · `0600-0699` finance/ledger/payments · `0700-0799` privacy/retention/AI audit · `0800+` M2+. |
| Auth | IAM-14: standard OIDC/JWT via a maintained library (PyJWT + JWKS); no invented token formats. Local/dev uses a **labelled simulator issuer** (`simulation=true`, only when `DWAAR_ENV=local`) behind an `IdentityProvider` adapter, so Supabase/other OIDC drops in. Short-lived access tokens, rotating refresh tokens with reuse detection, session/device list, revocation. Authorisation is re-derived from DB memberships/grants on every sensitive action — **never trust role claims in the JWT**. OTPs: hashed at rest, rate-limited, never logged. |
| Pii | `persons.phone_token` = keyed salted hash (HMAC) for lookup; real phone/ID/bank values in `person_vault` with field-level envelope encryption (AES-GCM; KMS adapter simulated locally from env master key). Phone is never a primary key. |
| Writes | Domain mutation + `audit_log` row + `outbox` row **in one transaction** (PRD §12.4). `Idempotency-Key` required on financial writes, approvals, command creation; bound to actor+society+endpoint+request hash; same key + different payload ⇒ 409 `duplicate_payload_mismatch`. |
| Errors | PRD §12.2 codes; every error has `request_id`, stable `code`, user-safe `message`, `details`. Errors must never reveal whether a person is a member (use 404 `not_found`). Raw DB errors never exposed. |
| Lists | Cursor pagination, max 100 rows, allow-listed filters, bounded date ranges. |
| Time/IDs/money | Store UTC, present `Asia/Kolkata`; UUIDv7 IDs (event/financial IDs never recycled); money `bigint` paise; quantities fixed-decimal (Wh, litres). |
| Workers | Transactional outbox relayed by `services/worker` (Dramatiq+Redis adapter, but job logic = plain testable functions; `StubBroker` in tests). Redis is available locally (`redis-server`). |
| Edge | `services/edge`: Python, SQLite **WAL + `synchronous=FULL`**, encrypted sensitive fields, local deterministic policy engine, signed policy snapshots (Ed25519), outbox sync to `POST /v1/edge/sync/batches`. |
| Clients | `apps/admin-web` Next.js App Router + TS + Tailwind + shadcn/ui · `apps/resident-mobile` Expo/React Native + TS (+ accessible web) · `apps/guard-android` native Kotlin (Room/SQLite; pure-Kotlin core module so logic is JVM-testable). |
| AI | Every AI call goes through `services/ai-gateway` (provider adapter, redaction, prompts as versioned files in `packages/prompts`, `ai_runs` audit, per-society budgets/kill-switch). No API keys exist here ⇒ a deterministic, labelled **simulator provider** implements the same interface; never claim measured AI quality. Permission classes A/B/C/X from PRD §10.2. |
| i18n | All user-visible strings via keys in `packages/i18n` (en, hi, mr at M1; kn at M2). Guard flows need icons + audio prompt keys. No hard-coded copy in UI code. |

## 4. Parallel-work rules (critical — many agents write to this repo at once)
1. **Ownership.** You may create/edit only the paths your task assigns. Everything else is read-only. If you need a change in
   someone else's area, do a minimal local workaround and list it under `blocked_requests` in your result.
2. **No git write commands.** Never `git add/commit/checkout/reset/stash/rebase/push`. The orchestrator commits. Read-only
   git (`status`, `diff`, `log`) is fine.
3. **Auto-discovery over shared edits.** API modules live in `services/api/dwaar_api/modules/<name>/` and are discovered by the
   core registry (each exposes `router` and optional `register(app)` / `permissions`), so adding a module never edits a shared file.
4. **Own migration range** (see §3). Never renumber or edit an applied migration of another area; additive new files only.
5. **Own your tests.** Tests for your code live in `tests/integration/<area>/` (needs Postgres), `services/<svc>/tests/unit/`,
   `tests/acceptance/` (AT scenarios), `tests/security/`. Do not weaken or delete another agent's tests; if one is wrong, report it.
6. **Never leave the tree red.** Before you finish: `make lint`, `make typecheck` and the tests you own must pass (run them).
   If the shared harness is broken by someone else's in-flight work, report it, do not paper over it.
7. Do not run long-lived servers in the foreground; stop anything you start. Clean up temp databases.
8. No secrets in the repo. `.env.example` documents variables; real values come from the environment.
9. **Package managers are shared state.** Wrap every `uv lock|sync|add|remove` in `flock /tmp/dwaar-uv.lock …` and every
   `pnpm install|add|remove` in `flock /tmp/dwaar-pnpm.lock …`. Edit only your own package's manifest. If a sync races
   and the venv is briefly broken, wait ~20 s and retry rather than "fixing" other people's files.
10. Each pytest session starts its own ephemeral Postgres on a random port in a private temp dir and tears it down; never
    share or hard-code a port, and never leave `postgres`/`redis-server` processes behind (check `pgrep -a postgres`).

## 5. Traceability & evidence (PRD §4.3, §19.2.5)
* Reference requirement IDs in code (`# REQ: GATE-03`), commit-style notes and tests. Tag tests:
  `@pytest.mark.req("GATE-03")` and acceptance tests `@pytest.mark.at("AT-04")` (+ `milestone("M0")` derived from the PRD matrix).
* `make acceptance MILESTONE=M0` must emit evidence per AT into `docs/evidence/` with: requirement/AT ID, commit, environment,
  dataset, scenario, expected, observed, trace/log reference, tester, date. Simulated, staging and field results are separate.
* `tools/trace_check.py` reports, per requirement ID for the target milestone: implemented-in (files), tested-by (tests),
  status (`done` | `partial` | `not-started` | `blocked-external`). Unimplemented IDs are listed honestly, not hidden.

## 6. Definition of done (PRD §19.3, per requirement)
Code merged with tests · acceptance criteria automated · RLS + permission tests pass · translation keys added · audit and outbox
events emitted · export representation exists · docs updated · no open P0/P1 defects · SLO measured where applicable · evidence
recorded. A requirement dependent on external reality (live provider, certified hardware, legal/CA approval, field metrology)
is `blocked-external`: implement the adapter/configuration + simulator, keep it **disabled by default**, show the missing
dependency to authorised admins only, and say so plainly in reports.

## 7. Honesty rules
* Do not invent partner APIs, bank integrations, legal eligibility, tax rules, measured AI quality, or hardware certification.
* `[LEGAL]` `[CA]` `[VERIFY]` `[TBD]` items ⇒ configuration in versioned packs, disabled/unapproved by default.
* Test data: invented identities and reserved test numbers only (e.g. +91 99999 00xxx style fictional range). Demo logins only in
  synthetic development (`DWAAR_ENV=local`).
* Report real test output. If something fails or is skipped, say so; never mark done on a green-looking but untested path.

## 8. Standard commands (created by the platform step; keep them working)
`make setup` · `make db-up` / `make db-down` / `make db-reset` · `make migrate` · `make seed` · `make api` · `make lint` ·
`make typecheck` · `make test` · `make acceptance MILESTONE=M0|M1` · `make trace`.
