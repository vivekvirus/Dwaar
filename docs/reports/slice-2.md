# Slice 2 report — visitor flows, clients, M0 exit (2026-10-05)

Stop-and-report content per PRD §19.6. Environment for every result below: local synthetic development (`DWAAR_ENV=local`),
ephemeral PostgreSQL 16, labelled identity simulator. **Simulated results only; no staging or field results exist.**

## Measured results (run by the orchestrator, not copied from agent claims)
| Check | Result |
|---|---|
| Python: `ruff`, `ruff format --check`, `mypy` (strict, 138 files) | clean |
| Python: `make test` (full suite, real Postgres) | **2338 passed**, 1 strict xfail (PostgreSQL own-password limitation, ADR-0004) |
| `make acceptance MILESTONE=M0` | **300 passed** (AT-01 … AT-04 plus supporting tests); evidence in `docs/evidence/` |
| `make trace` (M1 cumulative, 220 requirements) | done 23, partial 36, not-started 161, orphans 0; acceptance AT done 4, partial 2, not-started 29 |
| JS: `pnpm -r lint` / `typecheck` | clean (an undeclared `eslint-plugin-react-hooks` in admin-web was found and fixed) |
| JS unit tests | i18n 8, admin-web 96, resident-mobile 224 — all pass |
| Resident app (agent-run) | `expo export --platform web` OK; Playwright e2e 32/32 against the real backend; axe 0 violations |
| Admin console (agent-run) | `next build` OK; Playwright e2e 40/40 against the real backend; axe 0 violations on 8 pages + dialogs |
| Android guard app (agent-run) | `:core:test` 79/79, `:app:testDebugUnitTest` 11/11, `assembleDebug` APK built, `lintDebug` 0 errors |

## M0 exit condition (PRD §4.1) — status
* *Every acceptance test tagged M0 passes:* AT-01, AT-02, AT-03, AT-04 pass **as simulated evidence**.
* *No static-only features:* resident and admin clients use the real API only; unreleased modules are hidden, not stubbed.
* *Repeatable startup:* `make db-up && make migrate && make seed && make api` is exercised by the client e2e suites; a clean-machine
  run from an empty container has not been separately timed.
* Not yet true: the Android app has never run against the live backend or on an emulator/device.

## Built
Visits backend (migrations 0200-0205, 18 route paths): invitations with signed QR and rate-limited codes; unannounced-visitor
approval requests with compare-and-swap decisions (first valid decision wins; `409 already_decided`, `409 request_expired`, no
permission after expiry); observations that never create permission; multi-stop visits; overstay exceptions; gates, lanes,
devices; visitor-history endpoint (completes AT-02 end to end). Android guard app (Kotlin core + Compose, Room outbox, canonical
JSON/signing byte-parity with Python via golden vectors). Resident app (Expo, web-verified). Admin console (Next.js BFF).

## Requirement IDs
Done: GATE-03, GATE-04, GATE-05, GATE-08, GATE-11. Partial: GATE-01, GATE-02, GATE-07, GATE-09, GATE-13, SOC-05, SOC-06, IAM-03,
IAM-08, UX-01..06, UX-08..10 (guard). See `docs/traceability/TRACEABILITY.md` for the authoritative generated view.

## Not verified / not built (honest list)
* No native iOS/Android resident build, no emulator/device run, no TalkBack/VoiceOver, no manual screen-reader pass on the console.
* Guard app: kiosk mode, Keystore storage, WorkManager and Ed25519 on device never executed; Delivery/Service/Parcels/Inside/Incident
  and device enrolment not built; audio prompts are unrecorded; **AT-48 not met**. Sync is simulated until slice 3.
* Hindi/Marathi strings are machine-drafted (resident/admin apps partly keep their own copy and must move into `packages/i18n`
  and get native review); admin console has no hi/mr copy yet.
* UX-07 (support/privacy issue while membership disputed) not built — no API endpoint yet. IAM-09 step-up for bank/export and IAM-10
  offline guard login not built.
* Blocked requests carried forward: `dwaar_worker` INSERT on `outbox`; `/v1/me` effective permissions; CSV export and exception
  counts endpoints; typed OpenAPI response bodies and the `X-Society-Id` header; committee-role read of approval requests;
  GUARD_SUP actions in the identity matrix; family-delegation API.

## Deviations and decisions
See `DECISIONS.md` B-011 (matrix reading corrected: AUDITOR = R) and B-012 (per-society uniqueness, canonical response).
