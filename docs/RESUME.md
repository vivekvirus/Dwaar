# Resume point (paused by the owner, 2026-10-06)

Branch `claude/nifty-cori-45yfal`. Source PRD: `docs/prd/` (git-ignored; re-extract from the PDF if the container was reset:
`pdftotext -layout <pdf> docs/prd/Dwaar_Master_PRD_v2.0.txt`). Android SDK bootstrap: `tools/dev/android/bootstrap-sdk.sh`.

## Last fully verified state
Slice 3 (commit `b7e8f29`): ruff + mypy clean, 2860 tests passed (1 documented xfail), `make acceptance MILESTONE=M1` 382 passed.
M0 (AT-01..AT-04) and slice 3 (AT-05..AT-08) pass as SIMULATED evidence. See `docs/reports/slice-1.md` .. `slice-3.md`.

## Slice 4 — BUILT BUT NOT INTEGRATED OR VERIFIED
Four modules were built in parallel and each passed only its own paths (no full suite was run on the combined tree):
notifications (ADR-0020), parcels/staff/shifts (0021), helpdesk/community (0022), AI gateway (0023).
The integration agent was stopped mid-run, so the tree may contain partial integration edits. Treat the tree as RED until checked.

Known open items (the integration agent's task list):
1. Seed steps fail non-idempotently on re-run (`parcel_custody_reports_pkey`, parcels step s470) — full seed must build and be idempotent.
2. AT-01 `test_route_inventory` + the "files/exports/search/AI do not exist yet" tripwire fail on the new routes; classify them
   while keeping real foreign-id isolation probes mandatory (each module has `tests/integration/<module>/test_isolation.py`).
3. Catalog guards fail on the AI module's `ai_drafts` table (private by API filter, not RLS) and the retention/legal-hold column
   guard fails on sibling tables — fix by design/migration, not by weakening guards.
4. Regenerate `packages/i18n/src/{keys,catalogs}.ts` (`node tools/gen_i18n_keys.mjs`), register new namespaces, run `pnpm -r test`.
5. Add all new env vars to `.env.example` / `make setup` (DWAAR_NOTIFICATION_*, DWAAR_COMMUNITY_*, DWAAR_AI_*, DWAAR_I18N_DIR, ...).
6. Wire worker jobs: helpdesk sweep, notices.publish_due, polls.close_due, parcel reminders, cascade scheduler.
7. Cross-module hooks: edge policy publisher consuming staff edge input + shift override (AT-12 end to end); visits `DecisionIn.channel`
   widening (remove notifications' `model_construct` workaround); fold module-local permissions into the PRD 5.2 matrix and list
   unspecified cells in `docs/permissions-gaps.md`; `dwaar-api` depends on `dwaar-ai-gateway`; AI-G08/AI-F01 ports to real services.
8. Then: `make lint`, `make typecheck`, full `make test` (~25 min, run in background), `rm docs/evidence/_run.json && make trace`,
   `make acceptance MILESTONE=M1`, `pnpm -r lint typecheck test`, and write `docs/reports/slice-4.md`.

## Not started
Slice 5 (ledger, bills, receipts, cash, payments, bank import; AT-14..AT-18, AT-37, AT-39, AT-46, AT-47) and
slice 6 (privacy, retention, exports, backup/restore, security hardening; AT-23/24/33/34), M1 pilot gate.
Also pending: guard-app wiring to the edge gateway (slice 3b), AT-48, native device/emulator runs, real providers.

## Standing honesty notes
All evidence is simulated. No real provider, device, model, ASR, or certified hardware was used. hi/mr strings are machine-drafted.
