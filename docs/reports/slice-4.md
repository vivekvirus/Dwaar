# Slice 4 report: notifications, parcels, staff, shifts, helpdesk, community, AI gateway, integrated (2026-10-06)

Stop-and-report content per PRD 19.6. **Every result is SIMULATION**: one 4 vCPU VM, ephemeral PostgreSQL 16, labelled simulators (identity, notification providers, AI provider, ASR, malware scanner, object store),
virtual clocks where a test says so. No staging, no field, no real provider, device or model took part. Four modules were built in parallel without running the whole suite; this report is about what the first
full run found and how the pieces were made to work together.

## Measured (see the section "Verification" for the final numbers filled in at the end of the run)
| Item | Result | How / limit |
|---|---|---|
| NOTIF-04 decision withdraws the other device | **0.53 s** (0.530, 0.534, 0.535) | simulator, real scheduler loop at 1 s, StubBroker, one process, real PostgreSQL. Says nothing about Redis, a real provider or a phone |
| PII redaction recall (AI-SYS-05) | 100 % (563/563 identifiers, 0 % FPR on decoys), second set 574/574 | synthetic set, **no longer held-out**: the first run (95.03 %) was used to find redactor bugs. Gate is 99 %; the generator's templates are narrow: a statement about these shapes only |
| Prompt-injection / exfiltration set (AT-25) | 0 unauthorised disclosures, 0 tool executions, 0 class-X executions over 200 attacks + 20 controls | authored by the same team as the defences with a compromised-model double: **not independent red-team assurance**; removing scoped retrieval makes 115 cases fail (the harness is not vacuous) |
| Edge numbers | unchanged from slice 3 (NFR-02/04/09/10 VM numbers) | the manifest gained `staff` and `overrides` sections; the performance tests still pass, numbers not re-claimed |
| AI quality | **not measured** | simulator provider only; PRD gates (recall >= 99 %, macro-F1 >= 0.90, ...) are release gates, not results |

## What integration found and fixed
1. **Seed**: the real non-idempotency was the edge policy (published before the staff step; a second run found a changed manifest). New step `s485_edge_policy`. The seeded active shift was already over in the evening: now covers "now".
   Staff re-used the person rows of owner-occupiers: dedicated persons now (97 -> 100). Two outbox payloads were being masked to `[REDACTED]` (`credential_kind`, a hex digest): fixed, guarded by a test.
2. **AT-01**: route inventory no longer allow-lists; it resolves each module's real foreign-id probe tables against the live router (see B-022). 132 new routes covered; helpdesk and community probes completed; the files/AI tripwire became real replays
   of documents, signed downloads and AI. Export and search have no routes and keep a tripwire.
3. **Catalog guards**: the `ai_drafts` RLS guard failure reported at hand-over did not reproduce on the shipped schema (verified with the guard function against a freshly migrated database); no guard weakened. Retention/legal-hold: migration 0710 on 33 tables.
4. **i18n**: keys and catalogs regenerated (467 keys, 15 namespaces: notifications, parcels, staff, shifts, ops, community, ai included); `tools/i18n_check.py` 0 errors (hi/mr remain machine-drafted); `pnpm -r lint|typecheck|test` green.
5. **Config**: `.env.example` documents every new variable; `make setup` generates `DWAAR_COMMUNITY_DOWNLOAD_KEY`; tests prove every `Settings` field and every `DWAAR_*` name read by product code is documented.
6. **Worker**: five slice 4 sweeps registered as actors and scheduled (helpdesk, notices, polls, parcels, shifts); worker grant for polls (0563); real-role, per-society, idempotent, StubBroker tests. Notification tick already registered.
7. **Hooks**: edge publisher consumes staff and shift overrides (AT-12 end to end through `publish_policy`); `DecisionIn.channel`; permission basis + `docs/permissions-gaps.md`; `dwaar-api` depends on `dwaar-ai-gateway` (gateway imports nothing of the API: tested); AI-F01 and AI-G08 wired to the real helpdesk and shift services.
8. **Flaky or wrong tests**: one forged-QR test failed by chance (1 in ~64 signatures end in "AAA"): fixed, recorded in B-022. In the first full run `test_ops_endpoints` (503) and three `test_w1_r2_db` role tests failed while I ran a second PostgreSQL and other suites on the same VM; all pass in isolation and in the final run. Not reproduced as bugs.

## Requirement IDs and acceptance
Generated status (`docs/traceability/TRACEABILITY.md`, M1 cumulative) is the source: see the Verification section. Slice 4 evidence is **simulated**: AT-11 (notification fallback), AT-12 (also through the signed snapshot), AT-13 (parcel pickup twice),
AT-25 (malicious document, AI), AT-26 (stale AI proposal), AT-29 (AI unavailable; the billing scenario waits for the ledger), AT-40 (cascade timing on a virtual clock, plus NOTIF-04 above). AT-01 re-proved with files and AI.
Done in simulation means implemented and tested; PAR-06/07, NOTIF-08 (spoken approval), AI-R04, AI-C05 (interface only) are not built.

## Deviations and decisions
DECISIONS.md B-021 and B-022 (and ADR-0020..0023). Notable: PRD 9.7 SLA targets for emergency/urgent/low resolution are `[TBD]` placeholders; the HTTP decision route refuses non-app channels; a summary is never auto-attached to a handover.

## Open issues
* The gateway **parses and stores** `staff` and `overrides` but its decision engine does not use them yet.
* `legal_hold_id` is insertable by the runtime roles on tables with table-level INSERT; retention codes CONSENT/STAFF/OPS/COM/DOC are not in the retention pack (pinned by a test).
* `ticket.create` (AI-R02) and `notice.create_draft` ports are not wired; committee/treasurer can request a triage draft but the helpdesk (manage = secretary, estate manager) refuses to apply it.
* Permission defaults for everything the PRD matrix does not specify (GUARD_SUP, notifications, parcels, shifts, staff, documents, polls, AI) wait for the owner: `docs/permissions-gaps.md`.
* Publish-on-poll, key rollover, snapshot retention, restore-from-backup sequence issues from slice 3 remain.
* Redis and live Dramatiq worker processes were never started.

## NOT VERIFIED
No real push/SMS/WhatsApp/IVR provider, FCM/APNs, DLT registration, phone or OS behaviour (Doze, OEM kill); no real model, ASR or recordings (noisy/accented/code-switched speech untested); no real object store or malware scanner;
no live Anthropic call (adapter tested against a mocked transport); hi and mr strings are machine-drafted and unreviewed (legal and safety namespaces need human review); translation meaning preservation unmeasured; sub-processor approval, residency and
retention terms `[VERIFY]`; SLA targets `[TBD]`; calling/telephony vendor `[TBD]`; no Android UI for guards or staff; no payroll computation; edge gateway on certified hardware, power loss, mTLS and TPM as in slice 3.
