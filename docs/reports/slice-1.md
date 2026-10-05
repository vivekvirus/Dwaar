# Slice 1 report: repo, identity, scoped schema, synthetic data, CI, audit foundation

PRD 4.3 gate before slice 2: **AT-01 and AT-02**. Both pass as simulated-environment evidence; both are PARTIAL against the PRD
wording (see "Honest limits"). Date 2026-10-05. Evidence: `docs/evidence/AT-01.json`, `AT-02.json`, `INDEX.md` (commit field is the
pre-commit HEAD `c184f02`, `tree_dirty: true`, `simulation: true`, dataset = seed v1).

## 1. Working code
* Platform and API core (earlier): UUIDv7, money, errors, audit/outbox/idempotency, RLS context, registry, packs, i18n, harness.
* Organisation module (SOC-01..03, ARCH-01/05): societies, legal entities (identifiers encrypted), blocks, units, CSV import,
  pack selection, feature flags, quotas. ADR-0010.
* Identity module (IAM-01..08, 11..14): OTP sign-in via the labelled simulator, sessions with rotating refresh and reuse
  detection, TOTP step-up, memberships with verification cases, owner confirmation, disputes, holds, role grants, PRD 5.2 matrix
  as data, database-backed grant resolver and session store. ADR-0011.
* **New in this step**
  * `services/api/dwaar_api/seed/` (`python -m dwaar_api.seed`, `make seed`): the PRD 8.3 dataset, see section 3.
  * `tests/acceptance/`: AT-01, AT-02 and the seed-shape tests on the seeded world (real API, real OTP/TOTP tokens).
  * Organisation tests now also run on the real resolver (`pg` kind): 76 tests became 152.
  * `.env.example` identity block, `DECISIONS.md` B-011, `docs/adr/0012`, README "Local demo".

## 2. Migrations
`0001-0009` platform core; `0101-0103` organisation; `0130-0135` identity (schema `iam`, memberships, cases, holds, role grants,
access index, SECURITY DEFINER functions); `0190` identity-to-organisation composite FKs. **No migration was added in this step.**

## 3. Seed updates
Two societies: Sahyadri Residency CHS (Maharashtra, blocks A/B/C = 100/80/60 = **240 units**) and Nandana Apartments (Karnataka,
Tower 1/2 = 100/80 = **180 units**); labels `101..` repeat in every block. 97 invented people on `+91 99999 0nnnn`; staff and
committee per society (13 elevated holders with a confirmed synthetic TOTP factor); owners with several memberships; a non-resident
owner (Meera, also secretary of the other society) and her tenant; active tenant with absent owner (reasoned waiver); disputed
move-out (occupancy continues); family approvals (2 approved, 1 pending, 1 rejected); a mover (ended membership in A, tenant in
B); a committee hold; 64 generated owner-occupiers. Legal packs selected from `packages/legal-packs`; the Maharashtra pack is
unapproved and binding governance is disabled (API refuses to enable it: 422 `legal_pack_not_approved`).
Runs in about 5 s, refuses unless `DWAAR_ENV=local`, deterministic ids (fixed UUIDv7 time), idempotent (second run: no new rows,
audit or outbox), goes through the service functions as `dwaar_app` with RLS context. Demo logins only through the simulator.
**Not seeded (later slices):** guard shifts, visits, invoices, receipts, bank lines, settlements.

## 4. Test results (real numbers)
* `make lint`, `make typecheck` (119 files): clean.
* `make test` before regenerating the traceability report: **2066 passed, 1 xfailed, 1 failed** (the failure was the committed
  `TRACEABILITY.*` being stale, fixed by `make trace`; the affected files then ran green: 163 passed). Baseline before this step:
  1839 passed, 1 xfailed.
* `make acceptance MILESTONE=M0`: **137 passed** (AT-01 124 tests, AT-02 13), 46 ATs of the matrix have no evidence yet (honest).
* `tests/acceptance` in full: 152 passed (adds 15 seed-shape tests incl. idempotency, cross-database id determinism, refusal in
  test/staging/production/unset).
* `make trace`: M1 cumulative, 220 requirements: done 15, partial 25, not-started 180, orphans 0; acceptance done 2, partial 2.
* No postgres or uvicorn process left (`pgrep` clean after `make db-down`).

## 5. Requirement IDs
* **Done (annotation status):** INV-01, INV-04, ARCH-01, ARCH-02, ARCH-03, IAM-01, IAM-03, IAM-04, IAM-11, IAM-13, SOC-01, SOC-02,
  SOC-03 (units subset), and others in `TRACEABILITY.md`.
* **Partial:** IAM-02, IAM-05, IAM-06, IAM-07, IAM-08, IAM-12, IAM-14, ARCH-05.
* **Not started:** IAM-09 (step-up for bank approval/legal-hold export/bulk export; the TOTP step-up is only the building block),
  IAM-10 (offline guard login).
* AT-01 and AT-02: passed, partial against PRD wording.

## 6. Honest limits
* **AT-01:** files, export, search and AI have no endpoints; they are covered only by a tripwire (no route exists; probes answer
  404) and an inventory test that fails when a route is added without a replay. Exercised end-to-end when those slices land.
* **AT-02:** the visitor-history endpoint does not exist. Denial is proven at the permission-service level (real registry, real
  resolver, real grants from the seed) for `matrix.gate_ops.read_own` (the PRD "Gate operations" row; there is no `gate.history`
  string), plus the owner's own-unit bills/register/audit capabilities and, end to end, the unit record, unit-register scope and
  liability facts. **To exercise when slice 2 adds the endpoint:** owner_nr -> 403 `not_authorised` on the tenant's unit,
  tenant/owner_occ -> 200, stranger -> 404; the tripwire test `test_visitor_history_route_is_not_built_yet` fails until then.
* Not done: IAM-09, IAM-10, web cookies/CSRF (IAM-08, needs the web client), push-token revocation (no token store), real SMS and
  real IdP (blocked-external), IAM-02 timing of sweeps by the worker.
* The simulator is the only sign-in; evidence is simulated, never staging or field.

## 7. Findings and open questions
1. **Status quirk of `decide()`:** a non-resident owner who is also an owner-occupier elsewhere gets 404 (not 403) for the rented
   unit's history (Sanjay case); a pure non-resident owner gets 403. Both deny; pick one semantic.
2. **Auditor reading (RESOLVED by orchestrator — AUDITOR = R per the rendered PRD table; matrix and tests corrected):** identity matrix reads the register AUDITOR cell as N, the organisation module's `unit.read` lets auditors
   read units (B-011). Needs one owner decision.
3. **`platform_admin` has no database form** (`role_grants.role` lacks it), so operator society creation through the API cannot work
   outside the tests' in-memory overlay. Needs a decision (platform operator table or out-of-band issuance).
4. **`/v1/me` shows a mover's own ended membership in the old society** (own history, no active role). Intended? Decide.
5. Membership/case ids use `uuid4()` inside identity (`create_membership`): not deterministic in the seed.
6. `.env.example` still holds three keys no module reads (`DWAAR_SIM_IDENTITY_SIGNING_KEY`, `DWAAR_PHONE_HASH_KEY`,
   `DWAAR_OTP_HASH_KEY`), now labelled; platform step should remove them.
7. Applicant path: a non-member may create a PENDING claim for a unit of a society they are not in (by design, no grant); asserted
   in AT-01 that it reveals nothing and grants nothing.

## 8. Deviations with reasons
* Edited README.md (not in the file list) for the requested "Local demo" section; additive.
* `docs/evidence/_run.json` was deleted after the acceptance run: `tools/trace_check.py` would otherwise embed it and
  `test_committed_traceability_report_is_current` (which renders without it) would fail. Re-run `make acceptance` to recreate it.
* Simulator allowed in local and test (B-011), seed local only.

## 9. DECISIONS.md
B-011 appended (AUDITOR read as N per ADR-0011; simulator in local and test; elevated role without MFA gets 403 not_authorised; seed
design; real-resolver test kind and `platform_admin` overlay; AT-02 capability naming; README edit).
