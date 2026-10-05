# ADR-0012: Seed dataset and the acceptance world

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team (slice 1 finish)
- Related: PRD 8.3 (Seed dataset), 4.3 (build slices, evidence format), 16 (AT-01, AT-02), INV-01, INV-04; ADR-0003 (harness and
  evidence), ADR-0004 (RLS), ADR-0005 (audit/outbox), ADR-0010, ADR-0011;
  code: `services/api/dwaar_api/seed/`, `tests/acceptance/`

## Context

Slice 1 ends with synthetic data and two acceptance gates (AT-01 cross-society isolation, AT-02 non-resident owner). The risk is a
seed that quietly bypasses the rules it is meant to demonstrate (RLS, audit, maker-checker), and acceptance tests that pass
against hand-made fixtures that no real run ever produces.

## Decisions

1. **The seed uses the domain's own service functions** (`organisation.service`, `organisation.imports`, `identity.grants`,
   `identity.members`) as the restricted `dwaar_app` role with the request context a route would set. Each seed transaction is one
   `RequestContext` (society, acting person, role); the acting person is the real actor of the story (platform operator for society
   onboarding and the first secretary, the secretary for later grants, the applicant for a claim, a DIFFERENT person for every
   decision, the unit's owner for tenant confirmation and family approval). Where no service owns a write yet (liability and voting
   entitlement flags) the seed writes it through `core.audit.mutation` so the audit and outbox rows still exist. The only owner-role
   use is the legal/tax pack loader (global reference data, ADR-0010).
2. **Refusal and labelling.** The seed refuses unless `DWAAR_ENV` is exactly `local`. Demo logins are the labelled local
   identity simulator only (OTP from `/v1/dev/otp`, TOTP code from `python -m dwaar_api.seed totp`); the synthetic TOTP secrets are a
   pure function of the fictional number and protect nothing.
3. **Determinism and idempotency.** `seed.ids.deterministic_ids(scope)` swaps the process UUIDv7 generator for one with a fixed clock
   (2026-01-01T00:00:00Z) and random bits seeded from the scope key, for the length of one step; every step reads the natural key
   first and does nothing if it is there, and drives multi-phase flows (claim, review, verify, dispute, end) from the CURRENT state,
   so a run that stopped halfway continues. Ids minted with `uuid.uuid4()` inside identity (`create_membership`) are the one exception.
4. **Steps are discovered** (`seed/steps/sNNN_*.py`, unique `ORDER`, band table in `steps/__init__.py`), so a later slice adds its
   data (visits, shifts, invoices) by adding a file. The dataset itself is pure data in `seed/dataset.py`; phone indexes are
   append-only.
5. **The acceptance world is the seeded dataset.** `tests/acceptance/_world.py` migrates a private database, runs `seed.run`, builds
   the full app (every discovered module, database-backed resolver and session store) and signs people in through the real OTP/TOTP
   flow of the simulator. AT evidence therefore records `simulation=true` and a dataset string naming the seed. Direct database
   reads in the tests are oracles for ids the API would hide.
6. **AT-01 is inventory-driven.** `test_route_inventory` compares the live route table with the table of probed routes, so a route
   added by a later slice (files, exports, search, AI) fails the gate until its replay is written. Each replay compares the answer
   for a REAL foreign id with the answer for a RANDOM id (status, code, message, details, no foreign id echoed): an existence
   oracle is a failure even if both answers are refusals. The database layer is checked separately, table by table, from the
   catalogue.
7. **AT-02 is permission-level until slice 2.** The visitor-history endpoint does not exist; the denial is asserted with the real
   registry, the real resolver and `decide()` over the seeded memberships, and a tripwire fails when a gate/visitor route appears.

## Consequences

- Seeding costs about 5 seconds, so the acceptance tests use a session-scoped seeded clone for read-only scenarios and a fresh
  clone for the few that change state.
- AT-01 and AT-02 are `partial` for the PRD wording: files, export, search and AI (AT-01) and the endpoint-level denial (AT-02) are
  covered only by tripwires until their slices exist.
- A second, platform-level way to hold `platform_admin` is still needed (open question in the slice report).

## Alternatives considered

- SQL fixtures as the owner role: fast, but they skip audit/outbox and the maker-checker rules; rejected.
- HTTP-driven seeding through the simulator: closest to real, but every person would need an OTP login and elevated roles a TOTP
  step-up just to be created, and ids could not be deterministic; the service-level path keeps the same rules with far less machinery.
