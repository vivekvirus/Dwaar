# ADR-0010: Organisation module (societies, legal entities, blocks, units, packs, flags)

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team
- Related: PRD SOC-01, SOC-02, SOC-03 (units subset), ARCH-01, ARCH-03, ARCH-05, INV-01, INV-10, GOV-01, D-24, PRD 5.2, 8.1, 8.2;
  ADR-0004 (RLS), ADR-0005 (audit/outbox/idempotency), ADR-0006 (registry/authz), ADR-0007 (packs);
  code: `dwaar_api/modules/organisation/`, migrations `0101-0103`; tests: `tests/integration/organisation/`

## Context

The first feature slice needs the tenant root: a society with a legal entity, its blocks and units, the selection of
legal and tax packs, and per-society switches and budgets. The identity module (migrations 0130+) will hang
memberships and grants on these rows, so the keys and the isolation model must be fixed first.

## Decision

1. **`societies` is RLS-protected by its own id.** The PRD table has no society column. The table carries
   `society_id uuid GENERATED ALWAYS AS (id) STORED`, so `dwaar_enable_society_rls` applies unchanged and the policy reads
   `society_id = app.society_id`: a society context sees exactly its own row. Creating a society needs the context of
   the NEW id: the API allocates a UUIDv7, opens the transaction with that context and inserts. A creator can neither read
   nor write another society's row. Listing "my societies" opens one short transaction per granted society (a context holds
   one society by design) and is driven by the grant resolver, never by a query across societies.
2. **Global tables are reachable only through catalog views.** `orgs`, `legal_packs`, `tax_packs` have no `society_id` and
   the runtime roles hold no privilege on them (the catalog guard forbids reachable tables without a society column). The API
   reads reference data through owner-owned views (`org_catalog`: id and status only; `legal_pack_catalog` and `tax_pack_catalog`:
   identity, status, computed `approved` / `binding_allowed`, no rules or content). Views run with the owner's rights, so
   no `SECURITY DEFINER` function (each needs a reviewed entry in the security test allow-list) is required. Rows are
   written by the pack loader and operations tooling as `dwaar_owner`. An organisation API for `orgs` is not part of this
   slice (tests and tooling insert them as the owner).
3. **Legal entity and society reference each other** through DEFERRABLE FKs, and `societies (id, legal_entity_id)` references
   `legal_entities (society_id, id)`: a society can never adopt another society's legal entity (ARCH-01). Blocks and units carry
   `society_id`; `units (society_id, block_id)` references `blocks (society_id, id)`, so a unit can never sit in another society's
   block. The identity module should use the same composite pattern against `units (society_id, id)`.
4. **Units are unique per `(society_id, block_id, label)`** exactly as PRD 8.1/8.2; an additional case-insensitive unique
   index on the trimmed label (and block name) stops `A-101` and `a-101` from coexisting. Archived units keep their label
   reserved. Units and blocks are archived, never deleted.
5. **PAN, TAN, GSTIN** are encrypted with `dwaar_common.crypto` (AES-GCM, AAD bound to society, table, field and row id) into
   `pan_enc`, `tan_enc`, `gstin_enc`, with a masked display copy (`******234F`) stored beside it; the API never decrypts to
   respond, never returns an unmasked value, and audit/outbox rows carry neither. Deviation from PRD 8.2: its `gstin` column
   is `gstin_enc` here because PRD 7.4 requires ID numbers to be encrypted and the task says PAN/TAN/GSTIN are all encrypted.
   Only the shape (regex) of each identifier is validated; no registry or checksum claim is made. Without a configured key
   ring (`app.state.pii_cipher` or `DWAAR_PII_KEYS`) society creation answers 503, never stores plaintext.
6. **Packs are rows loaded by code.** `organisation.packs.load_packs(conn)` upserts every shipped legal and tax pack through
   `dwaar_packs.FilePackRepository` (so a file that merely claims approval is stored as unapproved, ADR-0007 #9). An
   unchanged pack is a no-op, a changed unapproved pack is refreshed in place, a changed approved pack is refused. A CHECK makes
   `approved` and `approved_by/approved_at` all-or-nothing. A society may select any existing, enabled, non-retired legal pack
   whose entity type fits (approved or not) and any enabled, non-retired tax pack; selection never implies approval.
   Tax packs are not in the PRD 8.2 DDL; `tax_packs` mirrors `legal_packs` because `societies.tax_pack_id` needs a target.
7. **Binding governance is disabled until the pack is approved (D-24, GOV-01).** `society_feature_flags.binding_governance`
   starts off. Enabling it fails with 422 `legal_pack_not_approved` unless the society's pack is approved with evidence, enabled,
   and inside its effective range (IST date). The configuration read reports `binding_governance.enabled` and the blockers to
   authorised readers only.
8. **Permissions** are declared in `permissions.py` from the PRD 5.2 matrix with lower-case role codes: `society.read` (secretary,
   treasurer, committee, estate_mgr, auditor), `society.configure` and `unit.write`/`unit.import` (secretary), `unit.read` (staff
   roles, guard receives a masked view without areas, interest or cost; owners, tenant and family are UNIT scoped, so they
   see only units their grants cover), `society.view` (every role: name, city, timezone) and `society.create`
   (`platform_admin`, or `org_admin` within the org of the society where the grant is held). Platform roles are ordinary society-wide grants
   held in an operator "home" society: the identity module may model them differently as long as the resolver returns a
   society-wide `Grant` with that role; the create route then needs no change. Creation re-reads grants fresh (`fresh=True`).
9. **Writes** use `core.audit.mutation` (domain row + audit row + outbox row in one SAVEPOINT). `POST` creates of blocks, units
   and imports require `Idempotency-Key` (`IdempotentCall.run`). `PATCH`/`PUT`/`DELETE` carry optimistic concurrency
   (`expected_version`, 409 `stale_version`) or are naturally idempotent and are marked `idempotency_exempt` with the reason.
   `POST /v1/societies` is exempt too: there is no society scope to bind a key to before the society exists (a retried create
   makes a second, separately audited society; the operator workflow, not the HTTP key, owns that).
10. **CSV import** (`POST /v1/societies/{id}/units:import`, body `text/csv`) validates the whole file first and writes only if the
    report is clean, in one transaction with one audit row and one `UnitsImported` event (not one per unit). `dry_run=true`
    reports only; `create_missing_blocks=true` creates blocks named in the file. Rules: required header, no unknown or repeated
    columns, UTF-8, at most 5000 rows, formula-injection refusal, decimals with bounded precision (never floats), integer paise,
    undivided interest of all active units at most 100, duplicate detection in the file and against existing (archived included)
    units. Invalid non-dry-run requests answer 422 `policy_violation` with the report in `details`.
11. **ARCH-05**: `society_feature_flags` and `society_quotas` (rate per minute, burst, queue quota, AI requests per day) exist per
    society; `societies.ai_budget_paise` is the PRD column. Enforcement by the rate limiter, queue and AI gateway belongs to
    those services; this module stores and audits the values.

## Consequences

- The catalog guard (`tests/security/test_core_rls_isolation.py`) passes without allow-list edits.
- `dwaar_api` loads `dwaar_packs` lazily (only the loader). `services/api/pyproject.toml` should list `dwaar-packs` as a
  dependency for deployments that run the loader (recorded as a blocked request).
- Org-level administration (creating `orgs`, org membership) is intentionally minimal: only `society.create` consults the org.
- The creator of a society receives no role from this module; identity must grant the first secretary (the `SocietyCreated`
  outbox event and the audit row carry the actor).

## Alternatives considered

- A global-table allow-list entry in the catalog guard for `legal_packs`, or SECURITY DEFINER read functions: rejected; a
  narrow view needs no shared-file edit and no new privileged code path.
- A `society_id` column on `legal_entities` only through `societies`: rejected; two mutually referencing deferrable FKs give
  a one-hop composite guarantee in both directions.
- One audit row and event per imported unit: rejected for 5000-row files; the batch is one aggregate (`unit_import`).
