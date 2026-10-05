# ADR-0007: Law as configuration (legal, tax, retention and fee packs)

- Status: accepted
- Date: 2026-10-05
- Related: PRD INV-10, GOV-01, FIN-04, PAY-05, TAX-01..05, PRIV-06, D-13, D-15, D-16, Appendices A-C; AT-37, AT-38, AT-46

## Context

Interest caps, quorum, notice periods, tax rates and retention periods differ by state and change by notification.
Hard-coding them would make a legal change a code release and would let the platform assert law nobody approved.
Counsel and CA approval are external steps that this repository cannot perform.

## Decision

1. **Packs are versioned YAML** under `packages/legal-packs/` (legal packs, retention classes, cascade/offline
   defaults) and `packages/tax-packs/` (TDS, GST for RWAs, e-invoice, UPI MDR fee schedule). Each has a JSON Schema
   in its `schema/` folder; `python -m dwaar_packs validate` checks every shipped pack (schema first, then
   pydantic models and cross-references such as `legal_source_ref`).
2. **Legal pack shape mirrors the PRD 8.2 `legal_packs` row** (jurisdiction, entity_type, version, rules,
   legal_sources, approved_by, approved_at, effective_from, effective_to). Rules are a flat map of dotted keys
   (exactly the PRD Appendix A keys for Maharashtra) to `{value, unit, labels, legal_source_ref}`. A null value means
   "unconfigured": it must be marked `configurable` and set with a legal reference before use. `to_db_row()` produces
   the table shape.
3. **Nothing ships approved.** Every pack has `approved_by: null`, status `unapproved` (legal) or `draft` (tax) and
   carries the PRD labels (LEGAL, VERIFY, CA, TBD). The schema and models reject any approver on a non-approved
   pack and an approved pack without approver and timestamp. Sources are only those named in the PRD, as
   `legal_source_ref` strings; `url` stays null because the PRD names no exact URLs.
4. **Binding gate (GOV-01).** `is_binding_allowed(pack, at_date)` is true only when the pack is enabled, approved
   and `at_date` is within `[effective_from, effective_to]`. `is_binding_ready` additionally requires that no rule is
   unconfigured. The Karnataka Bill variant is `enabled: false` until enactment and counsel review.
5. **Evaluators read parameters from packs.** Quorum uses exact `Fraction` arithmetic with the pack's fraction,
   rounding and cap (ordinary: min(ceil(2/3 x members), 20); redevelopment: ceil(2/3 x total) plus registrar and
   video conditions). `check_interest_cap(rate_bp, pack)` returns a structured violation (AT-37: 18% against the
   12% simple cap blocks approval; an unconfigured cap fails closed). TDS, GST and UPI MDR calculators return a rule
   ID and explanation; missing configuration raises `RuleNotConfigured` so the caller routes to review (TAX-05).
6. **Money is integer paise and rates are basis points.** Rounding mode is an explicit parameter
   (`half_up`, `half_even`, `up`, `down`); the pack supplies the default.
7. **Cascade and offline defaults carry bounds** (min 10 s between steps, expiry 60-180 s, guest pass at most
   2 h, standalone terminal at least 24 h); `cascade_config(overrides)` rejects anything outside them and cannot be
   configured to auto-allow (INV-03).
8. **Access** goes through the `PackRepository` Protocol (file-backed and in-memory implementations now; a
   `legal_packs`-table implementation can follow without caller changes). Packs are located by walking up from the package;
   `DWAAR_PACKS_ROOT` is honoured only when `DWAAR_ENV` is local or test.
9. **Approval is evidence, not a claim** (fix round 1, GOV-01). `status: approved` plus an approver name in a pack file proves
   nothing. A pack is binding only if the approval registry holds a pin of its exact content (`pack_content_hash`): by default
   `DWAAR_PACK_APPROVALS` from deployment configuration (`python -m dwaar_packs pin <file>` prints the entry); a DB-backed
   approvals table can implement `ApprovalRegistry` later. `FilePackRepository` serves unproven claims as unapproved. Evaluators
   (`evaluate_quorum`, `evaluate_resolution`, `check_interest_cap`) compute from any pack and stamp results with `binding` and
   `binding_blockers`, so a preview from an unapproved pack cannot be mistaken for a binding decision.
10. **Pack data is immutable** (`FrozenDict`/`FrozenList`), YAML duplicate keys are rejected, secretary overrides are
    shape/range-validated, the cascade pack carries approved upper bounds for the four safety-relevant offline settings, and
    all money inputs are ints in signed 64-bit range rounded by the single `dwaar_common.money.div_round`.

## Consequences and open items

- Counsel approval of legal packs, CA approval of tax packs and acquirer verification of the UPI schedule remain
  external (`blocked-external`); the platform shows binding features as disabled until then.
- The PRD does not list the "specified essential categories" for the flat Rs 5 UPI fee; `categories` is empty and
  must be configured from the acquirer/DFS notification. Rates for professional and rent TDS, the missing-PAN rate,
  the aggregate-crossing basis and the GST rate are null for the same reason.
- PRD wording differs on the e-invoice AATO threshold ("above Rs 10 crore" in the task text versus "Rs 10 crore and
  above" in TAX-03). The pack stores `comparison: gte` following the PRD requirement text; the CA must confirm.
- Pack `effective_from` is the date a pack version is proposed for use, not the commencement date of the underlying
  law, except where the PRD gives one (Maharashtra Rules, 18 June 2026, VERIFY Gazette; TDS, 1 April 2026; UPI MDR,
  15 October 2026).
