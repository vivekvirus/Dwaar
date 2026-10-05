# Blocking decisions

Hand-maintained (there is no generator) from the PRD Decision Register D-01..D-28 and Open Questions Q1..Q14
(PRD sections 3, 19.6 and 20). `tests/security/test_w1_quality_requirements.py` fails if an ID is missing here or if
a statement about a shipped pack stops being true. The external-dependency catalogue (providers, hardware,
partners, approvals, field evidence) is `module_map.yaml`; what each one blocks is computed by
`tools/trace_check.py` into `TRACEABILITY.md` as `blocked-external`.

## 1. What blocks safe M0/M1 implementation

**Nothing.** Every decision has a PRD default and every open question gates a claim, an approval or a live
enablement, never the code. Anything that needs a human before real-world use is configuration, disabled or
unapproved by default, or behind a labelled simulator (`simulation=true`).

## 2. Every decision and question, and how this build treats it

`default` = built on the PRD default; changing it later is rework in the named module, not a safety issue.
`unapproved` = ships as versioned configuration with no approval, never binding. `simulator` = adapter plus a
labelled simulator; live use disabled. `claim` = a statement the build does not make.

| ID | Topic | Treatment in this build |
|---|---|---|
| D-01 | Product name | default: Dwaar is a placeholder; rename is a string change (see Q14) |
| D-02 | Pilot geography | default: Pune, Maharashtra co-operative housing societies; Karnataka and Haryana packs also ship, unapproved |
| D-03 | Target size (250 to 1,500 units) | default: commercial scope only, no code impact |
| D-04 | Languages | default: en, hi, mr at M1 (hi/mr machine-drafted, unreviewed); Kannada at M2; no all-language accuracy claim |
| D-05 | Resident app | default: React Native (Expo), TypeScript, plus accessible web |
| D-06 | Guard app | default: native Android Kotlin with Room; pure-Kotlin core so logic is JVM-testable; no Android SDK in this environment |
| D-07 | Admin console | default: Next.js App Router, TypeScript, Tailwind, shadcn/ui |
| D-08 | Backend | default: FastAPI modular monolith plus workers |
| D-09 | Database | default: PostgreSQL 16 with RLS as defence in depth; managed multi-zone India region is a deployment choice |
| D-10 | Identifiers | default: UUIDv7, native `uuid` |
| D-11 | Offline sync | default: application event protocol; no shared-file SQLite, no money CRDTs |
| D-12 | Edge gateway | default: Python, encrypted SQLite WAL `synchronous=FULL`; no durability claim until measured on the certified unit |
| D-13 | Offline validity | default: resident credentials 72 h, guest passes 2 h gate-bound |
| D-14 | Approval expiry | default: 90 s, never auto-allow |
| D-15 | Notification cascade | default: t=0, 10, 20, 35, 90 s, configurable within limits |
| D-16 | Visitor data retention [LEGAL] | unapproved: retention pack, 30 days (90 with justification) plus restricted archive |
| D-17 | Backups | default: 35-day encrypted rotation; restores re-apply deletion tombstones |
| D-18 | AI provider | default: provider-neutral adapter; labelled simulator provider only until terms are signed (Q13) |
| D-19 | Speech | default: self-hosted faster-whisper is the plan; simulator only, no accuracy claim |
| D-20 | Payment aggregator | simulator: aggregator adapter disabled until credentials and onboarding exist; BBPS is M2 |
| D-21 | Telephony, SMS, WhatsApp, video [TBD] | simulator: vendors undecided, live channels disabled |
| D-22 | Accounting export | default: Tally XML file export first; Zoho Books API is M2 and disabled |
| D-23 | First hardware | simulator: one dry-contact barrier model and one RFID reader model; live adapter disabled until installer sign-off |
| D-24 | Binding governance [LEGAL] | unapproved: binding stays disabled until a legal pack is approved; opinion polls only |
| D-25 | Defaulter amenity restriction [LEGAL] | disabled by default; essential services never restricted (INV-08) |
| D-26 | Pricing tiers | default: commercial only; no code impact until billing-of-the-platform is built |
| D-27 | Billing unit | default: commercial only; no code impact |
| D-28 | Payment cost policy [VERIFY] | unapproved: society absorbs MDR and gateway fees, no resident surcharge, shown as unconfirmed |
| Q1 | Willingness to pay | claim not made: commercial validation outside the code |
| Q2 | Push reliability on real handsets | simulator: push adapter simulated; no reliability claim until a device matrix exists |
| Q3 | Gate hardware manuals and measurements | simulator: no performance claim |
| Q4 | Rule 8(3) retention of photos and ANPR images [LEGAL] | unapproved: retention is configuration |
| Q5 | Maharashtra Rules 2026 values [VERIFY] | unapproved: `maharashtra-chs` pack ships unapproved; no law hard-coded (INV-10) |
| Q6 | Karnataka Apartment Bill 2026 status [LEGAL] | unapproved: `karnataka-aoa-1972` ships unapproved and enabled; `karnataka-bill-2026-variant` ships unapproved and DISABLED (the Bill is not law) |
| Q7 | Haryana online meetings and weighted votes [LEGAL] | unapproved: `haryana-group-housing` ships unapproved and labelled LEGAL/VERIFY; counsel must confirm the online-meeting and weighted-vote rules before it can bind |
| Q8 | GST and TDS classification [CA] | unapproved: tax packs ship `draft`; calculators stamp every result `binding=false` until approved with evidence |
| Q9 | UPI MDR classification [VERIFY] | unapproved: cost configuration marked VERIFY, no cost claims |
| Q10 | Delivery-partner access | disabled: M3, needs written partner approval |
| Q11 | Metered water billing in Maharashtra [LEGAL] | disabled until counsel opinion (M3 module) |
| Q12 | Vendor terms for calls, SMS, WhatsApp, video [TBD] | same as D-21: simulators only |
| Q13 | AI provider processing terms | simulator: AI runs only on the labelled simulator provider |
| Q14 | Name and trademark [TBD] | default: placeholder Dwaar used internally |

## 3. Open product decisions found while building (not in the PRD register)

- **AT-47 and DB-05 at M1.** PRD section 16 makes AT-47 (a constraint rejects restricting an essential amenity) an M1
  gate, but amenities (AMEN-01..03) are scheduled for M2 while DB-05 is assigned to slice 4. Default taken: the
  constraint ships with the first table that can hold an amenity restriction, and AT-47 stays `not-started` until that
  table exists. Owner to confirm or move AT-47 to M2.
- **PRD role codes.** PRD 5.1 names roles in upper case (`OWNER_OCC`, `GUARD_SUP`); the API accepts lower-case role
  names only. Default taken: lower-case snake case; the mapping table belongs with the role matrix (PRD 19.4), still
  to be written.
