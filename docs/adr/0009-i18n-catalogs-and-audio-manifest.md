# ADR-0009: i18n catalogs, audio prompt manifest and review status

- Status: accepted
- Date: 2026-10-05
- Related: PRD INV-11, UX-02, UX-03, UX-04, UX-08, NOTIF-09, COM-02, 12.2; BUILD_BRIEF section 3 (i18n)

## Context
Guards and staff must use every core flow in their own language with icons and audio (INV-11). M1 languages are
English, Hindi and Marathi; Kannada follows at M2. No native-speaker or counsel review has happened.

## Decision
1. **Catalogs** live in `packages/i18n/locales/<lang>/<namespace>.json` with flat dotted keys; the full key is
   `<namespace>.<key>`. Namespaces: common, errors, states, guard, resident, notifications, visitor, ops, finance,
   consent. English is the source; `{param}` placeholders must match across languages.
2. **Typed keys.** `tools/gen_i18n_keys.mjs` generates `src/keys.ts` (key union plus per-key params type) and
   `src/catalogs.ts`; `--check` fails when they are stale. `t()` falls back locale, then English, then the key.
3. **Unit numbers** are passed through verbatim as Latin characters (e.g. `A-402`) in every language, so they stay in
   one script (UX-03). Catalog text never transliterates them.
4. **Truthful states (UX-04, INV-07).** The three UX-04 strings are exact; submitted, approved, entered,
   handed-over, paid and settled are separate keys. "Approved" says "not yet entered".
5. **Errors** carry one user-safe message per PRD 12.2 code. Messages never distinguish "not a member" from "does
   not exist"; `not_authorised` and `not_found` are generic.
6. **Lock screen (NOTIF-09).** Lock-screen notification keys have no visitor or unit placeholders. Security and
   emergency channel text states that it never carries advertisements.
7. **Audio.** `audio/prompts.yaml` has one entry per `guard.*` key per language: spoken text (no placeholders),
   duration hint, status `unrecorded`. Nothing is recorded. `icons.yaml` maps each guard key to an icon name; allow
   and deny differ by shape and always pair with text (UX-02).
8. **Review (COM-02).** `review_status.json` marks every hi/mr namespace `machine_drafted: true` and every namespace
   `human_reviewed: false`. Namespaces `errors, states, guard, notifications, visitor, consent, finance` are legal or
   safety significant and need human review before release. Consent and notice text are stubs flagged for counsel;
   they are not approved wording.
9. **Gate.** `tools/i18n_check.py` fails on missing or extra keys, placeholder mismatch, empty values, missing audio
   or icon for a guard key, missing PRD 12.2 messages and inconsistent review status; it prints an unreviewed report.

## Consequences
Hindi and Marathi text must not ship to real users as approved until a native reviewer signs off and the status file
is updated with a reviewer. Kannada adds a locale directory and entries in the tool's language list at M2.
