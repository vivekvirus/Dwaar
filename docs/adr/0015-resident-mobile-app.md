# ADR-0015: Resident app (Expo / React Native + web), slice 2

- Status: accepted (web build verified in chromium against the local API; native builds NOT run, see "Not verified")
- Date: 2026-10-05
- Deciders: build team (slice 2)
- Related: PRD D-05, 6 (IA, UX-01..07, accessibility acceptance, tokens), 9.2 (GATE-01, GATE-02, GATE-03), 12 / 12.2 / 12.3,
  INV-01, INV-05, INV-07; ADR-0009 (i18n catalogs), ADR-0011 (identity), ADR-0013 (visits API); code: `apps/resident-mobile/`

## Context

D-05 fixes the resident app as React Native (Expo), TypeScript, iOS and Android, plus an accessible web build. Slice 2 builds the
resident side of the gate flows against the real visits and identity APIs: OTP sign-in through the labelled simulator, household
selection, Home with the pending approval pinned, the approval decision screen (409 semantics), invitations with a signed QR,
visitor history, profile and privacy. Push notifications belong to slice 4.

## Decisions

1. **Expo SDK 57 + expo-router, one codebase for native and web.** `app/` holds thin route files; every screen is a component
   in `src/screens/` so it is testable without the router (tests mock `useRouter`). The web build is `expo export --platform web`
   (single-page output, react-native-web). No analytics, crash-reporting, ads or tracking package is a dependency (INV-05); the
   Profile screen says so and a dependency review of `package.json` backs it.
2. **Typed client from the OpenAPI file, plus runtime validation.** `scripts/gen-api.mjs` runs `openapi-typescript` over
   `packages/contracts/openapi/dwaar.v1.json` and writes `src/api/generated/schema.d.ts` (committed; `pnpm gen:api:check` and a
   contract test fail when it is stale). The spec types request bodies and `ErrorBody` but leaves most 2xx bodies as free-form
   objects, so responses are parsed with zod (`src/domain/types.ts`) at the HTTP boundary: an unexpected shape is a
   `ContractError`, never a silently wrong screen. Request bodies are checked against the spec's JSON Schemas with Ajv 2020-12
   in `__tests__/contract.test.ts`, which also asserts that every operation the client calls is documented with its required
   headers and query parameters.
3. **One HTTP client** (`src/api/client.ts`): bearer auth, a single refresh-and-replay on 401, `Idempotency-Key`, `X-Society-Id`
   (the `/v1/approval-requests/*` and `DELETE /v1/invitations/{id}` routes carry no society in the path), response validation,
   error mapping. Automatic retries (network error or 503, at most 2) happen only for GET or for a call that carries an
   `Idempotency-Key`, and always re-send the same key and body.
4. **Commands are objects created once per user action** (`DecisionCommand`: Idempotency-Key, `client_action_id` as UUIDv7,
   `expected_version` of the version the screen showed). A retry after a network failure re-sends the same object, so it cannot
   decide twice; a new decision is a new command. Invitation creation freezes its body and key on the first attempt for the same
   reason. A late poll that still says "pending" can never reopen a request the screen has seen closed (GATE-03).
5. **Approval flow is a pure reducer** (`src/state/approvalFlow.ts`): `ready`, `submitting`, `send_failed`, `closed`
   (`decided_here`, `decided_elsewhere`, `expired_on_submit`, `seen_closed`), `not_available`, `error`. 409 `already_decided`
   shows the canonical result carried in `details.canonical` (the other device's outcome, never our intent); 409
   `request_expired` shows expiry, no permission, no entry; 409 `stale_version` reloads. 403/404 both render the same "not
   available" copy (no membership disclosure).
6. **Truthful vocabulary (INV-07).** `src/domain/status.ts` is the only mapping from backend state to words: an approved request
   with `entry_observed=false` reads "Approved; not yet entered" and the entry line "Not yet at gate / not observed". "Entered"
   appears only when the backend observed entry. Every status also carries a glyph, so colour is never the only signal.
7. **Household context never changes silently.** Contexts are derived from the server's `/v1/me` (active, valid household roles
   with a unit: owner_occ, tenant, family; `owner_nr` and staff roles are excluded because the API refuses them). A stored
   choice is re-validated on every start; if it is gone the person must choose again, with a notice. With exactly one household it
   is active and visible in the header. Data caches are keyed by society and unit and cleared on any change; every object coming
   back from the API is checked against the active unit (fail closed).
8. **Tokens.** Native: `expo-secure-store` (three keys, each under 2 KB). Web: `sessionStorage` (tab-scoped; no secure enclave
   exists in a browser) and the privacy copy says so. Refresh tokens rotate; the new pair is persisted before the original
   request is replayed and concurrent 401s share one refresh (a second use of a rotated token would look like reuse). A refresh
   that cannot reach the server keeps the tokens; one the server rejects ends the session with a notice.
9. **i18n.** Shared strings come from `@dwaar/i18n` (`resident`, `states`, `errors`, `common`). Strings the shared package does
   not hold yet live in `src/i18n/appStrings.ts` under `app.*` with the same en/hi/mr shape and a test for key and
   placeholder parity. The hi/mr text there is machine-drafted and unreviewed (COM-02); moving it into `packages/i18n` and getting
   a native-speaker review is a blocked request. Dates are formatted with Latin digits and `Asia/Kolkata`, unit numbers are passed
   through verbatim (UX-03).
10. **Notification adapter interface only.** `src/notifications/adapter.ts` defines `NotificationAdapter`; the default does nothing
    and `available` is false, so the UI never claims push. A real adapter (slice 4) can only trigger a refresh from the API.
11. **Unreleased modules do not exist in the UI.** Dues, Help, Community, "Report an issue" and notices have no API yet: no tab,
    no button, no empty screen. Home has quick actions for invite, approve and view visitors (UX-01 lists dues and issues too;
    they appear with their modules). The raise-a-support-or-privacy-issue path (UX-07) has no endpoint yet and is therefore
    open.
12. **Accessibility is enforced in three layers.** `eslint-plugin-react-native-a11y` rules as errors (a test proves the rules fire
    on bad code), React Testing Library assertions (role, accessible name, state, minimum 48 dp height on every control, no
    truncation or fixed heights, no font-scaling caps, contrast of every token pair at least 4.5:1), and an axe-core run plus
    200% browser-zoom reflow check in the Playwright script. None of this replaces a screen-reader pass on a device.

## Alternatives considered

- **react-navigation without expo-router**: more wiring for web deep links, no gain here.
- **Hand-written fetch wrappers per endpoint with `any` bodies**: rejected; the generated types catch request drift, zod catches
  response drift.
- **Offline queue for decisions**: rejected on purpose. A decision on a gate request is time-critical (90 s) and a queued stale
  approval is exactly what GATE-03 forbids; an offline tap says "not sent, nothing decided" and offers a retry of the same command.
- **Persisting server data to disk for offline reading**: not done; the in-memory cache is shown with an offline banner only when
  it holds data, otherwise the screen says nothing is saved.

## Consequences / open points

- OpenAPI does not declare the `X-Society-Id` header the approval routes use, and most 2xx bodies are untyped; both are reported to
  the API owner (a contract test records the first as a known gap).
- The decision response does not include the permission validity in minutes, so the effect text says "a limited time" and the
  receipt shows the exact `permission_expires_at` after approval.
- No device or emulator was available: native behaviour (SecureStore, safe areas, TalkBack/VoiceOver, OS font scale, push) is
  unverified.
