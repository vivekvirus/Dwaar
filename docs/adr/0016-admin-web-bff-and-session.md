# ADR-0016: Committee console (apps/admin-web): BFF, cookies, society context, access model

Status: accepted (slice 2). REQ: IAM-03, IAM-08, IAM-09, INV-01, INV-05, INV-07, SOC-02/03/05/06, GATE-07 (view and review), UX, RPT-01 (partial).

## Context

The committee console is a Next.js App Router app. PRD 5/6/12 require: server-derived roles, a role-specific menu, a society
selector that never silently changes context, HttpOnly cookies with CSRF protection on the web (IAM-09), TOTP step-up for
elevated roles (IAM-03), session list and revocation (IAM-08), PRD 12.2 errors without membership disclosure. The API issues
bearer access tokens (15 min) and rotating refresh tokens with reuse detection, and answers `X-Society-Id` / path society only
for societies the caller's current grants cover. The API was not changed for this slice.

## Decisions

1. **Backend-for-frontend inside Next route handlers.** The browser talks only to same-origin `/api/auth/*`, `/api/session*` and
   `/api/bff/*`. Access and refresh tokens live in `HttpOnly; SameSite=Strict` cookies (`dwaar_at` path `/`, `dwaar_rt` path
   `/api` so page routes never receive it, `Secure` except in the labelled local environment). Tokens never appear in a
   response body, in `document.cookie` or in storage (asserted in unit and e2e tests).
2. **CSRF.** Double submit: a non-HttpOnly `dwaar_csrf` cookie (set by middleware and by `/api/session`) must be echoed in
   `X-CSRF-Token` on every POST/PUT/DELETE; additionally `Sec-Fetch-Site` and `Origin` must be same-origin when present. Mutating
   BFF calls without both are refused with 403 `not_authorised` and never reach the API.
3. **Refresh is single-flight.** Parallel requests that find the access cookie gone must not each rotate the same refresh token
   (the API would read that as theft and revoke the session). `server/tokens.ts` coalesces refreshes per refresh token and
   remembers the result for 15 s for late arrivals. This is per Node process: a multi-instance deployment needs sticky routing or
   a shared lock (open item).
4. **Roles come only from the server.** `/v1/me` is the single input. An elevated role is reported by the API with
   `active=false` until the session passed TOTP; the console treats `valid_now && requires_mfa && !mfa_satisfied` as "step-up
   pending" and sends the person to the TOTP step instead of showing the console. The menu (`lib/access.ts`) and every page guard
   are derived from the effective roles of the SELECTED society. The role -> capability table mirrors the API permission
   declarations and only decides what to show; the API still authorises every call (blocked request BR-1: expose effective
   permissions in `/v1/me`).
5. **Society context is explicit and server-held.** The selected society is an HttpOnly cookie `dwaar_soc`, set only by
   `POST /api/session/society` with `{society_id, confirm: true}` and only for a society where the person holds a console role
   (anything else answers 404 `not_found`, identical for unknown and not-yours). Nothing is preselected when several societies are
   usable (a picker is shown); a single usable society is selected on first load because there is no prior context to change. The
   proxy builds the upstream path itself (`/api/bff/society/units` -> `/v1/societies/{selected}/units` plus `X-Society-Id`), drops
   any society in the query, and requires the page's `X-Dwaar-Society` claim to equal the cookie: another tab that switched makes
   stale tabs fail loudly (409 `stale_version`, `details.reason=society_context_changed`) instead of acting in the wrong society.
   Client caches (TanStack Query) put the society id first in every key and are cleared on switch, which also reloads the page.
6. **The proxy is an allow-list, not a relay.** Only (method, path-pattern) pairs listed in `server/config.ts` are forwarded
   (a contract test proves each exists in the OpenAPI file); query parameters are allow-listed; body size is capped; idempotency
   keys are forwarded or generated for writes; a 401 triggers one refresh and one retry.
7. **Errors.** Every PRD 12.2 code maps to an existing `@dwaar/i18n` `errors.*` key; server `message` text is never shown;
   `rate_limited` shows the retry seconds; unknown codes fall back to `errors.unknown` with the request id. A short explanation is
   added only for a fixed list of `details.reason` values (maker-checker, review-first, ...). Not-found and not-authorised for
   society scope are rendered with neutral wording.
8. **Copy.** Shared strings come from `@dwaar/i18n`; console-only strings are in `src/i18n/console.en.json` under `console.*`.
   hi/mr console copy does not exist yet and falls back to English. ESLint forbids hard-coded JSX text.
9. **Honesty.** Counters come from the live exception queue (capped at 100 rows by the API and labelled `100+`); CSV export is
   client-side over the rows currently loaded (no export endpoint yet); the legal pack shows "Unapproved: binding governance is
   disabled" from the API fields; integration readiness is shown only to the secretary and only states what `/v1/meta` reports.
10. **Security headers.** No third-party script, font or tracker (INV-05); CSP `default-src 'self'` with `'unsafe-inline'` for
    Next's bootstrap scripts and styles (no nonce pipeline yet), `frame-ancestors 'none'`, `no-store`.

## Testing

Vitest + Testing Library (BFF handlers with a fake API, access model, error mapping, i18n catalog completeness, components);
contract tests validate recorded real responses and BFF-built request bodies against the OpenAPI file and pinned response
schemas; Playwright runs against the real local stack (`make db-up migrate seed api`, `DWAAR_ENV=local`, private port and data
directory) including axe-core WCAG 2.2 AA scans, keyboard flows, zoom/reflow, role and cross-society negatives, and live
contract checks. The OTP rate limit (3 per number per 5 minutes) and single-use TOTP steps shape the e2e personas and fixtures.

## Consequences / open items

Menu mirror can drift from the API until BR-1 is done; refresh coalescing is per process; no server-side CSV export; guard
supervisor approval-request view needs a gate choice (API requirement); hi/mr console copy and human review of translations are
pending; manual screen-reader testing has not been done.
