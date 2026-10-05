# Dwaar resident app

Expo (React Native + TypeScript) with an accessible web build. Decisions: [`docs/adr/0015-resident-mobile-app.md`](../../docs/adr/0015-resident-mobile-app.md).

```bash
pnpm install                       # from the repo root (wrap in flock /tmp/dwaar-pnpm.lock when other agents work)
make db-up && make migrate && make seed && make api      # the real backend (DWAAR_ENV=local)
pnpm --filter @dwaar/resident-mobile web                 # http://localhost:8081, API at EXPO_PUBLIC_API_BASE_URL (default http://localhost:8000)
```

Sign in with a seeded resident through the labelled simulator, for example `+91 99999 01201` (Neha Patil, A-101); the "Simulator:
Fill code" button fetches the one-time code from the dev-only endpoint (`GET /v1/dev/otp`, exists only when `DWAAR_ENV` is
`local` or `test`). On an Android emulator use `EXPO_PUBLIC_API_BASE_URL=http://10.0.2.2:8000`.

| Script | What it does |
|---|---|
| `pnpm lint` | eslint incl. `eslint-plugin-react-native-a11y` as errors |
| `pnpm typecheck` | `tsc --noEmit` (strict) |
| `pnpm test` | Jest + React Native Testing Library (components, client vs recorded fixtures, OpenAPI contract, reducers) |
| `pnpm build` | `expo export --platform web` |
| `pnpm e2e` | starts postgres/API (local mode), builds the web export against it, drives chromium (`/opt/pw-browsers/chromium`) with Playwright, checks the DB, stops everything it started; screenshots in `e2e/screenshots/` |
| `pnpm gen:api` / `gen:api:check` | regenerate / verify `src/api/generated/schema.d.ts` from `packages/contracts/openapi/dwaar.v1.json` |
| `node scripts/record-fixtures.mjs` | re-record `__tests__/fixtures/recorded/*` from a running local API |

Not verified: iOS/Android builds, TalkBack/VoiceOver, OS font scaling, push (slice 4). The e2e run is chromium on react-native-web.
