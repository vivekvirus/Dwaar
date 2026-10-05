# ADR-0014: Guard Android app (native Kotlin), slice 2

- Status: accepted (skeleton; see "Not verified")
- Date: 2026-10-05
- Deciders: build team (slice 2)
- Related: PRD D-06, 6 (UX-02, UX-03, UX-04, UX-08, UX-09, UX-10), 9.2 (GATE-02, GATE-09, GATE-13), 9.3 (EDGE-01..03, EDGE-05),
  12.2, 12.3, 16 (AT-48), INV-03, INV-05, INV-07, INV-11; ADR-0009 (i18n catalogs); code: `apps/guard-android/`,
  `tools/dev/android/`, `.github/workflows/android.yml`

## Context

D-06 fixes the guard app as native Android (Kotlin, Room/SQLite) in device-owner kiosk mode. Slice 2 builds the skeleton that later
slices fill in: the unannounced-visitor flow end to end against the real visits API, the local outbox with the edge event
envelope, truthful statuses, the guard language model and the shared catalogs. Nothing could be run on a device or emulator here.

## Decisions

1. **Two Gradle modules.** `:core` is pure Kotlin/JVM (no `android.*`): API models and client, canonical JSON, Ed25519, edge
   envelope, outbox interface, sync engine, status mapping, banner logic, guest flow controller, i18n loader, scanner decoder,
   training model, palette/contrast. It is tested on the JVM (JUnit 5). `:app` is Android only: Compose UI, Room, WorkManager,
   Keystore-backed storage, audio, kiosk. The line is deliberate: anything that decides what the guard is told, or what is
   written to the outbox, is JVM-testable.
2. **No DI framework.** Hand-written `AppContainer` (about 100 lines, lazy members). Hilt/Dagger would add kapt/KSP processing and
   generated graphs for roughly ten singletons; Koin adds a runtime service locator with failures at runtime. Core classes take
   their collaborators in constructors, so a framework can be added later without touching `:core`.
3. **Crypto is JDK crypto only.** Canonical JSON, `sha256:<hex>` payload hash and Ed25519 (`java.security`, JDK 15+; Android
   platform provider from API 33, hence `minSdk = 33`) are implemented in `:core` to be byte-identical to
   `packages/dwaar-common` (`events.py`, `signing.py`). Proof: `tools/dev/android/gen_golden_vectors.py` runs the Python
   implementation and writes `core/src/test/resources/golden/edge_vectors.json` (canonical cases, rejected inputs, three
   signed edge events with TEST-ONLY keys). `GoldenVectorTest` reproduces canonical JSON, hashes, signing bytes AND signatures
   exactly (Ed25519 is deterministic). CI regenerates the file and fails on drift. Known difference: Python accepts integers
   up to 64 bits unsigned, Kotlin up to `Long.MAX_VALUE`; no event field needs the gap.
4. **The outbox never regenerates ids.** `OutboxStore.append(build, projection)` allocates the next `seq` inside the store's
   transaction, builds and signs the event for that seq, and commits event row, local projection and the sequence counter
   together (Room: one `withTransaction`; a failing build consumes no seq). The stored envelope text is re-sent verbatim on every
   retry (`SyncEngine`), with exponential backoff and full jitter, at most 500 events or 1 MB per batch, and a bad event is
   quarantined without blocking later ones (EDGE-03). The counter row survives pruning.
5. **Truthful status (INV-07, UX-04).** `VisitStatusMapper` maps (server request state, entry_observed, local outbox state) to
   one catalog string and one icon. Approved is never shown as entered. A locally recorded entry shows "Saved on this device;
   awaiting sync" until the sync acknowledges it (or the server reports `entry_observed`). A countdown that reaches zero shows
   "No response yet" and offers the manual fallback; nothing auto-allows (D-14, INV-03). The countdown is anchored to the
   server's `expires_in_seconds`, not the terminal clock (EDGE-05: the clock is unverified in this slice).
6. **Shared i18n catalogs are copied and gated at build time.** `:core:syncI18nCatalogs` copies `packages/i18n/locales/{en,hi,mr}`
   (namespaces guard, states, common, visitor, errors), `audio/prompts.yaml` and `icons.yaml`; `:core:verifyI18nCatalogs` fails
   the build if any key is missing or empty in a supported language, if a key listed in `core/src/main/i18n/required-keys.txt`
   (the keys the app code references) is absent, or if a `guard.*` key has no audio manifest entry for every language.
   `tools/dev/android/test-i18n-gate.sh` demonstrates the failure on a temp copy. The catalogs ship as APK assets.
7. **Audio is hooked, not faked.** `AudioManifest` resolves key + language to a declared asset path
   `audio/<lang>/<key>.ogg`. Every clip is `unrecorded`, so `AudioHook` shows a visible "[dev] audio not recorded" indicator and
   plays nothing. No TTS.
8. **Language per guard at login (UX-08).** The login screen offers en/hi/mr in their own scripts; the choice is saved against a
   hash of the guard's phone (`guardKeyFor`), never per site.
9. **Practice mode (UX-09 skeleton).** A scripted `PracticeVisitsApi` and dummy "Practice" units; entries are never written to the
   outbox; scenarios run are counted per guard. This is not a competency sign-off (the supervisor signs, AT-48).
10. **Scanner (UX-10 skeleton).** `WedgeScannerDecoder` (core) separates fast key bursts ended by Enter/Tab (scan) from slow
    typing (manual), strips configured prefix/suffix, caps length, drops stale partial input. The Scan screen only displays the
    decoded text. Camera scanning and pass validation (GATE-06) are not built.
11. **Kiosk.** The manifest declares `lockTaskMode="if_whitelisted"`, a device-admin receiver and a `KioskController` that calls
    `setLockTaskPackages` + `startLockTask` only when the app is device owner. Provisioning (`dpm set-device-owner`, QR or
    zero-touch) is an installer procedure, outside this slice.
12. **Secrets.** Tokens and the Ed25519 device key (PKCS#8) live in `EncryptedSharedPreferences` under an Android Keystore AES-256
    master key (`androidx.security:security-crypto` 1.1.0-alpha06; Google has deprecated the library, replace with direct
    Keystore + Tink or DataStore encryption before the pilot). Backups and device transfer are excluded.
13. **No ad/analytics SDKs (INV-05).** Dependencies: Kotlin stdlib/coroutines/serialization, AndroidX (Compose, Room,
    WorkManager, Lifecycle, Security). Gradle repositories are limited to Google Maven and Maven Central.
14. **Local persistence.** Room: `outbox_events`, `device_counter`, `local_visits`, `cached_units`; WAL plus
    `PRAGMA synchronous=FULL` set on open (EDGE-01, partial).
15. **Sync is a stub behind an interface.** `SyncApi` has an HTTP implementation for `POST /v1/edge/sync/batches` and
    `SimulatedSyncApi` (acknowledges everything). The build default is the simulation (`-Pdwaar.syncSimulated=false` switches to
    HTTP) and the UI shows "sync SIMULATED". A "synced" state under the simulation proves nothing about the backend.

## Contract used (reconciled with `services/api` as it stood during this slice)

| Call | Route | Status |
|---|---|---|
| OTP request / verify / refresh | `POST /v1/auth/otp/request`, `/otp/verify` (with `device`), `/refresh` | matches identity module |
| Society and role | `GET /v1/me` | matches; guard role picks the society |
| Gates | `GET /v1/societies/{id}/gates` | matches; the guard role may be refused, then reported |
| Units (tower grid) | `GET /v1/societies/{id}/units?limit&cursor` | matches organisation module (masked view for guard) |
| Masked surname | `GET /v1/societies/{id}/units/{unit}/destination-hint` | matches visits module |
| Create request | `POST /v1/approval-requests` + `X-Society-Id` + `Idempotency-Key` | matches visits module (`ApprovalRequestCreate`, strict) |
| Poll request | `GET /v1/approval-requests/{id}?gate_id=` | matches (accepts `id` and `request_id`) |
| Edge sync | `POST /v1/edge/sync/batches` | PRD EDGE-03 only; request/response shape beyond EDGE-03 ASSUMED (slice 3) |

The app does not call `POST /v1/visits/{id}/observations`: physical entry is an outbox event delivered through edge sync.
The visits module expects `device_id` of an enrolled device; the app has no enrolment flow, so its event `device_id` is a local
id and `society_id/gate_id` come from the dev bootstrap (`/v1/me` + `/gates`, only when exactly one active gate is visible).

## Not verified (read before relying on anything above)

- No emulator, instrumented, screenshot or on-device run happened. The UI was compiled and exercised only through Compose-on-
  Robolectric component tests (size floor, wording). Layout, touch, fonts (Devanagari rendering and wrapping), large-font
  behaviour, contrast on a real panel and sunlight legibility are unchecked. UX-03 (screen reader, wrapping) is not verified.
- The app was not run against the live backend or its OTP simulator; HTTP behaviour is verified against a local JDK test server
  that mimics the module's response shapes.
- Kiosk/lock-task, device-owner provisioning, WorkManager scheduling and the Keystore-backed stores were never executed.
- Ed25519 via the Android platform provider (API 33+) was not run on Android; only on the JVM.
- Room encryption at rest and field-level encryption (EDGE-01) are not implemented; WAL/FULL is set but fsync behaviour on
  the real tablet is unmeasured. No outbox pruning, no tombstone handling (EDGE-10).
- No real audio exists; HID scanning was not tried with a scanner; camera scanning, USB/BLE behaviour untested.
- Policy snapshots, policy age (`policyAppliedAtMs` is never set), trusted time and clock uncertainty (a conservative placeholder
  is reported) are not implemented: the banner shows "no policy" until slice 3. Device enrolment, masked calling (GATE-13: the
  call button is disabled), Delivery, Service, Parcels, Inside, Incident, Scan validation (GATE-06) are not built.
- Android 12 and below are unsupported by design (`minSdk 33`). Release build signing and Play/MDM distribution are not set up.
- AT-48 is not met: Marathi strings exist for the shared catalog keys, but the five training scenarios are not implemented
  (only the unannounced-guest rehearsal) and competency recording needs the supervisor flow.

## Blocked requests (catalog is owned elsewhere)

Strings the guest flow needs but the shared catalog lacks, so the UI reuses nearby keys or shows an English `[dev]` note:
`states.visit.cancelled`, `guard.banner.clock_uncertain`, phone-number and OTP-code labels, a visitor-name label, a
"does the surname match" prompt, "not built yet", "practice mode" button label. Audio prompts: none recorded.

## Consequences

Guard logic is testable without a device and byte-compatible with the Python reference. The price is a second implementation of
canonical JSON and signing that must stay in lockstep: the golden-vector test and the CI drift check are the guard rail.
