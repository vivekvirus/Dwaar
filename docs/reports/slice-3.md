# Slice 3 report — edge gateway and cloud wired together (2026-10-06)

Stop-and-report content per PRD §19.6. **Environment for every result below: SIMULATION.** One machine (a 4 vCPU x86_64 VM, not certified gateway hardware), loopback
networking, ephemeral PostgreSQL 16, labelled identity and policy-issuer simulators, a virtual clock where a test says so. **No staging and no field result exists.** The two
halves of slice 3 (cloud `services/api/.../modules/edge`, gateway `services/edge`) had been tested only against each other's fakes; this report is about the first time they ran
against each other for real, and about what that found.

## Measured results (run by the integration agent)
| Check | Result |
|---|---|
| `make lint` (`ruff check`, `ruff format --check`, 365 files) | clean |
| `make typecheck` (mypy strict, 177 source files) | clean (needed `mypy_path`: the worker now imports `dwaar_api`) |
| `make test` (full suite, real PostgreSQL, final run) | **2860 passed, 1 strict xfail** (PostgreSQL own-password limitation, ADR-0004), 0 failed, 21 min 21 s on a 4 vCPU VM |
| `make test` before this slice's fixes (orchestrator baseline) | 2707 passed, 1 xfail, 2 failed (`test_route_inventory`, committed traceability report): both closed |
| `make test` first run of this integration (honest record) | 2854 passed, 6 failed. Four tests encoded the OLD "worker has no INSERT" grants and the reviewed-definer list (`edge/test_schema::test_least_privilege_grants`, `security/test_w1_rls::test_worker_cannot_forge_outbox_events`, `::test_every_security_definer_function_is_locked_down`): updated to the new, still narrow contract (assertions kept and sharpened, nothing deleted); one env-var scan tripped on a literal in my own test (fixed); the traceability guard (regenerated). One timing test (`visits/test_race::test_decisions_racing_the_expiry...`, 40-165 ms windows) failed once on the loaded machine and passed 3 of 3 isolated reruns and the final full run: **a pre-existing timing-sensitive test, not reproduced, not changed** |
| `make acceptance MILESTONE=M1` | **382 passed** (2479 deselected), 3 min 38 s; evidence regenerated: AT-01..AT-08, AT-37 and AT-46 passed, all simulated; AT-05..AT-08 record `environment.clouds = [fakecloud, realcloud]` |
| New tests in this slice | 32 real edge-to-cloud (`tests/integration/edge_e2e`: protocol 18, cross-check 6, conformance 6, performance 2), 30 end-to-end acceptance (AT-05 12, AT-06 6, AT-07 4, AT-08 8 = both clouds), 10 projection (`tests/integration/edge/test_projection.py`), 15 worker (`tests/integration/worker`), 10 worker config, 18 gateway-side fixes, 5 AT-01 device-signed and 9 AT-01 edge-route probes per persona, 2 env, 1 evidence |
| `make trace` (M1 cumulative) | 220 requirements: done 33, partial 42, not-started 145, blocked-external 0, orphans 0; acceptance done 10, not-started 25 (`docs/evidence/_run.json` deleted before generating; the guard test `test_committed_traceability_report_is_current` passes) |
| Processes left behind | none (`pgrep postgres|uvicorn|redis` empty); Redis was never started |

## What was built in this integration
* **Real wiring** (`tests/integration/edge_e2e/`): a commissioned gateway (real enrolment routes, maker != checker approval, device key, issuer and pass keys pinned through a device-signed
  `GET /v1/edge/keys`, `python -m dwaar_edge.provision`) running its real `SyncClient` against the real FastAPI app on a real loopback socket (uvicorn) and a real ephemeral PostgreSQL. Every test in that
  directory crosses a real socket, so signature canonicalisation of path, query and body bytes is proven on the wire (`test_signed_bytes_are_identical_on_both_sides_over_a_real_socket`).
* **Protocol mismatches found and fixed** (full table with the side and the reason in ADR-0019): M1 pass keys not obtainable, M2 pass entries never reached `visits`/`invitations.uses`, M3 `Retry-After`
  ignored, M4 outage-explained events flagged as a stale clock, M5 revoked pass read as fully used, M6 expired pass judged as single-use, M7 gate-bound versus society gateway (rule documented, seed fixed).
* **Edge-local movements (item 1a)**: resident, standing-rule, guard-assisted and emergency entries are recorded without a visit; pass entries are projected (visit inside, one use, audit+outbox);
  unknown/revoked/override/remote entries raise supervisor exceptions and stay recorded; no legitimate resident entry is flagged (B-013).
* **AT-05..AT-08 end to end** (`tests/acceptance/test_at0{5,6,7,8}_e2e.py`): the same scenarios and assertions against `fakecloud` and `realcloud` (REAL-ONLY extras marked); evidence records the cloud and
  `simulation = true`. FakeCloud-versus-real conformance: `test_conformance.py` (fixed in the fake: auth window, caps, seq conflict, payload size, wrong-society disposal; differences listed and asserted).
* **Cross-checks** (`test_cross_check.py`): exactly-once after an outage, restarts, a lost response and a hand-made duplicate resend; revocation reaches the edge and an offline-cached resident is denied after
  the next sync; a policy rollback and six kinds of tampered snapshot are rejected while the old policy keeps serving; a policy older than 72 h forces guard-assisted verification; a clock moved backwards
  disables guest passes and standing-rule allows without locking residents out.
* **Open items closed**: AT-01 route inventory (new society routes probed with foreign ids; device-signed routes have isolation tests: read own society only, cannot impersonate, cannot use human routes, cannot write
  into the other society in either direction, revocation is immediate and local to the device); edge seed default ON (`test_seed_visits` counts justified in B-015); `.env.example` and `make setup` (distinct 32-byte
  keys; a test loads them in the cloud, visits and gateway configs); migrations 0010 (worker outbox INSERT), 0104, 0206, 0314 with tests; `services/worker` publisher and sweep as job functions + Dramatiq actors
  (StubBroker in tests, Redis never started) with idempotent re-run tests; the committed traceability report regenerated.

## Measured numbers (labelled: VM, not certified hardware)
Reused from the edge agent (ADR-0018, `tests/integration/edge_gateway/test_nfr_edge.py`) and measured again through the real wiring (`tests/integration/edge_e2e/test_performance.py`).
| Target | Measured here | How |
|---|---|---|
| NFR-02 decision p95 <= 150 ms, p99 <= 300 ms, 50,000 cached credentials, 20 events/s burst | edge agent: local API over loopback, 600 decisions in 30 bursts of 20: p95 67.1 / 87.1 ms, p99 75.7 / 98.3 ms (two runs); in-process service time p95 0.78 ms; policy apply with 50,000 residents 1.45 s | VM, loopback, loaded shared machine |
| decisions while a REAL upload runs | 2,000 decisions: p50 0.99 ms, **p95 1.92 ms**, p99 2.9 ms (NFR-02 target 150 ms on certified hardware with 50,000 credentials: NOT claimed) | gateway in process, real HTTP upload thread draining a 3,000-event backlog to the real API |
| drain over real HTTP | 3,000 events in 22.2 s = **135 events/s** over real HTTP (batches of up to 500 / 1,000,000 B); zero loss, sequence 1..3000 contiguous in the cloud ledger | the same run; zero loss, contiguous sequence |
| policy of 2,000 residents, publish + download + verify + apply over real HTTP | **1.57 s** for 2,000 residents (50,000: edge-side apply 1.45 s, measured by the edge agent; the cloud-side build of 50,000 is not measured) | real API, real PostgreSQL |
| NFR-04 LAN propagation p95 <= 1 s | edge agent: p95 8.5 / 8.7 ms, p99 9.9 / 11.7 ms (loopback only; says nothing about a real switch) | |
| NFR-09 72 h / 60,000+ events with restarts | edge agent: 0 lost, 0 duplicates, order preserved, restart <= 323 ms, 1.5-1.6 ms per event, database 158 MB (injected clock; close/reopen restarts) | |
| NFR-10 60,000 events reconciled <= 10 min at 5 Mbps | edge agent: **simulation** on a virtual clock: 200.9 s ideal, 268.1 s with 25 % overhead and 200 ms RTT. NOT a measured uplink. Cloud ingest measured separately (ADR-0017): 500-event batch 2.0-4.8 s depending on path (105-250 events/s) | |
| kill -9 recovery | edge agent: 8 subprocess tests, no torn state, every acknowledged event present (a process kill is not a power cut) | |

## Requirement IDs
Statuses are the generated ones (`docs/traceability/TRACEABILITY.md`, M1 cumulative); "done" there means implemented and tested with the acceptance gates tagged, **in simulation**.
* **Done (simulated, now also against the real cloud):** EDGE-02 (event envelope, atomic with projection and outbox), EDGE-03 (batches, per-event outcomes, gaps, backoff with jitter and Retry-After, quarantine that never blocks), EDGE-04 (signed snapshots, pinned
  keys, rollback and tampering rejected), EDGE-05 (stale policy and clock rules; the outage-aware stale flag), EDGE-07 (conflict algorithm; edge-local movements, projection, exceptions), GATE-01 (pass keys provisioned; the signed QR verified on the gateway),
  GATE-05, GATE-06, GATE-07, GATE-11 (sweep as a worker job), GATE-14 (date-valued standing rules over the wire), OBS-02.
* **Partial:** EDGE-01 (WAL/FULL, encryption, backups built; fsync on real hardware NOT verified), EDGE-06 (terminal logic only; no Android UI), EDGE-08 (hardware baseline: not started, blocked-external), EDGE-09 (device signatures only: no mTLS, A/B updates or telemetry),
  EDGE-10 (tombstones before reconcile, in logic; the terminal UI is a later slice), NFR-02, NFR-04, NFR-09, NFR-10 (VM numbers and simulations only), ARCH-04 (worker role holds only narrow, column-scoped rights), DB-02, INV-03, INV-07 (distinct statuses recorded and shown by the cloud; clients not yet wired).
* **Newly evidenced at M1 level (simulated):** AT-05, AT-06, AT-07, AT-08 end to end; AT-01 with the edge routes and the device-signed isolation tests; AT-02 completes further (a pass entry now appears in the household's visitor history).

## AT-05 .. AT-08 evidence status
All four pass as **simulated** evidence, against the in-process FakeCloud AND the real API (loopback, real PostgreSQL), on a virtual clock. `docs/evidence/AT-0{5,6,7,8}.json` record `environment.simulation = true`, `environment.clouds`
(`fakecloud`, `realcloud`) and the cloud per test. They are NOT field evidence: no real power loss, hardware, network or Android terminal took part. AT-01 re-proved with the new routes (M0 evidence regenerated).

## Deviations and decisions
`DECISIONS.md` B-013 (edge-local movements and the projection), B-014 (provisioned trust anchors), B-015 (society gateway, seed default on, count changes), B-016 (Retry-After, revoked and departed passes),
B-017 (outage-aware stale flag), B-018 (worker, grants, society listing, mypy_path), B-019 (evidence says which cloud; virtual clock), B-020 (local edge keys). Deviation from the brief's migration range: the
society listing function is `0104` (it needs `societies`, created in `0102`), not in 0008-0020; 0010 is the outbox grant that was asked for. FakeCloud was changed (it is a test double, not a product file).

## Open issues
* Publish-on-poll is still the default (`DWAAR_EDGE_PUBLISH_ON_POLL=true`): a deployment that runs `make worker` + `make scheduler` should set it to false. A policy poll rebuilds the manifest; at 50,000 credentials that is the wrong place to do it.
* Restoring the database from an old backup can re-issue snapshot sequence numbers a gateway already applied (the gateway detects only a cloud that is *behind*). Restores must be point-in-time; the publisher should resume above the highest applied sequence (not built).
* A key rotation needs every gateway re-provisioned; there is no signed key-rollover message.
* Snapshots grow by one full manifest per change and per 6 h refresh; retention belongs to the privacy slice.
* The cloud does not push; revocation latency is the gateway poll interval plus the publisher interval.
* Cloud `stale`-clock allowance trusts `edge_device_state.last_sync_at`; a device that never synced before has the plain 72 h rule.
* `tests/integration/edge_e2e` shares one process between server and client (threads), and PostgreSQL's own clock is real: scenarios that depend on a database-stamped time move it explicitly (labelled).

## Not verified (precise list)
* **Real power loss and fsync behaviour on real hardware** (EDGE-01, EDGE-08): the store opens with WAL and `synchronous=FULL`, a write+fsync probe measured about 0.4 ms on this VM's virtual disk; that proves nothing about a power cut or a disk that lies about fsync.
* **mTLS with per-device certificates, certificate pinning, TLS at all on the sync path** (EDGE-09): only the Ed25519 request signature authenticates the device; requests can be replayed inside 120 s (harmless: both endpoints are idempotent). A 204 "up to date" answer is not signed.
* **Signed A/B updates with rollback, health telemetry** (EDGE-09) and **TPM / hardware-backed keys** (D-12): keys come from configuration.
* **A real device / real gateway hardware / real network**: nothing ran on one; NFR-02 on certified hardware, NFR-04 on a real switch and NFR-10 on a real 5 Mbps uplink are not measured.
* **Android terminal UI and Room cache**: `StandaloneTerminal` is the specification; the app has never talked to the gateway or the cloud, and AT-07 is logic-level.
* **A real KMS/HSM issuer, a real OIDC issuer**: simulators, labelled.
* **Redis and the Dramatiq worker processes**: the job functions and the actors (StubBroker) are tested; `make worker` against a live Redis was not run in this slice.
* **Concurrency at production scale** (many gateways, many societies) and **multi-gateway failover**.
