# ADR-0019: Edge gateway and cloud wired together (slice 3 integration)

- Status: accepted
- Date: 2026-10-06
- Deciders: Viz (owner), build team (slice 3 integration)
- Related: PRD 9.3 (EDGE-01..EDGE-10, authority split, outage runbook), 9.2 (GATE-01/05/06/07/14), 12.1 / 12.3 / 12.4, 13 (workers), 14 (NFR-02/04/09/10),
  16 (AT-01, AT-05..AT-08); INV-01, INV-03, INV-07; ADR-0004, ADR-0013, ADR-0017 (cloud side), ADR-0018 (gateway side);
  contract: `docs/contracts/edge-sync.md`; code: `services/edge/dwaar_edge/{provision,sync,policy_model,gateway,restricted}.py`,
  `services/api/dwaar_api/modules/edge/{sync,routes_device,localdev}.py`, `services/worker/dwaar_worker/`;
  tests: `tests/integration/edge_e2e/`, `tests/acceptance/test_at0{5,6,7,8}_e2e.py`, `tests/integration/edge/test_projection.py`,
  `tests/integration/worker/`, `tests/acceptance/test_at01_cross_society_isolation.py`.

## Context

The cloud half (ADR-0017) was tested only with synthetic signed requests, the gateway half (ADR-0018) only against `FakeCloud`, an in-process fake of the
contract. Nothing had run edge-to-cloud. This slice runs the REAL gateway (`Gateway` + `SyncClient`, SQLite, real signatures) against the REAL FastAPI
application (identity + visits + edge modules, real migrations, RLS and roles, real device authentication) over a **real loopback socket** (uvicorn in
a thread; every test in `tests/integration/edge_e2e/` uses it, so path, query and body bytes are signed and verified exactly as sent), with a real
ephemeral PostgreSQL. Everything is a SIMULATION (one machine, loopback, virtual clock where a test says so); none of it is field evidence.

## What is wired, and how

* **Commissioning is real.** A guard requests the gateway's enrolment with its PUBLIC key, a different supervisor approves it (maker != checker), through
  the real routes. The gateway then signs `GET /v1/edge/keys` with its device key (`python -m dwaar_edge.provision`, `fetch_trust_anchors`) and pins the
  policy issuer keys and the guest-pass verification keys into its configuration (`DWAAR_EDGE_ISSUER_KEYS`, `DWAAR_EDGE_PASS_KEYS`). A snapshot is verified
  against the pinned keys only; a key named by a snapshot is refused (`unknown_issuer`, tested). The installer compares the printed fingerprints out of band
  (otherwise this is trust on first use); a key rotation needs the new key provisioned again. mTLS is still NOT implemented.
* **Time.** `virtual=True` sites share one virtual TRUE clock: the gateway wall clock is a `ManualTime`, the cloud's `utc_now` (edge and visits modules) and
  its HTTP `Date` header follow `start + monotonic elapsed` (never the gateway's stepped wall clock, so AT-08 is faithful). PostgreSQL still stamps
  `clock_timestamp()` with the real clock; where a test depends on such a stamp (`revoked_at`) the harness moves it to virtual time and says so
  (`Site.revoke_pass`). `virtual=False` sites use the machine clock and uvicorn's real `Date` (the 401-with-Date repair test).
* **The WAN** is a switch in front of the real HTTP transport (`WanSwitch`); the server keeps running.

## Mismatches found by running them against each other (what, which side, why)

| # | What mismatched | Side fixed | Why this side |
|---|---|---|---|
| M1 | The gateway verifies guest-pass QR signatures with provisioned pass keys, but `/v1/edge/keys` published only the policy issuer keys: a gateway could not obtain the pass key from the cloud. | Cloud (`/v1/edge/keys` adds `pass_keys`, additive) and gateway (`dwaar_edge.provision` pins both lists) | The key already exists in the cloud; publishing its public half is additive and the gateway must not invent it. |
| M2 | A pass entry observed at the edge (`entity_id` = a gateway-minted movement id, `payload.invitation_id`) was accepted by the cloud as an access event but the cloud never learned the pass was used: `invitations.uses` stayed 0 (the same pass could be redeemed again online), and the visitor never appeared in the unit's visitor history (AT-02). | Cloud (`sync.py`: projection) | The cloud is authoritative for passes and history (PRD 9.3). See decision 1. |
| M3 | The gateway ignored `Retry-After` on 429/503 and backed off blindly (a 60,000-event backlog trips the per-device budget by design). | Gateway (`sync.py`) | The cloud's rate limit is deliberate; the client must honour it. Clamped to one hour so a hostile or broken cloud cannot park the gateway. |
| M4 | The cloud flags an event older than `policy_age_limit` (72 h) at receipt as a `stale` clock and opens a `clock_implausible` exception. A gateway that was offline for slightly more than 72 h (NFR-09 requires buffering that long and more) therefore had its oldest, perfectly honest events flagged. | Cloud (`sync.py`: allowed age = max(limit, time since the device's previous batch)) | The cloud knows how long the device was silent; an age beyond that silence is a wrong clock, an age explained by it is an outage. |
| M5 | A revoked invitation is published with `uses_remaining = 0`. The gateway computed `cloud_used = max_uses - uses_remaining`, so after the revoking snapshot arrived every earlier legitimate entry of a multi-use pass reconciled as `single_use_pass_reused`. | Gateway (`Invitation.cloud_used`: a revoked pass contributes no cloud use count) | "Revoked" is carried by `revoked_version`/the revocation list; changing `uses_remaining` to hide it would lose the cloud's own count. |
| M6 | The cloud stops publishing a pass after its last window; a standalone terminal's entries of that pass, reconciled later, were judged against a guessed limit of one use (`max_uses = 1 if invitation unknown`). | Gateway (`restricted.py`: the terminal's observation carries the `max_uses` it knew; `_consume_pass(max_uses_hint=...)`) | Only the observer knew the limit at the time of the entry. Without a hint the old conservative reading stays. |
| M7 | A device enrolled WITH a gate binding may report only for that gate (`device_wrong_gate`), while the seeded society gateway was bound to one of two gates. | Operational rule + seed (no code change to the cloud rule) | A bound device is stricter by design and an existing test asserts it. A society gateway is enrolled WITHOUT a gate binding (seed and e2e do this); a bound gateway sees the other gates' events quarantined visibly and disposed, never looping (tested). |

Everything else in the contract held first time over the wire: lane directions `in|out|both`, invitation `windows`, date-valued standing rules (`YYYY-MM-DD`),
`suspended` residents, masked aliases, opaque references, the 120 s signature window, 401 with `Date` repaired by one retry, 409 `cursor_ahead_of_cloud` (never a
rollback), 413 for more than 500 events or more than 1 MiB (the gateway sends at most 500 events and 1,000,000 bytes; a gateway misconfigured to send more is repaired
by halving), 2,048-byte event payloads (the gateway caps at 2,000; a 2,000-byte payload is accepted), UTF-8 (Devanagari) text inside signed bodies, duplicate resend with a lost
response, gaps and late fill, quarantined seqs counting as disposed.

## Decisions

1. **Edge-local movements (what the gateway mints) and INV-07.** The gateway mints the id of every movement it records; the cloud has no visit for it, and the
   gateway must not learn cloud visit ids. Per PRD EDGE-07 and INV-07 (observed, authorised, entered are distinct facts; an observation never creates permission):
   * every EntryObserved/ExitObserved is stored as an `access_events` row, accepted or not, never discarded;
   * a **resident** entry decided from the cached policy, an exit of a known movement, and a guard-assisted entry are *recorded*: no visit, no permission, **no
     exception** (they are legitimate and must not read as errors);
   * a **pass** entry the cloud knows and did not revoke before the entry is *projected*: one `visits` row (`state = inside`, `authorisation_source` `invitation`, or
     `supervisor_override`, `authorised_until = entered_at` because the permission was consumed by the entry), one `visit_stops` row, and one use of the pass
     (`invitations.uses + 1`, `consumed` when exhausted), in one transaction with audit and outbox (`VisitEntered`). The visit id is `uuid5(society, movement)`, **not** the
     movement id: a device can neither choose nor probe the primary key of another society's visit, and the exit finds the visit again. The exit then closes it
     (`exited`, basis as observed). An exit that arrived first is recorded as `exit_without_entry` for review and a late entry becomes an `exited` visit (arrival order is not
     observation order);
   * a pass the cloud had already counted out (for example redeemed online meanwhile) still yields its visit (the person is inside) but the cloud never counts beyond
     `max_uses` and a supervisor exception (`unauthorised_entry`, or the `manual_entry` one extended) says so;
   * no matching authorisation, still recorded plus a supervisor exception: unknown pass, revoked-before-entry pass (no visit), a remote decision (`resident_app`, `ivr`)
     that can only be verified against a cloud visit, an override or emergency entry (`manual_entry`, GATE-07), a gateway-flagged conflict;
   * the gateway's own `review` flag is advisory and stays in the stored payload; the cloud raises exceptions for conditions it can judge, so a restart does not flood the
     queue (a device clock that is unknown or implausible raises one `clock_implausible` exception per device and flag).
2. **Retry-After and 5xx.** Backoff stays exponential with full jitter, never earlier than the cloud's `Retry-After` (clamped to 3,600 s).
3. **Outage-aware stale rule** (M4) and **society gateway unbound** (M7), as in the table.
4. **FakeCloud conformance.** `tests/integration/edge_e2e/test_conformance.py` sends the same signed bytes to both clouds. Fixed in the fake: 120 s signature window (was 5 min),
   1 MiB cap (was 1,000,000 B), same-seq-another-event is `quarantined/seq_conflict` (was `duplicate`), payloads above 2,048 B are `quarantined/payload_too_large`, a
   wrong-society event is disposed (no phantom gap), outcomes carry `index` and `seq`. **Documented differences, asserted by the test**: the fake's toy entity state
   machine (an entry for a known entity is `rejected_transition`) versus the real judging of edge-local movements; an exit without an entry; the `recorded_not_projected` reason.
   The fake still has no projection, exceptions, RLS, rate limit or clock flags.
5. **Evidence.** `at(...)` tests parametrised over the `cloud` fixture (`fakecloud` | `realcloud`) record the cloud in `docs/evidence/AT-0N.json` (`environment.clouds`, per-test
   `cloud`), next to `environment.simulation = true`. Tests that name no cloud claim none.
6. **Worker** (PRD 13): `services/worker` now has the policy publisher and the visits expiry/overstay sweep as plain job functions (`jobs.py`), Dramatiq actors (`actors.py`,
   explicit broker: Redis from `DWAAR_REDIS_URL` in `app.py`, `StubBroker` in tests, Redis is never started by a test), a scheduler loop and configuration from the environment.
   The jobs run as `dwaar_worker`, one transaction per society with that society's RLS context. Grants, all additive and column-scoped: `0010` (INSERT on `outbox`, content columns only;
   the society policy applies to the worker too, so a job writes only into the society whose context it set), `0104` (`dwaar_active_society_ids()`, SECURITY DEFINER, worker-only
   EXECUTE, ids only, behind one owner-only policy and a transaction-local flag: the worker still cannot read `societies`), `0206` (UPDATE `invitations(state, version)`), `0314`
   (INSERT `policy_snapshots`, `edge_credential_refs`, `gate_policies` revocation counter). Re-runs are idempotent (tested). Set `DWAAR_EDGE_PUBLISH_ON_POLL=false` once the worker
   publisher runs in a deployment; publish-on-poll stays the default until then.
7. **Seed** `s450_edge` is default ON (`DWAAR_SEED_EDGE=0` turns it off); the gateways are society gateways (no gate binding). `.env.example` documents and `make setup`
   generates the cloud issuer key, reference key, pass key and visitor HMAC key, and the gateway's device, token and field-encryption keys.
8. **AT-01 route inventory.** The new society-scoped routes are probed like every other route (`EDGE_CASES`: non-member, foreign ids replayed in another society, identical to a
   random id, none of A's ids in any answer); the four `/v1/edge/*` device routes are classified as device-signed with their own isolation tests (a device reads only its own
   society, cannot authenticate as another's device, cannot use human routes, cannot write into another society, a revoked device loses access and nothing else).
9. **mypy** resolves one module name per file now that a service imports another (`mypy_path` in `pyproject.toml`).

## Not changed / open

* **Restore from an old backup** can re-issue sequence numbers a gateway already applied: the cloud then answers 409 only if it is *behind*; an equal sequence with different
  content looks "up to date". Restores must be point-in-time (WAL), and the publisher should resume above the highest applied sequence reported by devices (not built).
* The cloud does not push anything to the gateway; revocation latency is the poll interval (default 15 s) plus the publish-on-poll or worker interval (60 s).
* A gateway never refreshes its pinned keys by itself (rotation = re-provision).
* The real-cloud runs use the simulated policy issuer (`SimulatedKmsSigner`) and the simulated identity issuer; there is no KMS/HSM, no mTLS, no real hardware.
