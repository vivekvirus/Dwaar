# ADR-0005: Audit log, transactional outbox and idempotency keys

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team
- Related: PRD 7.4, 12 (idempotency), 12.2, 12.4, DB-02, INV-02; code: `dwaar_api.core.audit`, `dwaar_api.core.idempotency`,
  `dwaar_api.core.ratelimit`, migrations 0004-0007; tests: `tests/integration/core/test_audit_outbox.py`, `test_idempotency.py`

## Context

PRD 12.4 requires domain mutation, audit row and outbox row in one transaction, with masked before/after diffs. PRD 12
requires `Idempotency-Key` bound to actor, society, endpoint and request hash. Both must be hard to bypass for module authors.

## Decision

### Audit and outbox

1. `audit_log` (append-only, DB-02): `id, society_id (nullable, see ADR-0004), actor_id, effective_role, operation, object_type,
   object_id, object_version, diff_masked jsonb, reason, approver_id, request_id, at`. The PRD column is `approver_id`; the
   task text said `approver_ref`; the PRD wins.
2. `outbox` carries the PRD 12.4 contract (`event_id, schema_version, society_id, aggregate_type/id/version, event_type,
   occurred_at, actor_ref, correlation_id, causation_id, payload`) plus `payload_hash` (canonical JSON, `dwaar_common.events`)
   and delivery state (`published_at, attempts, next_attempt_at, last_error`). Content is immutable (trigger); the worker may
   update delivery fields only (column grant); nothing deletes except the owner purge path. The relay claims with
   `FOR UPDATE SKIP LOCKED` over the partial index `outbox_claim_idx (next_attempt_at, event_id) WHERE published_at IS NULL`.
   Delivery is at least once, ordering only per aggregate version, consumers deduplicate on `event_id`.
3. `mutation(conn, ctx, operation, object_type, event_type, apply=...)` runs the domain function, `record_audit` and `emit_event`
   inside one SAVEPOINT on the caller's connection. A failure in any of the three rolls back all three and re-raises, even when
   the caller swallows the exception. The domain function returns `MutationResult` (object id, version, before/after, minimal
   event payload). Event payloads reject floats (INV-02).
4. `masked_diff` lists changed fields only (data minimisation) and masks sensitive values by name (phone, otp, aadhaar, bank,
   token, secret, password, anything ending `_enc`, `_vault`, `_hash`, `_token`, ...) and by pattern in free text. That a
   sensitive field changed stays visible; its values never do. Callers can add `redact=[...]`.
   Fix round 1 (B-009): masking also covers identity fields by key (email, pan, upi/vpa, ifsc, gstin, dob, address, plate,
   person-name compounds), numbers under innocuous keys, nested lists, `record_audit(diff=...)` and outbox event payloads
   (masked with a warning that names paths only). `audit_log.at` and the outbox delivery columns are server-set: the runtime
   roles have column-scoped INSERT grants (migration 0008). Both tables carry `retention_class` (a retention-pack class code,
   default `LOG`) and `legal_hold_id` (set by privacy tooling only).
5. `request_id` is a UUID: an inbound `X-Request-ID` is honoured only if it parses as one.

### Idempotency

6. `idempotency_required` is a FastAPI dependency (header documented in OpenAPI, required). `IdempotentCall.run(auth, work)` is
   the single entry point for idempotent endpoints. The key claim (`INSERT ... ON CONFLICT (society_id, actor_id, key) DO
   NOTHING`), the domain work and the stored response are **one transaction**.
   - A crash or error before commit leaves no key behind; the client retries with the same key.
   - Concurrent identical requests serialise on the unique index: the second blocks, then replays the stored response. No
     polling, no stuck "in progress" row (`in_progress` exists only inside the owning transaction).
   - Same key with another payload or endpoint under the same (society, actor) gets 409 `duplicate_payload_mismatch`.
     The hash covers method, path, sorted query and canonical JSON body (key order and whitespace are irrelevant).
   - A replay returns the stored status and body plus `Idempotent-Replayed: true`; the transport `X-Request-ID` is the new request's.
   - Failed requests (4xx/5xx) are not stored. Retention is at least `idempotency_ttl_seconds` (default 7 days, longer than the
     72 h offline buffer) and until the worker deletes the expired row (the worker deletes expired rows only). All expiry
     decisions use the database clock inside SQL and the claim loop is bounded (no recursion under clock skew). A retry with
     the SAME key and payload replays the stored response even after `expires_at` while the row exists; only a different
     payload may reclaim an expired key. Responses encode `Decimal` as strings and refuse floats.
   - A request body above `max_request_body_bytes` (default 1 MiB) is answered 413 before it is buffered or hashed.
7. Rate limiting: `dwaar_rate_limit_take(key, capacity, refill_per_second, cost)` is a Postgres token bucket (row lock per
   key, denied attempts burn nothing). `dwaar_api.core.ratelimit.enforce` raises 429 `rate_limited` with `Retry-After`
   and runs in its own short transaction so a denied attempt is recorded even if the request later fails. Keys are opaque
   (never raw phone numbers).

## Consequences

- Module authors cannot forget the audit/outbox rows if they use `mutation()`; a missing `Idempotency-Key` is a 400 before any work.
- The stored response may contain personal data; the retention window and RLS bound the exposure, and responses should stay minimal.
- Money-moving endpoints must additionally rely on their own business keys (INV-02, billing keys, e.g. `client_action_id` per
  aggregate); the HTTP key only protects against client retries and cannot cover a retry older than the retention window.
- `audit_log` and `outbox` grow without bound until the privacy/retention engine (0700+) partitions or purges them through the owner path.

## Alternatives considered

- Claiming the key in a separate committed transaction and polling for completion: simpler to wrap as middleware, but leaves
  stuck claims after crashes and needs a lease/timeout invented by us. Rejected.
- Middleware capturing the response body: cannot make the stored response atomic with the domain change. Rejected.
- Application-level audit through ORM events: invisible to raw SQL writes and easy to skip. Rejected for an explicit helper plus tests.

## Fix round 2 additions (B-010)

- **Masking never decides money by digit count.** Numbers are masked by key (identifier-like names) only; any other number and any
  decimal string with a point survives, so `payload_hash` is computed over the real amount. Digit-only strings under non-quantity
  keys are still scrubbed.
- **One event per aggregate version** (`outbox_aggregate_version_uq`): PRD 12.4 orders events only per aggregate version.
- **A replay answers with the replaying request's id.** A `request_id` member inside a stored response body is refreshed to the
  current request; the original id is returned in `Idempotent-Original-Request-Id`. The request hash keeps the order of repeated
  query parameters (`?x=1&x=2` differs from `?x=2&x=1`) and sorts only by name.
- **Bad input is a 400.** A lone surrogate in an audited or evented value and a NUL byte in a text field are `invalid_schema`.
