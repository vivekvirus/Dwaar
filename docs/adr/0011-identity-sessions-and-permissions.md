# ADR-0011: Identity, sessions, memberships and the permission matrix

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team (slice 1: identity and permissions)
- Related: PRD IAM-01..IAM-14, ARCH-02, INV-01, INV-04, PRD 5.1/5.2/12.1; ADR-0004 (RLS), ADR-0005 (audit/outbox),
  ADR-0006 (registry/authz); code: `dwaar_api.modules.identity`, migrations `0130`-`0135`, `0190`;
  tests: `tests/integration/identity/`, `tests/security/test_identity_*.py`

## Context

The core (ADR-0004/0006) fixed the contracts: a restricted DB role, society context per transaction, `IdentityProvider`,
`SessionStore`, `GrantResolver`, a `Permission` registry. This slice supplies the concrete, database-backed
implementations and the identity data model. Three constraints shape it: persons are GLOBAL (one person, many
societies) so they cannot carry `society_id` + RLS; every society table is FORCE-RLS on `app.society_id` so "which
societies am I in?" cannot be asked of the tables themselves; and no role claim in a token may ever matter.

## Decisions

### 1. Schema `iam` for global data; the runtime roles hold no table privilege there

`iam.persons`, `iam.person_vault`, `iam.otp_challenges`, `iam.otp_deliveries`, `iam.auth_sessions`, `iam.refresh_tokens`,
`iam.mfa_factors` and `iam.person_access_index` are reachable only through reviewed `SECURITY DEFINER` functions
(`iam.*`, pinned `search_path`, `REVOKE ... FROM PUBLIC`). Each function gates itself on `app.person_id` /
`app.society_id` (set only by the authorisation layer) or on a proof. Examples: `iam.session_create` needs a login OTP
challenge consumed in the last two minutes for THAT person's number; `iam.vault_get` returns CIPHERTEXT only to the
person themself or to a secretary acting in a society where that person has a membership or grant.

Why a separate schema rather than public tables with grants: the core catalog guard
(`find_rls_violations`) is deny-by-default for any reachable table without `society_id` (it would need an allowlist entry
per table), and the core "reviewed definers" test scans schema `public` only. Keeping the identity internals in `iam`
leaves both guards green WITHOUT editing core tests, and `tests/security/test_identity_database.py` repeats the review
for `iam`: the exact set of runtime-executable definers is pinned; trigger and helper functions are owner-only; no
runtime role has any privilege on any `iam` table; the global catalog guard still passes. If the core guards later grow
an allowlist, the `iam` tables can move to `public` without touching callers (`store.py` is the only SQL surface).

### 2. The access index (how grants cross societies)

Row triggers on `memberships` and `role_grants` (SECURITY DEFINER, not executable by runtime roles) maintain
`iam.person_access_index` in the SAME transaction as the change: person, society, unit, role, effective flag, validity
window, MFA-relevant role. `PgGrantResolver` reads only that index, for the context person, on EVERY call (no cache), so
"sensitive actions re-check the CURRENT role" is true for all actions, not only `sensitive=True` ones. A membership's
effective role comes from `iam.membership_role(kind, lives_in_unit)`: ownership and occupancy are separate columns
(`kind`, `lives_in_unit`, `billing_liable`, `voting_entitled`) so an owner who does not live in the unit is
`owner_nr` (INV-04); identity only RECORDS liability and entitlement, finance and governance own them.

Verified and disputed memberships carry grants; pending, rejected and reverification ones do not. A dispute therefore
never removes occupancy (IAM-05). A membership ended by an explicit decision gets `ended_at` (instant) next to
`effective_to` (inclusive calendar date shown to people), so a deactivation takes effect immediately.

### 3. Authentication

* `POST /v1/auth/otp/request|verify`: OTP hashed with a purpose-separated HMAC over (phone token, challenge id, code); six
  digits; five attempts; five minutes; superseded by a newer request; consumed exactly once (`iam.otp_consume`). Every
  failure is the same bare 401. A valid number gets the same 202 body whether or not it is known; rate limits (per
  number and per IP, core `rate_limit_buckets`) use keyed-hash keys, never raw numbers.
* Delivery: the core outbox is society-owned and an OTP request has no society, so delivery uses `iam.otp_deliveries`
  with an envelope-ENCRYPTED payload (recipient, DLT template id, parameters, code), AAD bound to the delivery id,
  cleared on consume/supersede/expiry. The labelled simulator marks it `simulated_sent`; in local/test ONLY, the dev
  endpoint `GET /v1/dev/otp` returns the code. Outside local/test no such endpoint exists, deliveries stay `pending`
  and the real SMS gateway (needs a DLT principal entity and approved template ids) is **blocked-external**.
* Tokens: PyJWT, Ed25519 (`EdDSA`), claims `sub iss aud exp iat jti sid` (+ `simulation`), 15 minutes by default. The
  simulator serves OIDC discovery and a JWKS and is verified through the SAME core `JwtVerifier`/`OidcIdentityProvider`
  as a real IdP. It is installed only when simulators are allowed AND no real issuer is configured. Production
  token minting through a real IdP's token endpoint is blocked-external: without a token issuer `/otp/verify` answers
  503 rather than minting its own format.
* Sessions: `PgSessionStore.is_active` is a row lookup on every request, so revocation is immediate and independent of
  `exp`. Refresh tokens are opaque 48-byte random values stored only as keyed hashes, single-use, rotated; presenting a
  used or revoked one revokes the whole session and writes an audit row. Bounded device list (20), absolute session
  expiry, per-person list/revoke endpoints that answer 404 for someone else's session.
* A token whose `sid` has no live session is refused even if validly signed: externally issued tokens (real OIDC) work
  the same way (`sub` = person id, `sid` = session id).

### 4. MFA and elevated roles

Elevated roles (`secretary treasurer committee estate_mgr guard_sup auditor org_admin plat_support`; SQL
`iam.is_elevated_role` and `matrix.ELEVATED_ROLES` are compared by a test) need a fresh TOTP step-up in THE SESSION
(`pyotp`, RFC 6238, +-1 step window, a step is accepted once, secret encrypted at rest, 5 attempts per 5 minutes, 8 hours
validity by default). Enforcement without changing the core: when the session has no fresh step-up the resolver returns an
elevated grant under the role name `<role>_mfa_pending`, which no permission lists, so `decide()` answers 403; `/v1/me`
reports `requires_mfa` / `mfa_satisfied`. Expiry or revocation of the person's last elevated grant revokes their
MFA-elevated sessions (`iam.sweep_person`, run on every session check and by the worker through
`iam.sweep_expired_grants`), which is what IAM-02 means by "expiry revokes open sessions for that privilege".
`makerchecker.require_distinct` is the reusable maker != checker helper; database CHECKs back it
(`role_grants_no_self_grant`, `role_grants_support_approval`, `membership_holds_decider_differs`, the appeal guard trigger).

### 5. Memberships, cases, holds, disputes, number changes

* Every membership starts `pending` with a case in `requested`; the only writers of effective state are reviewer
  decisions. Applicants act only for themselves, cannot be staff, cannot verify their own claim, and a requester can never
  be the reviewer. Ownership and staff claims are decided by a society-wide reviewer (secretary); tenant and household
  claims also by the owner of THAT unit.
* IAM-07 states are pure data (`states.py`). An appeal opens a NEW case in `appealed` (the rejected one stays rejected,
  one appeal per rejection) and is decided by someone other than the original decider (service check plus DB trigger).
  Reasons are stored on the case and shown to the applicant in `/v1/me`.
* IAM-12: `POST /v1/memberships/{id}/owner-confirm` finds the membership's society via the index, then proves the caller
  currently holds an owner grant on that unit; anyone else gets the same 404 as for an unknown id. Verifying a tenant needs
  `owner_decision = confirmed`; the only way around is a reasoned waiver, refused while the unit has an effective owner. A
  committee hold needs a 10+ character reason, is visible to owner and tenant, can be appealed, is decided by someone other
  than the placer, applies only to onboarding (never to a verified or disputed occupant) and keeps blocking when upheld.
* IAM-05: an owner or secretary can raise a dispute; a verified membership becomes `disputed` and keeps its grants; a
  dispute case ends only through an explicit reviewer decision (`verify` = tenancy stands; `deactivate` with a reason =
  occupancy ends). No timer and no other code path ends occupancy.
* IAM-11: a login on a number whose holder was dormant for `DWAAR_PHONE_DORMANCY_DAYS` (default 90) releases the old
  person's number (their memberships stay with them, sessions revoked) and creates a NEW person for the new holder with
  nothing. A voluntary number change needs an OTP to the new number, swaps the token and ciphertext, revokes ALL sessions
  and moves verified memberships to `reverification` with a case, in one transaction. Account recovery for the old person
  (IAM-09) is not part of this slice.

### 6. Permission matrix

`matrix.py` holds PRD 5.2 cell-for-cell (strings as printed) and generates `matrix.<capability>.<verb>` permissions
(`read manage read_masked read_own approve approve_own make check create draft vote`); identity adds `iam.*` permissions.
Correction (orchestrator, 2026-10-05): the Unit-and-member-register row prints ten values (F R R R Masked R O O O O). GUARD is
`Masked` and AUDITOR is `R`; a plain-text PDF extraction merges them into "Masked R", which was first misread as nine values
with AUDITOR empty. AUDITOR therefore has register read (purpose logged, IAM-04), consistent with the organisation module.

### 7. Role grants (IAM-02, IAM-03, IAM-13)

`POST /v1/societies/{id}/role-grants` is the ONLY writer of `role_grants`: secretary permission + MFA, reason mandatory (10+
for elevated roles), never to oneself, never `org_admin`/`plat_support` (platform roles are issued out of band), expiry
mandatory for auditor/vendor_tech/plat_support and at most 366 days, a person id is accepted only for someone who already
has a relationship with the society (a phone number introduces a new person without saying whether they existed),
`Idempotency-Key` required. Grants are immutable except revocation.

## Configuration (all optional in local/test; the three keys are mandatory elsewhere)

`DWAAR_PII_KEYS` (`id=base64url,...`), `DWAAR_PII_ACTIVE_KEY_ID`, `DWAAR_PHONE_HMAC_KEY` (base64url 32 bytes),
`DWAAR_SIM_ISSUER_KEY` (base64 PEM Ed25519; otherwise ephemeral per process), `DWAAR_SIM_ISSUER`,
`DWAAR_OTP_TTL_SECONDS` (300), `DWAAR_OTP_MAX_ATTEMPTS` (5), `DWAAR_OTP_DLT_TEMPLATE_ID`, `DWAAR_ACCESS_TOKEN_TTL_SECONDS`
(900), `DWAAR_REFRESH_TOKEN_TTL_SECONDS` (30 d), `DWAAR_MFA_TTL_SECONDS` (8 h), `DWAAR_PHONE_DORMANCY_DAYS` (90).
`.env.example` belongs to the platform step; these still need a block there.

## Accepted risks and limits

* A SQL-injection foothold running as `dwaar_app` can call the reviewed functions and set the context GUCs (ADR-0004
  accepted risk). The functions narrow what that buys: no direct table access, ciphertext only, proof-gated session
  creation, person-scoped reads.
* Any single-process in-memory element (the simulator key) is per process; multi-worker local runs should set
  `DWAAR_SIM_ISSUER_KEY`.
* The MFA-pending trick returns 403 `not_authorised` (not a dedicated `mfa_required` code): PRD 12.2 has no such code.
* Not in this slice: IAM-09 step-up for bank/legal-hold/bulk export (the TOTP step-up and `mfa_verified_at` are the
  building blocks), IAM-10 offline guard login, web cookies/CSRF (IAM-08, web clients), push-token revocation (IAM-11:
  sessions are revoked, there is no push token store yet), real SMS and IdP integrations (blocked-external).

## Alternatives considered

* Direct grants on global tables plus an allowlist in the core catalog guard: rejected here because it needs edits to
  another area's tests; the `iam` schema keeps the same security properties with no cross-area edit.
* A grant cache with a TTL: rejected; the index lookup is one indexed query and IAM-08 asks for current state.
* Putting roles in the JWT: forbidden by IAM-08/IAM-13 and BUILD_BRIEF.
