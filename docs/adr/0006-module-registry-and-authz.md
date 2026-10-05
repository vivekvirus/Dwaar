# ADR-0006: Module registry, authentication and authorisation framework

- Status: accepted
- Date: 2026-10-05
- Deciders: Viz (owner), build team
- Related: PRD INV-01, IAM-03, IAM-08, IAM-13, IAM-14, 12, 12.2; code: `dwaar_api.core.registry`, `authn`, `authz`, `errors`,
  `main.create_app`; tests: `tests/security/test_core_authn.py`, `test_core_authz.py`, `tests/integration/core/test_app_assembly.py`

## Context

Many builders add feature modules in parallel. Adding a module must not edit a shared file, and authorisation must be derived
on the server in one place so it cannot be skipped per endpoint.

## Decision

### Registry

1. A module is a sub-package `dwaar_api/modules/<name>/` exposing any of `router` (an `APIRouter` with full `/v1/...` paths),
   `permissions` (iterable of `Permission`) and `register(app)`. `registry.discover_modules` imports every sub-package (sorted by
   name), `load_modules` collects permissions, includes routers and runs the hooks. Discovery is strict: an import error, a
   module that exposes nothing, or a mistyped attribute stops the app. `create_app(modules_package=...)` lets tests load a
   test-only package (`core_probe` lives only under `tests/`).
2. At assembly every `require(action)` found on any route is checked against the permission registry; an undeclared action is a
   startup error (and denies at runtime if it ever slipped through). Route discovery tolerates both FastAPI router shapes
   (`original_router` wrappers in new versions, flat routes in old ones).
3. `create_app(settings, database=, identity_provider=, session_store=, grant_resolver=, ...)`: explicit arguments override what
   modules register; defaults fail closed (`DenyAllGrantResolver`, no identity provider => every request is 401). A provider
   marked `simulation=True` is refused unless `DWAAR_ENV` is local or test. `uvicorn dwaar_api.main:app` creates the app lazily.

### Authentication (IAM-14)

4. `IdentityProvider.authenticate(token) -> Principal` and `SessionStore.is_active(...)` are protocols; the identity module
   supplies implementations. `OidcIdentityProvider` + `JwtVerifier` use PyJWT with a JWKS source (`RemoteJwks` from the configured URL,
   `StaticJwks` for the simulator/tests). `exp`, `nbf`, `aud`, `iss` and the claims `exp, sub, iss, aud` are enforced; only
   asymmetric algorithms can be configured (`none` and `HS*` cannot); the key is chosen by `kid` and `jku`, `x5u` and embedded
   `jwk` headers are ignored; any verification failure, including key/algorithm mismatches that make the library raise
   `TypeError`, is the same bare 401. A JWKS outage is 503 `dependency_unavailable`, never an open door.
5. A `Principal` carries identity only (subject, person id, session id, times). Roles, society ids and permissions in a token are ignored.

### Authorisation (INV-01, IAM-08)

6. `require(action, society_param=, unit_param=, person_param=)` is a dependency factory returning an `AuthContext`
   (`principal`, derived `Scope`, `permission`, `request_id`, `tx()`). `Permission(action, roles, scope, sensitive)` lives in a
   registry; `ScopeKind` says how broad a grant must be: SOCIETY (society-wide grants only), UNIT (society-wide or on the
   targeted unit), PERSON (society-wide or restricted to that person: self service).
7. A `GrantResolver` (database-backed in the identity module, `InMemoryGrantResolver` for tests) returns the caller's CURRENT
   effective-dated grants on every request; there is no per-token role cache, so revocation is immediate. `sensitive`
   permissions pass `fresh=True` so a resolver may not serve them from cache.
8. The client may name a society (path parameter or `X-Society-Id`) and a target unit/person. These are selectors validated
   against the caller's grants, never trusted: no standing in the named society, an expired or future-dated grant, or a target
   outside the caller's coverage is `404 not_found`, identical for "does not exist" and "not yours". Standing without the right
   role is `403 not_authorised`. A person with several societies and no selector gets 400. A `society_id` in a request body is never read.
9. `AuthContext.tx()` opens the transaction with `RequestContext(society, person, effective role, request id)` (ADR-0004), so
   the database context always equals the derived scope. The society token (`soc_<hash>`) is bound to logs.

### Errors and logging

10. `core.errors` produces the PRD 12.2 body `{request_id, code, message, message_key, details}` for `DwaarError`, request
    validation (field path and error type only, never the submitted value), HTTP errors (404 unknown route is `not_found`; 405
    is `invalid_schema` with status 405 and `Allow`), database errors (SQLSTATE class decides: serialization/lock/connection =>
    503 with `Retry-After`, RLS/privilege refusal => 404, integrity violations => 422 `policy_violation` with a class-only
    reason, data exceptions => 400, anything else => generic 500 `internal_error`) and unhandled exceptions. Driver text, SQL,
    table and constraint names never leave the process; the (scrubbed) cause is logged for operators.
11. The request-id middleware (pure ASGI) sets a UUIDv7 `request_id`, `X-Request-ID`, `Cache-Control: no-store`,
    `X-Content-Type-Options: nosniff`, and writes one structured access line (route template, method, status, latency, error
    code, society token; never path parameters, query strings or bodies) through `dwaar_common.logging`'s scrubbing handler.

## Import convention and the mypy workaround

Inside `dwaar_api` the core modules use **relative imports**. The root mypy config uses `explicit_package_bases` with `files =
["services/*/dwaar_*", ...]`; for `services/api` (a valid dotted name) mypy registers each file as `services.api.dwaar_api...` and
again as `dwaar_api...` through the editable install and aborts with "Source file found twice". Relative imports avoid the second
name. Modules that import `dwaar_api.core...` absolutely need a root fix (`mypy_path = ["services/api"]` in `[tool.mypy]`); that is
recorded as a blocked request for the platform owner. `tools/export_openapi.py` imports the app dynamically for the same reason.

## Consequences

- A new module is one directory; `make api` and the OpenAPI export pick it up automatically.
- Authorisation cannot be skipped by forgetting a check inside a handler as long as the route depends on `require`; a route
  without it is visible in review (and listable through `iter_api_routes`).
- Probes for membership are indistinguishable by status and body, at the cost of 404 where 403 would be friendlier to the member.

## Alternatives considered

- Roles in the JWT (Supabase-style): rejected by PRD IAM-08 (stale claims) and INV-01.
- A central route table listing modules: a shared-file edit per module. Rejected.
- Decorator-based permission checks on handlers: skippable and invisible to the OpenAPI export. Rejected for a dependency.
