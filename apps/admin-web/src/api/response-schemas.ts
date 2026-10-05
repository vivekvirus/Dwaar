// JSON Schemas for the API responses this console depends on. The OpenAPI file types most 200 bodies only as `object`, so the
// shapes the UI reads are pinned here and checked (a) against recorded real responses (tests/contract.test.ts) and (b) against
// the live backend (e2e/contract.spec.ts). Error bodies are checked against the OpenAPI ErrorBody schema itself.
const str = { type: "string" } as const;
const strNull = { type: ["string", "null"] } as const;
const int = { type: "integer" } as const;
const bool = { type: "boolean" } as const;
const obj = (properties: Record<string, unknown>, required: string[] = Object.keys(properties)) => ({ type: "object", properties, required });
const page = (item: unknown) => obj({ items: { type: "array", items: item }, next_cursor: strNull }, ["items", "next_cursor"]);

const role = obj({ role: str, active: bool, valid_now: bool, requires_mfa: bool, mfa_satisfied: bool });

export const RESPONSE_SCHEMAS = {
  me: obj({
    person: obj({ id: str, display_name: str, preferred_language: str }, ["id", "display_name", "preferred_language"]),
    simulation: bool,
    mfa: obj({ enrolled: bool, confirmed: bool, session_verified: bool }),
    societies: { type: "array", items: obj({ society_id: str, roles: { type: "array", items: role } }, ["society_id", "roles"]) },
  }),
  societies: page(obj({ id: str, name: str, city: str, status: str }, ["id", "name", "city", "status"])),
  units: page(obj({ id: str, block_id: str, block_name: str, label: str, floor: int, status: str, version: int }, ["id", "block_id", "block_name", "label", "floor", "status", "version"])),
  blocks: page(obj({ id: str, name: str, floors: int, status: str }, ["id", "name", "floors", "status"])),
  gates: obj({ items: { type: "array", items: obj({ id: str, name: str, kind: str, status: str, version: int }) } }, ["items"]),
  lanes: obj({ items: { type: "array", items: obj({ id: str, gate_id: str, label: str, direction: str }, ["id", "gate_id", "label", "direction"]) } }, ["items"]),
  devices: obj({
    items: {
      type: "array",
      items: obj({ id: str, kind: str, name: str, state: str, key_id: str, simulation: bool, version: int }, ["id", "kind", "name", "state", "key_id", "simulation", "version"]),
    },
  }, ["items"]),
  gatePolicy: obj({
    approval_expiry_seconds: int, permission_validity_minutes: int, override_validity_minutes: int,
    overstay_minutes: { type: "object", additionalProperties: int }, overstay_bounds: { type: "object" },
    revocation_version: int, auto_allow_on_timeout: { const: false }, version: int,
  }),
  exceptions: obj({
    items: {
      type: "array",
      items: obj({ id: str, kind: str, reason: str, state: { enum: ["open", "supervisor_review", "resolved", "escalated"] }, version: int, entry_happened: bool, raised_by_system: bool, created_at: str },
        ["id", "kind", "reason", "state", "version", "entry_happened", "raised_by_system", "created_at"]),
    },
  }, ["items"]),
  visits: page(obj({
    id: str, kind: str, state: { enum: ["requested", "authorised", "inside", "exited", "cancelled", "expired"] },
    gate_id: str, entry_observed: bool, inside_confidence: str, stops: { type: "array" }, version: int, created_at: str,
  }, ["id", "kind", "state", "gate_id", "entry_observed", "inside_confidence", "stops", "version", "created_at"])),
  configuration: obj({
    id: str, name: str, city: str, status: str,
    legal_pack: { anyOf: [{ type: "null" }, obj({ pack_key: str, version: str, pack_status: str, approved: bool }, ["pack_key", "version", "pack_status", "approved"])] },
    binding_governance: obj({ enabled: bool, blockers: { type: "array", items: str } }),
    feature_flags: { type: "array" },
  }, ["id", "name", "city", "status", "legal_pack", "binding_governance", "feature_flags"]),
  authSessions: obj({
    sessions: { type: "array", items: obj({ id: str, device_label: str, created_at: str, last_seen_at: str, expires_at: str, current: bool }) },
  }, ["sessions"]),
  importReport: obj({
    dry_run: bool, valid: bool, rows_total: int, rows_valid: int, units_created: int,
    blocks_created: { type: "array", items: str },
    errors: { type: "array", items: obj({ row: int, field: str, code: str }) },
    errors_total: int, errors_truncated: bool,
  }),
  meta: obj({ service: str, version: str, api_version: str, environment: str, simulation: bool }, ["service", "version", "api_version", "environment", "simulation"]),
  approvalRequests: page(obj({ id: str, status: str, version: int, visit_id: str, unit_label: str, block_name: str, auto_allow_on_timeout: { const: false } },
    ["id", "status", "version", "visit_id", "unit_label", "block_name", "auto_allow_on_timeout"])),
} as const;

export type ResponseSchemaName = keyof typeof RESPONSE_SCHEMAS;
