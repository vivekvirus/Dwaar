// Hand-written response shapes the UI relies on. The OpenAPI file types most 200 responses only as `object`; these shapes are
// therefore checked at test time (tests/contract.test.ts, e2e/contract.spec.ts) against JSON Schemas in ./response-schemas.ts
// and against the live API. Request bodies are typed from the generated schema (./schema.d.ts).
import type { components } from "./schema";

export type Schemas = components["schemas"];

export type ApiError = {
  request_id: string;
  code: string;
  message: string;
  message_key: string;
  details: Record<string, unknown>;
};

export type MeRole = {
  role: string;
  source: string;
  unit_id: string | null;
  active: boolean;
  valid_now: boolean;
  not_before: string | null;
  expires_at: string | null;
  requires_mfa: boolean;
  mfa_satisfied: boolean;
};

export type Me = {
  person: { id: string; display_name: string; preferred_language: string; is_minor: boolean };
  simulation: boolean;
  mfa: { enrolled: boolean; confirmed: boolean; session_verified: boolean; required_for_roles: boolean };
  societies: { society_id: string; roles: MeRole[]; memberships: unknown[] }[];
};

export type SocietySummary = { id: string; name: string; city: string; state: string; timezone: string; status: string; version: number };

export type Page<T> = { items: T[]; next_cursor: string | null; request_id?: string };

export type Unit = {
  id: string;
  block_id: string;
  block_name: string;
  label: string;
  floor: number;
  status: string;
  version: number;
  carpet_area_sqft: string | null;
  builtup_area_sqft: string | null;
  undivided_interest_pct: string | null;
  construction_cost_paise: number | null;
};

export type Block = { id: string; name: string; floors: number; has_lift: boolean; status: string; version: number };

export type Gate = { id: string; name: string; kind: string; status: string; version: number };
export type Lane = { id: string; gate_id: string; label: string; direction: string; status: string; version: number };

export type Device = {
  id: string;
  kind: string;
  name: string;
  gate_id: string | null;
  state: string;
  key_id: string;
  firmware: string | null;
  capabilities: Record<string, unknown>;
  simulation: boolean;
  last_seen_at: string | null;
  requested_by: string | null;
  decided_by: string | null;
  decided_at: string | null;
  decision_reason: string | null;
  revoked_at: string | null;
  version: number;
  created_at: string;
};

export type GatePolicy = {
  approval_expiry_seconds: number;
  permission_validity_minutes: number;
  override_validity_minutes: number;
  overstay_minutes: Record<string, number>;
  overstay_bounds: Record<string, { min: number; max: number }>;
  revocation_version: number;
  auto_allow_on_timeout: boolean;
  version: number;
};

export type VisitStop = {
  id: string;
  unit_id: string;
  block_name: string;
  unit_label: string;
  seq: number;
  authorised: boolean;
  state: string;
  approval_request_id: string | null;
};

export type Visit = {
  id: string;
  kind: string;
  state: string;
  visitor_alias: string | null;
  gate_id: string;
  people_count: number;
  authorisation_source: string | null;
  authorised_at: string | null;
  authorised_until: string | null;
  entry_observed: boolean;
  entered_at: string | null;
  exited_at: string | null;
  exit_basis: string | null;
  inside_confidence: string;
  closed_reason: string | null;
  stops: VisitStop[];
  version: number;
  created_at: string;
};

export type ApprovalRequest = {
  id: string;
  status: "pending" | "approved" | "denied" | "expired" | "cancelled";
  version: number;
  visit_id: string;
  unit_id: string;
  block_name: string;
  unit_label: string;
  gate_id: string;
  visitor: { kind: string; alias: string | null; people_count: number; vehicle_plate: string | null };
  expires_at: string;
  expires_in_seconds: number;
  decision: { made: string; by_role: string | null; at: string | null } | null;
  closed_reason: string | null;
  entry_observed: boolean;
  auto_allow_on_timeout: boolean;
  created_at: string;
};

export type GateException = {
  id: string;
  kind: string;
  visit_id: string | null;
  reason: string;
  actor_id: string | null;
  raised_by_system: boolean;
  evidence_ref: string | null;
  entry_happened: boolean;
  state: "open" | "supervisor_review" | "resolved" | "escalated";
  reviewed_by: string | null;
  resolved_by: string | null;
  resolved_at: string | null;
  resolution_note: string | null;
  version: number;
  created_at: string;
};

export type SocietyConfiguration = {
  id: string;
  name: string;
  city: string;
  state: string;
  timezone: string;
  status: string;
  version: number;
  legal_entity: { name: string; entity_type: string; registration_no: string | null; gst_registered: boolean } | null;
  legal_pack: { pack_key: string; version: string; title: string; pack_status: string; approved: boolean; enabled: boolean; jurisdiction: string } | null;
  tax_pack: { pack_key: string; version: string; title: string; pack_status: string; approved: boolean; enabled: boolean } | null;
  binding_governance: { enabled: boolean; blockers: string[] };
  feature_flags: { flag_key: string; enabled: boolean; version: number }[];
};

export type AuthSession = {
  id: string;
  device_id: string;
  device_label: string;
  platform: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  mfa_verified_at: string | null;
  current: boolean;
};

export type ImportReport = {
  dry_run: boolean;
  valid: boolean;
  rows_total: number;
  rows_valid: number;
  units_created: number;
  blocks_created: string[];
  errors: { row: number; field: string; code: string }[];
  errors_total: number;
  errors_truncated: boolean;
};

export type Meta = { service: string; version: string; api_version: string; environment: string; simulation: boolean; server_time: string };
