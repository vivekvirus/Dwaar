// Runtime-validated shapes of the API responses this app uses. The OpenAPI file types request bodies and the error body but
// leaves most 2xx bodies as free-form objects, so every response is parsed with zod at the boundary (fail closed: an
// unexpected shape is an error, never a silently wrong screen). REQ: INV-07 (truthful state), INV-01.
import { z } from "zod";

export const TokenPairSchema = z.object({
  token_type: z.string(),
  access_token: z.string().min(10),
  refresh_token: z.string().min(10),
  expires_in: z.number().int().positive(),
  session_id: z.string(),
  simulation: z.boolean(),
});
export type TokenPair = z.infer<typeof TokenPairSchema>;

export const MetaSchema = z.object({
  environment: z.string(),
  simulation: z.boolean(),
  server_time: z.string(),
});
export type Meta = z.infer<typeof MetaSchema>;

export const OtpRequestResultSchema = z.object({
  status: z.string(),
  expires_in_seconds: z.number(),
  resend_after_seconds: z.number().optional(),
  simulation: z.boolean().optional(),
});

export const DevOtpSchema = z.object({ otp: z.string().regex(/^\d{6}$/), simulation: z.boolean() });

const RoleSchema = z.object({
  role: z.string(),
  source: z.string().optional(),
  unit_id: z.string().nullable(),
  active: z.boolean(),
  valid_now: z.boolean(),
  expires_at: z.string().nullable().optional(),
});
export const MeSchema = z.object({
  person: z.object({
    id: z.string(),
    display_name: z.string().nullable(),
    preferred_language: z.string().nullable(),
    is_minor: z.boolean().optional(),
  }),
  simulation: z.boolean(),
  societies: z.array(z.object({ society_id: z.string(), roles: z.array(RoleSchema) })),
});
export type Me = z.infer<typeof MeSchema>;

export const SocietySchema = z.object({
  id: z.string(),
  name: z.string(),
  city: z.string().nullish(),
  status: z.string().optional(),
});
export type Society = z.infer<typeof SocietySchema>;

export const UnitSchema = z.object({
  id: z.string(),
  block_name: z.string().nullish(),
  label: z.string(),
});
export type Unit = z.infer<typeof UnitSchema>;

export const REQUEST_STATUSES = ["pending", "approved", "denied", "expired", "cancelled"] as const;
export type RequestStatus = (typeof REQUEST_STATUSES)[number];

export const ApprovalRequestSchema = z.object({
  id: z.string(),
  status: z.enum(REQUEST_STATUSES),
  version: z.number().int(),
  visit_id: z.string().nullish(),
  unit_id: z.string(),
  block_name: z.string().nullish(),
  unit_label: z.string(),
  gate_id: z.string().nullish(),
  visitor: z.object({
    kind: z.string(),
    alias: z.string().nullish(),
    people_count: z.number().int(),
    vehicle_plate: z.string().nullish(),
  }),
  expires_at: z.string(),
  expires_in_seconds: z.number(),
  decision: z.object({ made: z.string().nullish(), by_role: z.string().nullish(), at: z.string().nullish() }).nullable(),
  decision_id: z.string().nullish(),
  permission_expires_at: z.string().nullish(),
  closed_reason: z.string().nullish(),
  entry_observed: z.boolean(),
  auto_allow_on_timeout: z.boolean().optional(),
  guard_options: z.array(z.unknown()).optional(),
  created_at: z.string(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

export const ApprovalListSchema = z.object({
  items: z.array(ApprovalRequestSchema),
  next_cursor: z.string().nullish(),
});

/** PRD 12.3 canonical response of a decision (also `details.canonical` of a 409). */
export const CanonicalDecisionSchema = z.object({
  request_id: z.string(),
  status: z.enum(REQUEST_STATUSES),
  version: z.number().int(),
  decision_id: z.string().nullish(),
  permission_expires_at: z.string().nullish(),
  entry_observed: z.boolean(),
});
export type CanonicalDecision = z.infer<typeof CanonicalDecisionSchema>;

export const INVITATION_STATES = ["draft", "active", "consumed", "expired", "revoked"] as const;
export const InvitationSchema = z.object({
  id: z.string(),
  unit_id: z.string(),
  kind: z.string(),
  purpose: z.string(),
  visitor_alias: z.string().nullish(),
  people_count: z.number().int(),
  windows: z.array(z.object({ start: z.string(), end: z.string() })),
  window_start: z.string(),
  window_end: z.string(),
  max_uses: z.number().int(),
  uses: z.number().int(),
  vehicle_plate: z.string().nullish(),
  state: z.enum(INVITATION_STATES),
  has_code: z.boolean(),
  version: z.number().int(),
  qr: z.string().optional(),
  code: z.string().nullish(),
});
export type Invitation = z.infer<typeof InvitationSchema>;
export const InvitationListSchema = z.object({ items: z.array(InvitationSchema) });

export const RevocationSchema = z.object({
  invitation_id: z.string(),
  state: z.string(),
  revoked_version: z.number().int().nullish(),
  version: z.number().int(),
  already_revoked: z.boolean().optional(),
  cancelled_visits: z.number().int().optional(),
});
export type Revocation = z.infer<typeof RevocationSchema>;

export const VISIT_STATES = ["requested", "authorised", "inside", "exited", "cancelled", "expired"] as const;
export const VisitSchema = z.object({
  id: z.string(),
  kind: z.string(),
  state: z.enum(VISIT_STATES),
  visitor_alias: z.string().nullish(),
  people_count: z.number().int(),
  vehicle_plate: z.string().nullish(),
  authorised_at: z.string().nullish(),
  authorised_until: z.string().nullish(),
  entry_observed: z.boolean(),
  entered_at: z.string().nullish(),
  exited_at: z.string().nullish(),
  closed_reason: z.string().nullish(),
  created_at: z.string(),
});
export type Visit = z.infer<typeof VisitSchema>;
export const VisitHistorySchema = z.object({
  items: z.array(VisitSchema),
  next_cursor: z.string().nullish(),
});

export const ErrorBodySchema = z.object({
  request_id: z.string(),
  code: z.string(),
  message: z.string(),
  message_key: z.string().optional(),
  details: z.record(z.unknown()).optional(),
});
export type ErrorBody = z.infer<typeof ErrorBodySchema>;

export const ProfileUpdateResultSchema = z.object({ updated: z.boolean() });
