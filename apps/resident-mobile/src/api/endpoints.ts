// REQ: GATE-01, GATE-03, PRD 12.1. Typed operations. Request bodies are typed from the GENERATED OpenAPI types
// (src/api/generated/schema.d.ts); response bodies are validated with the zod shapes of domain/types.ts.
import type { components } from "./generated/schema";
import { ApiClient } from "./client";
import {
  ApprovalListSchema,
  ApprovalRequestSchema,
  CanonicalDecisionSchema,
  DevOtpSchema,
  InvitationListSchema,
  InvitationSchema,
  MeSchema,
  MetaSchema,
  OtpRequestResultSchema,
  ProfileUpdateResultSchema,
  RevocationSchema,
  SocietySchema,
  TokenPairSchema,
  UnitSchema,
  VisitHistorySchema,
  type RequestStatus,
} from "../domain/types";

type Schemas = components["schemas"];
// fields with a server-side default are required in the generated (response-mode) types; on the way in they are optional
export type DecisionBody = Omit<Schemas["DecisionIn"], "channel"> & { channel?: "app" };
export type InvitationBody = Omit<Schemas["InvitationCreate"], "kind" | "max_uses" | "people_count" | "with_code"> & {
  kind?: Schemas["InvitationCreate"]["kind"];
  max_uses?: number;
  people_count?: number;
  with_code?: boolean;
};
export type DeviceBody = Omit<Schemas["DeviceIn"], "label"> & { label?: string };
export type ProfileBody = Schemas["ProfileIn"];

/** A decision command is created ONCE per user action; a retry re-sends the same object (same keys, same body). */
export interface DecisionCommand {
  requestId: string;
  societyId: string;
  idempotencyKey: string;
  body: DecisionBody;
}

export function createApi(client: ApiClient) {
  const enc = encodeURIComponent;
  return {
    meta: () => client.request({ path: "/v1/meta", auth: false, schema: MetaSchema }),

    otpRequest: (phone: string) =>
      client.request({
        method: "POST",
        path: "/v1/auth/otp/request",
        auth: false,
        body: { phone } satisfies Schemas["OtpRequestIn"],
        schema: OtpRequestResultSchema,
      }),

    otpVerify: (phone: string, code: string, device: DeviceBody) =>
      client.request({
        method: "POST",
        path: "/v1/auth/otp/verify",
        auth: false,
        body: { phone, code, device }, // validated against OtpVerifyIn by the contract test (device.label has a server default)
        schema: TokenPairSchema,
      }),

    /** Simulator-only helper (404 anywhere else). Never used unless /v1/meta says simulation=true. */
    devOtp: (phone: string) =>
      client.request({ path: "/v1/dev/otp", query: { phone }, auth: false, schema: DevOtpSchema }),

    logout: () => client.request({ method: "POST", path: "/v1/auth/logout", schema: null }),

    me: () => client.request({ path: "/v1/me", schema: MeSchema }),

    updateProfile: (body: ProfileBody) =>
      client.request({ method: "PATCH", path: "/v1/me/profile", body, schema: ProfileUpdateResultSchema }),

    society: (societyId: string) => client.request({ path: `/v1/societies/${enc(societyId)}`, schema: SocietySchema }),

    unit: (societyId: string, unitId: string) =>
      client.request({ path: `/v1/societies/${enc(societyId)}/units/${enc(unitId)}`, schema: UnitSchema }),

    listApprovalRequests: (societyId: string, unitId: string, state: RequestStatus = "pending") =>
      client.request({
        path: `/v1/societies/${enc(societyId)}/approval-requests`,
        query: { unit_id: unitId, state, limit: 20 },
        schema: ApprovalListSchema,
      }),

    getApprovalRequest: (societyId: string, requestId: string) =>
      client.request({ path: `/v1/approval-requests/${enc(requestId)}`, societyId, schema: ApprovalRequestSchema }),

    decide: (cmd: DecisionCommand) =>
      client.request({
        method: "POST",
        path: `/v1/approval-requests/${enc(cmd.requestId)}/decision`,
        societyId: cmd.societyId,
        idempotencyKey: cmd.idempotencyKey,
        body: cmd.body,
        schema: CanonicalDecisionSchema,
      }),

    listInvitations: (societyId: string, unitId: string) =>
      client.request({
        path: `/v1/societies/${enc(societyId)}/invitations`,
        query: { unit_id: unitId, state: "active", limit: 50 },
        schema: InvitationListSchema,
      }),

    getInvitation: (societyId: string, invitationId: string) =>
      client.request({ path: `/v1/societies/${enc(societyId)}/invitations/${enc(invitationId)}`, schema: InvitationSchema }),

    createInvitation: (societyId: string, body: InvitationBody, idempotencyKey: string) =>
      client.request({
        method: "POST",
        path: `/v1/societies/${enc(societyId)}/invitations`,
        idempotencyKey,
        body,
        schema: InvitationSchema,
      }),

    revokeInvitation: (societyId: string, invitationId: string) =>
      client.request({
        method: "DELETE",
        path: `/v1/invitations/${enc(invitationId)}`,
        societyId,
        schema: RevocationSchema,
      }),

    unitVisits: (societyId: string, unitId: string, cursor?: string | null) =>
      client.request({
        path: `/v1/societies/${enc(societyId)}/units/${enc(unitId)}/visits`,
        query: { limit: 20, cursor: cursor ?? undefined },
        schema: VisitHistorySchema,
      }),
  };
}

export type Api = ReturnType<typeof createApi>;
