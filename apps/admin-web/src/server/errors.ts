// REQ: PRD 12.2 (every error: request_id, stable code, user-safe message, details). BFF-originated errors reuse the API codes;
// they never reveal whether a person is a member (a society outside the session answers like an unknown one).
export const ERROR_CODES = [
  "invalid_schema",
  "unauthenticated",
  "not_authorised",
  "not_found",
  "stale_version",
  "duplicate_payload_mismatch",
  "already_decided",
  "request_expired",
  "policy_violation",
  "missing_tax_config",
  "legal_pack_not_approved",
  "rate_limited",
  "dependency_unavailable",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

const STATUS: Record<ErrorCode, number> = {
  invalid_schema: 400,
  unauthenticated: 401,
  not_authorised: 403,
  not_found: 404,
  stale_version: 409,
  duplicate_payload_mismatch: 409,
  already_decided: 409,
  request_expired: 409,
  policy_violation: 422,
  missing_tax_config: 422,
  legal_pack_not_approved: 422,
  rate_limited: 429,
  dependency_unavailable: 503,
};

export function newRequestId(): string {
  return crypto.randomUUID();
}

export function errorBody(code: ErrorCode, details: Record<string, unknown> = {}, requestId = newRequestId()) {
  return { request_id: requestId, code, message: code, message_key: `errors.${code}`, details };
}

export function errorResponse(code: ErrorCode, details: Record<string, unknown> = {}, extra?: HeadersInit): Response {
  return Response.json(errorBody(code, details), { status: STATUS[code], headers: { "cache-control": "no-store", ...extra } });
}
