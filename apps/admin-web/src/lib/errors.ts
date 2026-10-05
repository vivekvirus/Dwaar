// REQ: PRD 12.2, IAM (no membership disclosure). Every API error code maps to an i18n key; server `message` text is NEVER shown
// (it is not localised and could carry detail), and not_found / not_authorised for a society never say which one it was.
import type { MessageKey, Params } from "@/i18n";
import { ApiCallError } from "./api-client";

export const CODE_TO_KEY: Record<string, MessageKey> = {
  invalid_schema: "errors.invalid_schema",
  unauthenticated: "errors.unauthenticated",
  not_authorised: "errors.not_authorised",
  not_found: "errors.not_found",
  stale_version: "errors.stale_version",
  duplicate_payload_mismatch: "errors.duplicate_payload_mismatch",
  already_decided: "errors.already_decided",
  request_expired: "errors.request_expired",
  policy_violation: "errors.policy_violation",
  missing_tax_config: "errors.missing_tax_config",
  legal_pack_not_approved: "errors.legal_pack_not_approved",
  rate_limited: "errors.rate_limited",
  dependency_unavailable: "errors.dependency_unavailable",
};

/** details.reason values the console knows how to explain (extra line under the PRD 12.2 message). */
export const KNOWN_REASONS = ["maker_checker", "review_first", "import_validation_failed", "mfa_already_enrolled", "no_society_selected", "csrf"] as const;

export type MappedError = { key: MessageKey; params: Params; requestId: string | null; reasonKey: MessageKey | null };

export function mapError(err: unknown): MappedError {
  if (err instanceof ApiCallError) {
    if (err.societyChanged) return { key: "console.error.society_changed", params: {}, requestId: err.requestId, reasonKey: null };
    const key = CODE_TO_KEY[err.code] ?? "errors.unknown";
    const params: Params = { request_id: err.requestId ?? "-" };
    if (err.code === "rate_limited") params.retry_after_seconds = err.retryAfterSeconds ?? 30;
    const reason = typeof err.details.reason === "string" ? err.details.reason : "";
    const reasonKey = (KNOWN_REASONS as readonly string[]).includes(reason) ? (`console.reason.${reason}` as MessageKey) : null;
    return { key, params, requestId: err.requestId, reasonKey };
  }
  return { key: "errors.unknown", params: { request_id: "-" }, requestId: null, reasonKey: null };
}
