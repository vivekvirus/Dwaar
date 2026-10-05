// REQ: PRD 12.2 (every error code mapped to a user-safe i18n message), INV-01 / IAM (no membership disclosure: the UI shows
// our own generic copy keyed by `code`, never server free text, and 403/404 never explain WHY).
import type { TFn } from "../i18n";
import type { ErrorBody } from "../domain/types";
import { CanonicalDecisionSchema, type CanonicalDecision } from "../domain/types";

/** Every code of PRD 12.2. */
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

export function isKnownCode(code: string): code is ErrorCode {
  return (ERROR_CODES as readonly string[]).includes(code);
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: Record<string, unknown>;
  readonly retryAfterSeconds: number | null;

  constructor(
    status: number,
    body: Partial<ErrorBody> & { code: string },
    retryAfterSeconds: number | null = null,
  ) {
    super(`${status} ${body.code}`);
    this.name = "ApiError";
    this.status = status;
    this.code = body.code;
    this.requestId = body.request_id ?? null;
    this.details = body.details ?? {};
    this.retryAfterSeconds = retryAfterSeconds;
  }

  /** The canonical decision carried by 409 already_decided / request_expired / stale_version (PRD 12.3), if valid. */
  get canonical(): CanonicalDecision | null {
    const parsed = CanonicalDecisionSchema.safeParse(this.details["canonical"]);
    return parsed.success ? parsed.data : null;
  }

  get decidedByRole(): string | null {
    const v = this.details["decided_by_role"];
    return typeof v === "string" ? v : null;
  }
}

/** The request never produced an HTTP answer (offline, DNS, CORS, abort). Safe to retry only with the same idempotency key. */
export class NetworkError extends Error {
  constructor(cause?: unknown) {
    super("network_error");
    this.name = "NetworkError";
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

/** The server answered 2xx with a body that does not match the contract: fail closed. */
export class ContractError extends Error {
  constructor(
    readonly path: string,
    readonly issues: string,
  ) {
    super(`contract_violation ${path}`);
    this.name = "ContractError";
  }
}

export function isApiError(e: unknown, code?: ErrorCode): e is ApiError {
  return e instanceof ApiError && (code === undefined || e.code === code);
}

/** i18n message for any thrown value. Unknown codes fall back to errors.unknown with the request id for support. */
export function errorMessage(err: unknown, t: TFn): string {
  if (err instanceof NetworkError) return t("app.errors.network");
  if (err instanceof ApiError) {
    const id = err.requestId ?? "-";
    if (!isKnownCode(err.code)) return t("errors.unknown", { request_id: id });
    switch (err.code) {
      case "rate_limited":
        return t("errors.rate_limited", { retry_after_seconds: err.retryAfterSeconds ?? 30 });
      case "invalid_schema":
        return t("errors.invalid_schema");
      case "unauthenticated":
        return t("errors.unauthenticated");
      case "not_authorised":
        return t("errors.not_authorised");
      case "not_found":
        return t("errors.not_found");
      case "stale_version":
        return t("errors.stale_version");
      case "duplicate_payload_mismatch":
        return t("errors.duplicate_payload_mismatch");
      case "already_decided":
        return t("errors.already_decided");
      case "request_expired":
        return t("errors.request_expired");
      case "policy_violation":
        return t("errors.policy_violation");
      case "missing_tax_config":
        return t("errors.missing_tax_config");
      case "legal_pack_not_approved":
        return t("errors.legal_pack_not_approved");
      case "dependency_unavailable":
        return t("errors.dependency_unavailable");
    }
  }
  return t("errors.unknown", { request_id: "-" });
}

/** Request id to show under an error for support, if the server gave one. */
export function errorRequestId(err: unknown): string | null {
  return err instanceof ApiError ? err.requestId : null;
}
