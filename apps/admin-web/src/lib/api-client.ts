// REQ: IAM-09, INV-01. Browser-side calls go ONLY to the same-origin BFF. No token is ever visible here; the CSRF token is the
// non-secret double-submit value; every society call states which society the page believes it is in.
import type { ApiError } from "@/api/types";

export class ApiCallError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly requestId: string | null,
    readonly details: Record<string, unknown>,
    readonly retryAfterSeconds: number | null,
  ) {
    super(code);
  }
  get societyChanged(): boolean {
    return this.code === "stale_version" && this.details.reason === "society_context_changed";
  }
}

export function readCsrfCookie(): string {
  if (typeof document === "undefined") return "";
  const m = document.cookie.split(";").map((s) => s.trim()).find((s) => s.startsWith("dwaar_csrf="));
  return m ? decodeURIComponent(m.slice("dwaar_csrf=".length)) : "";
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export type BffRequest = {
  kind: "society" | "v1";
  path: string;
  method?: "GET" | "POST" | "PUT" | "DELETE";
  query?: Record<string, string | number | boolean | null | undefined>;
  json?: unknown;
  text?: string;
  societyId: string;
  idempotencyKey?: string;
  signal?: AbortSignal;
};

function buildUrl(r: BffRequest): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(r.query ?? {})) if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  const q = qs.toString();
  return `/api/bff/${r.kind}/${r.path.replace(/^\/+/, "")}${q ? `?${q}` : ""}`;
}

export async function bff<T>(r: BffRequest): Promise<T> {
  const method = r.method ?? "GET";
  const headers: Record<string, string> = { accept: "application/json", "x-dwaar-society": r.societyId };
  let body: string | undefined;
  if (method !== "GET") {
    headers["x-csrf-token"] = readCsrfCookie();
    if (r.idempotencyKey) headers["idempotency-key"] = r.idempotencyKey;
    if (r.json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(r.json);
    } else if (r.text !== undefined) {
      headers["content-type"] = "text/csv";
      body = r.text;
    }
  }
  let res: Response;
  try {
    res = await fetch(buildUrl(r), { method, headers, body, credentials: "same-origin", cache: "no-store", signal: r.signal });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiCallError(503, "dependency_unavailable", null, {}, 5);
  }
  if (res.status === 204) return undefined as T;
  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }
  if (res.ok) return parsed as T;
  const err = (parsed ?? {}) as Partial<ApiError>;
  const ra = Number(res.headers.get("retry-after"));
  throw new ApiCallError(res.status, typeof err.code === "string" ? err.code : "unknown", typeof err.request_id === "string" ? err.request_id : null, err.details ?? {}, Number.isFinite(ra) && ra > 0 ? ra : null);
}

/** Auth-flow helper (sign-in and session endpoints are not society-scoped). */
export async function authCall<T>(path: string, init: { method?: "GET" | "POST"; json?: unknown } = {}): Promise<T> {
  const method = init.method ?? "POST";
  const headers: Record<string, string> = { accept: "application/json" };
  if (method !== "GET") headers["x-csrf-token"] = readCsrfCookie();
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: init.json !== undefined ? JSON.stringify(init.json) : undefined, credentials: "same-origin", cache: "no-store" });
  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }
  if (res.ok) return parsed as T;
  const err = (parsed ?? {}) as Partial<ApiError>;
  const ra = Number(res.headers.get("retry-after"));
  throw new ApiCallError(res.status, typeof err.code === "string" ? err.code : "unknown", typeof err.request_id === "string" ? err.request_id : null, err.details ?? {}, Number.isFinite(ra) && ra > 0 ? ra : null);
}
