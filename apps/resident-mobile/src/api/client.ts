// REQ: PRD 12 / 12.2. One place that talks HTTP: bearer auth with a single refresh-and-retry on 401, the Idempotency-Key
// header, the X-Society-Id header for society-less routes, error mapping, response validation (zod) and safe retries.
import type { ZodType } from "zod";
import { SessionManager } from "../auth/session";
import { ErrorBodySchema } from "../domain/types";
import { ApiError, ContractError, NetworkError } from "./errors";

export interface RequestOptions<T> {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  query?: Record<string, string | number | undefined | null>;
  body?: unknown;
  /** Set for approvals, command creation and any financial write; a retry MUST pass the same value. */
  idempotencyKey?: string;
  /** X-Society-Id, for routes whose path carries no society (approval-requests/{id}, DELETE /invitations/{id}). */
  societyId?: string;
  /** false for sign-in endpoints. Default true. */
  auth?: boolean;
  schema: ZodType<T> | null;
  /** Extra attempts after a NetworkError or 503, only honoured when an idempotencyKey is set (or the call is a GET). */
  retries?: number;
  signal?: AbortSignal;
}

export interface ApiClientDeps {
  baseUrl: string;
  session: SessionManager;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

export class ApiClient {
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  constructor(private readonly deps: ApiClientDeps) {
    this.fetchImpl = deps.fetchImpl ?? ((...a) => fetch(...a));
    this.sleep = deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  get baseUrl(): string {
    return this.deps.baseUrl;
  }

  async request<T>(opts: RequestOptions<T>): Promise<T> {
    const method = opts.method ?? "GET";
    const safeToRetry = method === "GET" || opts.idempotencyKey !== undefined;
    const maxAttempts = 1 + (safeToRetry ? (opts.retries ?? (method === "GET" ? 1 : 2)) : 0);
    let attempt = 0;
    for (;;) {
      attempt += 1;
      try {
        return await this.once(opts, method);
      } catch (e) {
        const retryable = e instanceof NetworkError || (e instanceof ApiError && e.status === 503);
        if (!retryable || attempt >= maxAttempts) throw e;
        const wait = e instanceof ApiError && e.retryAfterSeconds ? Math.min(e.retryAfterSeconds, 5) * 1000 : 300 * attempt;
        await this.sleep(wait);
      }
    }
  }

  private async once<T>(opts: RequestOptions<T>, method: string): Promise<T> {
    const useAuth = opts.auth !== false;
    let res = await this.send(opts, method, useAuth);
    if (res.status === 401 && useAuth) {
      // exactly one rotation + replay; the replay carries the SAME Idempotency-Key so it cannot double-apply
      const ok = await this.deps.session.refresh();
      if (ok) res = await this.send(opts, method, useAuth);
    }
    return this.parse(res, opts);
  }

  private async send<T>(opts: RequestOptions<T>, method: string, useAuth: boolean): Promise<Response> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    if (opts.societyId) headers["X-Society-Id"] = opts.societyId;
    if (useAuth) {
      const token = await this.deps.session.accessToken();
      if (token) headers["Authorization"] = `Bearer ${token}`;
    }
    const qs = opts.query
      ? Object.entries(opts.query)
          .filter(([, v]) => v !== undefined && v !== null && v !== "")
          .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
          .join("&")
      : "";
    const url = `${this.deps.baseUrl}${opts.path}${qs ? `?${qs}` : ""}`;
    try {
      return await this.fetchImpl(url, {
        method,
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: opts.signal,
      });
    } catch (e) {
      throw new NetworkError(e);
    }
  }

  private async parse<T>(res: Response, opts: RequestOptions<T>): Promise<T> {
    if (res.ok) {
      if (res.status === 204 || opts.schema === null) return undefined as T;
      const json: unknown = await res.json().catch(() => undefined);
      const parsed = opts.schema.safeParse(json);
      if (!parsed.success) throw new ContractError(opts.path, parsed.error.message.slice(0, 500));
      return parsed.data;
    }
    const raw: unknown = await res.json().catch(() => null);
    const body = ErrorBodySchema.safeParse(raw);
    const retryAfterHeader = Number(res.headers.get("Retry-After"));
    const retryAfter = Number.isFinite(retryAfterHeader) && retryAfterHeader > 0 ? retryAfterHeader : null;
    if (res.status === 401 && opts.auth !== false) {
      // still unauthenticated after the one allowed rotation: the session is over
      await this.deps.session.clear("expired");
    }
    throw new ApiError(
      res.status,
      body.success ? body.data : { code: res.status === 503 ? "dependency_unavailable" : "unknown_error" },
      retryAfter,
    );
  }
}
