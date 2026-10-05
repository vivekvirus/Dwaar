import me from "../fixtures/me.json";
import societies from "../fixtures/societies.json";
import type { Fetcher } from "@/server/upstream";

export type Call = { method: string; path: string; search: string; headers: Record<string, string>; body: string | undefined };
export type Handler = (call: Call) => { status?: number; json?: unknown; headers?: Record<string, string> } | Promise<{ status?: number; json?: unknown; headers?: Record<string, string> }>;

export const SOC_A = me.societies[0]!.society_id;
export const SOC_B = "019b76da-a800-7bbb-b000-000000000002";

export type MeShape = typeof me;
export const meWith = (roles: { role: string; active?: boolean; requires_mfa?: boolean; mfa_satisfied?: boolean }[], society = SOC_A): MeShape => ({
  ...me,
  societies: [
    {
      society_id: society,
      memberships: [],
      roles: roles.map((r) => ({
        role: r.role, source: "role_grant", unit_id: null as never, active: r.active ?? true, valid_now: true, not_before: null as never, expires_at: null as never,
        requires_mfa: r.requires_mfa ?? false, mfa_satisfied: r.mfa_satisfied ?? true,
      })),
    },
  ],
});

export function fakeApi(handlers: Record<string, Handler> = {}, meBody: unknown = me, societiesBody: unknown = societies) {
  const calls: Call[] = [];
  const base: Record<string, Handler> = {
    "GET /v1/me": () => ({ json: meBody }),
    "GET /v1/societies": () => ({ json: societiesBody }),
    ...handlers,
  };
  const fetcher: Fetcher = async (url, init) => {
    const u = new URL(url);
    const call: Call = {
      method: (init?.method ?? "GET").toUpperCase(),
      path: u.pathname,
      search: u.search,
      headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])),
      body: init?.body as string | undefined,
    };
    calls.push(call);
    const h = base[`${call.method} ${call.path}`];
    if (!h) return new Response(JSON.stringify({ request_id: "r", code: "not_found", message: "", message_key: "errors.not_found", details: {} }), { status: 404 });
    const out = await h(call);
    const status = out.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(out.json ?? {}), { status, headers: { "content-type": "application/json", ...(out.headers ?? {}) } });
  };
  return { fetcher, calls };
}

export function request(url: string, init: { method?: string; headers?: Record<string, string>; body?: string; cookies?: Record<string, string> } = {}): Request {
  const headers = new Headers(init.headers);
  headers.set("host", "localhost:3100");
  if (init.cookies) headers.set("cookie", Object.entries(init.cookies).map(([k, v]) => `${k}=${v}`).join("; "));
  return new Request(`http://localhost:3100${url}`, { method: init.method ?? "GET", headers, body: init.body });
}

export const CSRF = "a".repeat(64);
export const tokenPair = (n = 1) => ({ access_token: `access-${n}`, refresh_token: `refresh-${n}`, expires_in: 900, token_type: "Bearer" });

/** CSRF-valid mutating request with the same-origin headers a browser sends. */
export const post = (url: string, body: unknown, cookies: Record<string, string> = {}, extra: Record<string, string> = {}) =>
  request(url, {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "content-type": "application/json", "x-csrf-token": CSRF, origin: "http://localhost:3100", "sec-fetch-site": "same-origin", ...extra },
    cookies: { dwaar_csrf: CSRF, ...cookies },
  });

export const setCookies = (res: Response) => res.headers.getSetCookie();
