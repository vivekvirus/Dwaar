// REQ: IAM-03 (OTP + TOTP step-up), IAM-08 (session, refresh, revoke), IAM-09 (HttpOnly cookies + CSRF), INV-01 (the selected
// society is server-held and explicit), PRD 12.2 (errors pass through with their stable codes).
// Pure Fetch-API handlers (Request -> Response) so they run under Next route handlers AND in unit tests.
import { COOKIE, PROXY_ALLOW, QUERY_ALLOW, cookiesSecure } from "./config";
import { CookieJar } from "./cookies";
import { checkCsrf, ensureCsrfCookie } from "./csrf";
import { errorBody, errorResponse, newRequestId } from "./errors";
import { loadSession, SessionUnavailable, type SessionView } from "./session";
import { clearAuthCookies, ensureAccessToken, forceRefresh, isTokenPair, refreshTokens, setTokenCookies } from "./tokens";
import { callUpstream, type Fetcher, type UpstreamResult } from "./upstream";

export type Deps = { fetcher?: Fetcher };

const NO_STORE = { "cache-control": "no-store" };
const IDEM_RE = /^[A-Za-z0-9_.:-]{8,128}$/;
const MAX_BODY = 2 * 1024 * 1024;

function finish(res: Response, jar: CookieJar): Response {
  jar.apply(res.headers);
  return res;
}

function json(status: number, body: unknown, jar: CookieJar, extra?: Record<string, string>): Response {
  return finish(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...NO_STORE, ...extra } }), jar);
}

function relay(up: UpstreamResult, jar: CookieJar): Response {
  const extra: Record<string, string> = {};
  for (const h of ["retry-after", "x-request-id", "idempotent-replay"]) {
    const v = up.headers.get(h);
    if (v) extra[h] = v;
  }
  if (up.status === 204 || up.status === 205) return finish(new Response(null, { status: up.status, headers: { ...NO_STORE, ...extra } }), jar);
  return json(up.status, up.body ?? errorBody("dependency_unavailable"), jar, extra);
}

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const text = await req.text();
    if (text.length > MAX_BODY) return null;
    const v = JSON.parse(text) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function guardCsrf(req: Request, jar: CookieJar): Response | null {
  const v = checkCsrf(req, jar);
  if (v.ok) return null;
  return finish(errorResponse("not_authorised", { reason: "csrf" }), jar);
}

function deviceId(jar: CookieJar): string {
  const existing = jar.get(COOKIE.device);
  if (existing && /^[0-9a-f-]{36}$/.test(existing)) return existing;
  const id = crypto.randomUUID();
  jar.set(COOKIE.device, id, { httpOnly: true, secure: cookiesSecure(), sameSite: "Strict", path: "/api", maxAge: 60 * 60 * 24 * 365 });
  return id;
}

// ------------------------------------------------------------------------------------------------ sign-in
export async function otpRequest(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const bad = guardCsrf(req, jar);
  if (bad) return bad;
  const body = await readJson(req);
  const phone = typeof body?.phone === "string" ? body.phone.trim() : "";
  if (!/^\+?[0-9 ]{8,20}$/.test(phone)) return finish(errorResponse("invalid_schema", { fields: [{ field: "phone", issue: "invalid_phone" }] }), jar);
  const up = await callUpstream({ method: "POST", path: "/v1/auth/otp/request", json: { phone }, requestId: newRequestId() }, deps.fetcher);
  if (up.status === 202 || up.status === 200) return json(202, { ok: true }, jar);
  return relay(up, jar);
}

export async function otpVerify(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const bad = guardCsrf(req, jar);
  if (bad) return bad;
  const body = await readJson(req);
  const phone = typeof body?.phone === "string" ? body.phone.trim() : "";
  const code = typeof body?.code === "string" ? body.code.trim() : "";
  if (!/^\+?[0-9 ]{8,20}$/.test(phone) || !/^[0-9]{4,8}$/.test(code)) {
    return finish(errorResponse("invalid_schema", { fields: [{ field: "code", issue: "invalid_code" }] }), jar);
  }
  const up = await callUpstream(
    { method: "POST", path: "/v1/auth/otp/verify", json: { phone, code, device: { device_id: deviceId(jar), label: "Committee console (web)", platform: "web" } }, requestId: newRequestId() },
    deps.fetcher,
  );
  if (up.status !== 200 || !isTokenPair(up.body)) return relay(up, jar);
  setTokenCookies(jar, up.body);
  // A new sign-in starts with NO selected society: the context is chosen explicitly, never inherited from a previous person.
  jar.clear(COOKIE.society, { httpOnly: true, secure: cookiesSecure(), sameSite: "Strict", path: "/" });
  return json(200, { ok: true }, jar);
}

/** Local simulator only: shows the one-time code that a real SMS gateway would deliver. Closed unless the API says local. */
export async function devOtp(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const phone = new URL(req.url).searchParams.get("phone") ?? "";
  if (process.env.DWAAR_ADMIN_DEV_OTP === "off" || !/^\+?[0-9 ]{8,20}$/.test(phone)) return finish(errorResponse("not_found"), jar);
  const meta = await callUpstream({ method: "GET", path: "/v1/meta" }, deps.fetcher);
  const m = meta.body as { environment?: string; simulation?: boolean } | null;
  if (!m || m.simulation !== true || !["local", "test"].includes(m.environment ?? "")) return finish(errorResponse("not_found"), jar);
  const up = await callUpstream({ method: "GET", path: "/v1/dev/otp", query: { phone } }, deps.fetcher);
  if (up.status !== 200) return finish(errorResponse("not_found"), jar);
  const b = up.body as { otp?: string; simulation?: boolean };
  return json(200, { otp: b.otp, simulation: true }, jar);
}

export async function mfaVerify(req: Request, deps: Deps = {}): Promise<Response> {
  return mfaCall(req, "/v1/auth/mfa/verify", deps);
}
export async function mfaConfirm(req: Request, deps: Deps = {}): Promise<Response> {
  return mfaCall(req, "/v1/auth/mfa/totp/confirm", deps);
}
export async function mfaEnrol(req: Request, deps: Deps = {}): Promise<Response> {
  return mfaCall(req, "/v1/auth/mfa/totp/enrol", deps, false);
}

async function mfaCall(req: Request, path: string, deps: Deps, withCode = true): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const bad = guardCsrf(req, jar);
  if (bad) return bad;
  let token = await ensureAccessToken(jar, deps.fetcher);
  if (!token) return finish(errorResponse("unauthenticated"), jar);
  let json_: unknown;
  if (withCode) {
    const body = await readJson(req);
    const code = typeof body?.code === "string" ? body.code.trim() : "";
    if (!/^[0-9]{6}$/.test(code)) return finish(errorResponse("invalid_schema", { fields: [{ field: "code", issue: "invalid_code" }] }), jar);
    json_ = { code };
  }
  let up = await callUpstream({ method: "POST", path, token, json: json_, requestId: newRequestId() }, deps.fetcher);
  if (up.status === 401 && path !== "/v1/auth/mfa/verify") {
    const next = await forceRefresh(jar, token, deps.fetcher);
    if (next) {
      token = next;
      up = await callUpstream({ method: "POST", path, token, json: json_, requestId: newRequestId() }, deps.fetcher);
    }
  }
  return relay(up, jar);
}

export async function logout(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const bad = guardCsrf(req, jar);
  if (bad) return bad;
  const token = jar.get(COOKIE.access);
  if (token) await callUpstream({ method: "POST", path: "/v1/auth/logout", token }, deps.fetcher);
  clearAuthCookies(jar);
  return json(200, { ok: true }, jar);
}

/** GET, used by Server Components that found an expired access cookie: rotate, then come back. */
export async function refreshRedirect(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const url = new URL(req.url);
  const rawNext = url.searchParams.get("next") ?? "/overview";
  const next = rawNext.startsWith("/") && !rawNext.startsWith("//") && !rawNext.startsWith("/api/") ? rawNext : "/overview";
  const rt = jar.get(COOKIE.refresh);
  const pair = rt ? await refreshTokens(rt, deps.fetcher) : null;
  const base = req.headers.get("x-forwarded-host") ? `${req.headers.get("x-forwarded-proto") ?? "http"}://${req.headers.get("x-forwarded-host")}` : url.origin;
  if (!pair) {
    clearAuthCookies(jar);
    return finish(new Response(null, { status: 303, headers: { location: `${base}/signin`, ...NO_STORE } }), jar);
  }
  setTokenCookies(jar, pair);
  return finish(new Response(null, { status: 303, headers: { location: `${base}${next}`, ...NO_STORE } }), jar);
}

// ------------------------------------------------------------------------------------------------ session
export async function sessionGet(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  ensureCsrfCookie(jar);
  try {
    const { view } = await loadSession(jar, { fetcher: deps.fetcher });
    return json(200, view, jar);
  } catch (e) {
    if (e instanceof SessionUnavailable) return finish(errorResponse("dependency_unavailable"), jar);
    throw e;
  }
}

/** Explicit society switch. The browser must send the id of the society it believes it is leaving AND confirm: nothing else
 *  (no API call, no cached value) can change which society later calls carry. */
export async function selectSociety(req: Request, deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const bad = guardCsrf(req, jar);
  if (bad) return bad;
  const body = await readJson(req);
  const target = typeof body?.society_id === "string" ? body.society_id : "";
  if (body?.confirm !== true || !/^[0-9a-f-]{36}$/.test(target)) return finish(errorResponse("invalid_schema", { fields: [{ field: "society_id", issue: "confirmation_required" }] }), jar);
  const { view } = await loadSession(jar, { fetcher: deps.fetcher });
  if (!view.authenticated) return finish(errorResponse("unauthenticated"), jar);
  const usable = view.societies.find((s) => s.id === target && s.consoleAccess);
  if (!usable) return finish(errorResponse("not_found"), jar); // same answer for unknown and "not yours" (no membership disclosure)
  jar.set(COOKIE.society, target, { httpOnly: true, secure: cookiesSecure(), sameSite: "Strict", path: "/", maxAge: 60 * 60 * 24 * 30 });
  const fresh = await loadSession(jar, { fetcher: deps.fetcher });
  return json(200, fresh.view, jar);
}

// ------------------------------------------------------------------------------------------------ generic proxy
const meCache = new Map<string, { at: number; view: SessionView }>();
const ME_TTL_MS = 10_000;

export function __resetProxyStateForTests(): void {
  meCache.clear();
}

async function cachedSession(jar: CookieJar, token: string, deps: Deps): Promise<SessionView> {
  const now = Date.now();
  for (const [k, v] of meCache) if (now - v.at > ME_TTL_MS) meCache.delete(k);
  const key = `${token.slice(-24)}|${jar.get(COOKIE.society) ?? ""}`;
  const hit = meCache.get(key);
  if (hit) return hit.view;
  const { view } = await loadSession(jar, { fetcher: deps.fetcher });
  meCache.set(key, { at: now, view });
  return view;
}

export async function proxy(req: Request, segments: string[], deps: Deps = {}): Promise<Response> {
  const jar = new CookieJar(req.headers.get("cookie"));
  const method = req.method.toUpperCase();
  const bad = guardCsrf(req, jar);
  if (bad) return bad;
  const [kind, ...rest] = segments;
  if (!kind || (kind !== "society" && kind !== "v1") || rest.some((s) => !s || s === ".." || s === ".")) return finish(errorResponse("not_found"), jar);

  let token = await ensureAccessToken(jar, deps.fetcher);
  if (!token) return finish(errorResponse("unauthenticated"), jar);

  let view: SessionView;
  try {
    view = await cachedSession(jar, token, deps);
  } catch (e) {
    if (e instanceof SessionUnavailable) return finish(errorResponse("dependency_unavailable"), jar);
    throw e;
  }
  if (!view.authenticated) return finish(errorResponse("unauthenticated"), jar);
  const selected = view.selectedSocietyId;
  if (!selected) return finish(errorResponse("not_found", { reason: "no_society_selected" }), jar);
  const sel = view.societies.find((s) => s.id === selected);
  if (!sel?.consoleAccess) return finish(errorResponse("not_authorised"), jar);

  // The client states which society it believes it is working in; a mismatch (e.g. another tab switched) is refused loudly.
  const claimed = req.headers.get("x-dwaar-society");
  if (claimed !== selected) return finish(errorResponse("stale_version", { reason: "society_context_changed" }), jar);

  const path = kind === "society" ? `/v1/societies/${selected}/${rest.join("/")}` : `/v1/${rest.join("/")}`;
  if (!PROXY_ALLOW.some((r) => r.method === method && r.pattern.test(path))) return finish(errorResponse("not_found"), jar);
  if (kind === "v1" && /^\/v1\/societies\//.test(path)) return finish(errorResponse("not_found"), jar); // society routes only via /society/

  const query = new URLSearchParams();
  new URL(req.url).searchParams.forEach((v, k) => {
    if (QUERY_ALLOW.has(k)) query.append(k, v);
  });

  const unsafe = method !== "GET";
  let payload: { json?: unknown; text?: string } = {};
  if (unsafe && method !== "DELETE") {
    const ct = req.headers.get("content-type") ?? "";
    const raw = await req.text();
    if (raw.length > MAX_BODY) return finish(errorResponse("invalid_schema", { fields: [{ field: "body", issue: "too_large" }] }), jar);
    if (ct.startsWith("text/csv")) payload = { text: raw };
    else if (raw) {
      try {
        payload = { json: JSON.parse(raw) };
      } catch {
        return finish(errorResponse("invalid_schema"), jar);
      }
    }
  }
  const idemHeader = req.headers.get("idempotency-key");
  const idempotencyKey = unsafe ? (idemHeader && IDEM_RE.test(idemHeader) ? idemHeader : crypto.randomUUID()) : null;
  const call = { method, path, society: selected, query, idempotencyKey, requestId: newRequestId(), ...payload };

  let up = await callUpstream({ ...call, token }, deps.fetcher);
  if (up.status === 401) {
    const next = await forceRefresh(jar, token, deps.fetcher);
    if (!next) return finish(errorResponse("unauthenticated"), jar);
    token = next;
    up = await callUpstream({ ...call, token }, deps.fetcher);
  }
  return relay(up, jar);
}

