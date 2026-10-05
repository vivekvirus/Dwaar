// REQ: IAM-08 (short-lived access tokens, ROTATING refresh tokens with reuse detection), IAM-03.
// Tokens live only in HttpOnly cookies. Parallel BFF requests that all notice an expired access token must not each rotate the
// same refresh token (the API would treat the second use as theft and revoke the session): refreshes are single-flight per
// refresh token and the result is remembered for a few seconds for late arrivals (single Node process; ADR-0016).
import { COOKIE, cookiesSecure } from "./config";
import type { CookieJar } from "./cookies";
import { callUpstream, type Fetcher } from "./upstream";

export type TokenPair = { access_token: string; refresh_token: string; expires_in: number };

const inflight = new Map<string, Promise<TokenPair | null>>();
const recent = new Map<string, { at: number; pair: TokenPair | null }>();
const RECENT_MS = 15_000;

export function setTokenCookies(jar: CookieJar, pair: TokenPair): void {
  const secure = cookiesSecure();
  jar.set(COOKIE.access, pair.access_token, {
    httpOnly: true, secure, sameSite: "Strict", path: "/", maxAge: Math.max(30, pair.expires_in - 30),
  });
  jar.set(COOKIE.refresh, pair.refresh_token, {
    httpOnly: true, secure, sameSite: "Strict", path: "/api", maxAge: 60 * 60 * 24 * 30,
  });
}

export function clearAuthCookies(jar: CookieJar): void {
  const secure = cookiesSecure();
  jar.clear(COOKIE.access, { httpOnly: true, secure, sameSite: "Strict", path: "/" });
  jar.clear(COOKIE.refresh, { httpOnly: true, secure, sameSite: "Strict", path: "/api" });
  jar.clear(COOKIE.society, { httpOnly: true, secure, sameSite: "Strict", path: "/" });
}

export function isTokenPair(v: unknown): v is TokenPair {
  const o = v as Record<string, unknown> | null;
  return !!o && typeof o.access_token === "string" && typeof o.refresh_token === "string" && typeof o.expires_in === "number";
}

export async function refreshTokens(refreshToken: string, fetcher?: Fetcher): Promise<TokenPair | null> {
  const now = Date.now();
  for (const [k, v] of recent) if (now - v.at > RECENT_MS) recent.delete(k);
  const hit = recent.get(refreshToken);
  if (hit) return hit.pair;
  const running = inflight.get(refreshToken);
  if (running) return running;
  const p = (async () => {
    const res = await callUpstream({ method: "POST", path: "/v1/auth/refresh", json: { refresh_token: refreshToken } }, fetcher);
    const pair = res.status === 200 && isTokenPair(res.body) ? res.body : null;
    recent.set(refreshToken, { at: Date.now(), pair });
    return pair;
  })().finally(() => inflight.delete(refreshToken));
  inflight.set(refreshToken, p);
  return p;
}

/** Returns a usable access token (refreshing through the cookie jar if needed), or null when the session is gone. */
export async function ensureAccessToken(jar: CookieJar, fetcher?: Fetcher): Promise<string | null> {
  const at = jar.get(COOKIE.access);
  if (at) return at;
  const rt = jar.get(COOKIE.refresh);
  if (!rt) return null;
  const pair = await refreshTokens(rt, fetcher);
  if (!pair) {
    clearAuthCookies(jar);
    return null;
  }
  setTokenCookies(jar, pair);
  return pair.access_token;
}

/** Force one refresh after the API said 401 for a token we thought valid (revoked, or expired earlier than the cookie). */
export async function forceRefresh(jar: CookieJar, failedToken: string, fetcher?: Fetcher): Promise<string | null> {
  const rt = jar.get(COOKIE.refresh);
  if (!rt) {
    clearAuthCookies(jar);
    return null;
  }
  const pair = await refreshTokens(rt, fetcher);
  if (!pair || pair.access_token === failedToken) {
    clearAuthCookies(jar);
    return null;
  }
  setTokenCookies(jar, pair);
  return pair.access_token;
}

export function __resetTokenStateForTests(): void {
  inflight.clear();
  recent.clear();
}
