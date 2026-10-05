// REQ: IAM-03, IAM-08/IAM-09 (web uses HttpOnly cookies + CSRF protection).
// Double-submit: the CSRF token lives in a non-HttpOnly SameSite=Strict cookie and must be echoed in the X-CSRF-Token header
// of every unsafe request. Defence in depth: Origin / Sec-Fetch-Site must be same-origin when the browser sends them.
import { timingSafeEqual } from "node:crypto";
import { COOKIE, cookiesSecure } from "./config";
import type { CookieJar } from "./cookies";

export const CSRF_HEADER = "x-csrf-token";
const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function newCsrfToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function ensureCsrfCookie(jar: CookieJar): string {
  const existing = jar.get(COOKIE.csrf);
  if (existing && /^[0-9a-f]{64}$/.test(existing)) return existing;
  const token = newCsrfToken();
  jar.set(COOKIE.csrf, token, { httpOnly: false, secure: cookiesSecure(), sameSite: "Strict", path: "/", maxAge: 60 * 60 * 24 * 30 });
  return token;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export type CsrfVerdict = { ok: true } | { ok: false; reason: "cross_site" | "missing_token" | "mismatch" };

export function checkCsrf(req: Request, jar: CookieJar): CsrfVerdict {
  if (!UNSAFE.has(req.method.toUpperCase())) return { ok: true };
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return { ok: false, reason: "cross_site" };
  const origin = req.headers.get("origin");
  if (origin) {
    const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
    let originHost: string | null = null;
    try {
      originHost = new URL(origin).host;
    } catch {
      originHost = null;
    }
    if (!host || originHost !== host) return { ok: false, reason: "cross_site" };
  }
  const cookie = jar.get(COOKIE.csrf);
  const header = req.headers.get(CSRF_HEADER);
  if (!cookie || !header) return { ok: false, reason: "missing_token" };
  return safeEqual(cookie, header) ? { ok: true } : { ok: false, reason: "mismatch" };
}
