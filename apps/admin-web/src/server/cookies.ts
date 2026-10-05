// REQ: IAM-08. Minimal cookie jar over the Fetch API (no next/headers dependency, so handlers are unit-testable).
export type CookieOptions = {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax";
  path: string;
  maxAge?: number;
};

export function parseCookieHeader(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      /* ignore malformed cookie values */
    }
  }
  return out;
}

export function serializeCookie(name: string, value: string, o: CookieOptions): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${o.path}`, `SameSite=${o.sameSite}`];
  if (o.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(o.maxAge))}`);
  if (o.httpOnly) parts.push("HttpOnly");
  if (o.secure) parts.push("Secure");
  return parts.join("; ");
}

export class CookieJar {
  readonly incoming: Record<string, string>;
  readonly outgoing: string[] = [];
  private overrides = new Map<string, string | null>();

  constructor(cookieHeader: string | null | undefined) {
    this.incoming = parseCookieHeader(cookieHeader);
  }

  get(name: string): string | undefined {
    if (this.overrides.has(name)) return this.overrides.get(name) ?? undefined;
    return this.incoming[name];
  }

  set(name: string, value: string, options: CookieOptions): void {
    this.overrides.set(name, value);
    this.outgoing.push(serializeCookie(name, value, options));
  }

  clear(name: string, options: Omit<CookieOptions, "maxAge">): void {
    this.overrides.set(name, null);
    this.outgoing.push(serializeCookie(name, "", { ...options, maxAge: 0 }));
  }

  apply(headers: Headers): void {
    for (const c of this.outgoing) headers.append("set-cookie", c);
  }
}
