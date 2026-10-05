// REQ: IAM-09. Gives Server Components the request path, and makes sure every browser has the CSRF double-submit cookie before
// it can submit any form. No tokens are touched here.
import { NextResponse, type NextRequest } from "next/server";

export function middleware(req: NextRequest) {
  const headers = new Headers(req.headers);
  headers.set("x-dwaar-pathname", req.nextUrl.pathname);
  const res = NextResponse.next({ request: { headers } });
  const existing = req.cookies.get("dwaar_csrf")?.value;
  if (!existing || !/^[0-9a-f]{64}$/.test(existing)) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const token = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const secure = process.env.DWAAR_ADMIN_COOKIE_SECURE === "true" || (process.env.DWAAR_ADMIN_COOKIE_SECURE !== "false" && process.env.NODE_ENV === "production" && process.env.DWAAR_ENV !== "local");
    res.cookies.set("dwaar_csrf", token, { httpOnly: false, sameSite: "strict", secure, path: "/", maxAge: 60 * 60 * 24 * 30 });
  }
  return res;
}

export const config = { matcher: ["/((?!api/|_next/static|_next/image|favicon.ico).*)"] };
