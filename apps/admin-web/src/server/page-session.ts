// Server Component helper: reads the HttpOnly cookies through next/headers and returns the SERVER-derived session.
import { cookies, headers } from "next/headers";
import { cache } from "react";
import { redirect } from "next/navigation";
import { requiredFor } from "@/lib/access";
import { CookieJar } from "./cookies";
import { loadSession, type SessionView } from "./session";

export type ConsoleSession = Extract<SessionView, { authenticated: true }>;

export async function currentPath(): Promise<string> {
  return (await headers()).get("x-dwaar-pathname") ?? "/overview";
}

// cache(): the layout and the page of one request share ONE /v1/me round trip
export const requireSession = cache(async (): Promise<{ session: ConsoleSession; path: string }> => {
  const store = await cookies();
  const jar = new CookieJar(store.getAll().map((c) => `${c.name}=${encodeURIComponent(c.value)}`).join("; "));
  const path = await currentPath();
  const { view, needsRefresh } = await loadSession(jar, { allowRefresh: false });
  if (needsRefresh) redirect(`/api/auth/refresh?next=${encodeURIComponent(path)}`);
  if (!view.authenticated) redirect("/signin");
  if (view.stepUpRequired) redirect("/signin?step=mfa");
  return { session: view, path };
});

export function accessVerdict(session: ConsoleSession, path: string): "ok" | "no_console" | "pick_society" | "forbidden" {
  if (!session.societies.some((s) => s.consoleAccess)) return "no_console";
  if (!session.selectedSocietyId) return "pick_society";
  const need = requiredFor(path);
  if (need && !need.every((c) => session.capabilities.includes(c))) return "forbidden";
  return "ok";
}

/** Per-page server guard (a layout does not re-run on client-side navigation, so every page checks for itself). */
export async function pageAllowed(path: string): Promise<boolean> {
  const { session } = await requireSession();
  return accessVerdict(session, path) === "ok";
}
