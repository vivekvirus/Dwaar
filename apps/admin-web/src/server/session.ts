// REQ: IAM-03, IAM-08, INV-01, PRD 6 ("role-specific menu", "society selector never silently changes context").
// Builds the browser-safe session view from the SERVER's answer to /v1/me. Roles in any token or client state are ignored.
import { capabilitiesFor, isConsoleRole, navFor, type Capability, type NavItem } from "@/lib/access";
import type { Me, MeRole, SocietySummary } from "@/api/types";
import { COOKIE } from "./config";
import type { CookieJar } from "./cookies";
import { callUpstream, type Fetcher } from "./upstream";
import { ensureAccessToken, forceRefresh } from "./tokens";

export type SessionSociety = {
  id: string;
  name: string;
  city: string | null;
  roles: string[]; // effective console roles (active, valid now, step-up satisfied)
  consoleAccess: boolean;
  stepUpPending: boolean;
};

export type SessionView =
  | { authenticated: false }
  | {
      authenticated: true;
      person: { id: string; displayName: string; preferredLanguage: string };
      simulation: boolean;
      mfa: { enrolled: boolean; confirmed: boolean; sessionVerified: boolean };
      stepUpRequired: boolean;
      societies: SessionSociety[];
      selectedSocietyId: string | null;
      capabilities: Capability[];
      nav: NavItem[];
    };

export function effectiveRoles(roles: MeRole[]): { effective: string[]; stepUpPending: boolean } {
  // The API reports an elevated role as active=false until this session passed the second factor (IAM-03); such a role is
  // "pending step-up", not "absent".
  const live = roles.filter((r) => r.valid_now);
  const effective = live.filter((r) => r.active && (!r.requires_mfa || r.mfa_satisfied)).map((r) => r.role);
  const stepUpPending = live.some((r) => r.requires_mfa && !r.mfa_satisfied);
  return { effective: [...new Set(effective)], stepUpPending };
}

export function deriveSession(me: Me, societies: SocietySummary[], selectedCookie: string | undefined): SessionView {
  const names = new Map(societies.map((s) => [s.id, s]));
  const list: SessionSociety[] = me.societies.map((s) => {
    const { effective, stepUpPending } = effectiveRoles(s.roles);
    const consoleRoles = effective.filter(isConsoleRole);
    const info = names.get(s.society_id);
    return {
      id: s.society_id,
      name: info?.name ?? `Society ${s.society_id.slice(0, 8)}`,
      city: info?.city ?? null,
      roles: consoleRoles,
      consoleAccess: consoleRoles.length > 0,
      stepUpPending,
    };
  });
  const usable = list.filter((s) => s.consoleAccess);
  // An unknown/foreign cookie value is ignored (never trusted); a single usable society is selected on first load only
  // because there was no prior context to change.
  let selected: string | null = null;
  if (selectedCookie && usable.some((s) => s.id === selectedCookie)) selected = selectedCookie;
  else if (!selectedCookie && usable.length === 1) selected = usable[0]!.id;
  const roles = selected ? (usable.find((s) => s.id === selected)?.roles ?? []) : [];
  const caps = capabilitiesFor(roles);
  return {
    authenticated: true,
    person: { id: me.person.id, displayName: me.person.display_name, preferredLanguage: me.person.preferred_language },
    simulation: me.simulation,
    mfa: { enrolled: me.mfa.enrolled, confirmed: me.mfa.confirmed, sessionVerified: me.mfa.session_verified },
    stepUpRequired: list.some((s) => s.stepUpPending),
    societies: list,
    selectedSocietyId: selected,
    capabilities: caps,
    nav: navFor(caps),
  };
}

export type SessionLoad = { view: SessionView; token: string | null };

/** Loads the session. `allowRefresh` is false inside Server Components (they cannot set cookies). */
export async function loadSession(jar: CookieJar, opts: { fetcher?: Fetcher; allowRefresh?: boolean } = {}): Promise<SessionLoad & { needsRefresh: boolean }> {
  const allowRefresh = opts.allowRefresh ?? true;
  let token: string | null;
  if (allowRefresh) token = await ensureAccessToken(jar, opts.fetcher);
  else {
    token = jar.get(COOKIE.access) ?? null;
    if (!token && jar.get(COOKIE.refresh)) return { view: { authenticated: false }, token: null, needsRefresh: true };
  }
  if (!token) return { view: { authenticated: false }, token: null, needsRefresh: false };
  let me = await callUpstream({ method: "GET", path: "/v1/me", token }, opts.fetcher);
  if (me.status === 401 && allowRefresh) {
    const next = await forceRefresh(jar, token, opts.fetcher);
    if (!next) return { view: { authenticated: false }, token: null, needsRefresh: false };
    token = next;
    me = await callUpstream({ method: "GET", path: "/v1/me", token }, opts.fetcher);
  }
  if (me.status === 401) return { view: { authenticated: false }, token: null, needsRefresh: !allowRefresh && !!jar.get(COOKIE.refresh) };
  if (me.status !== 200 || !me.body) throw new SessionUnavailable(me.status);
  const socs = await callUpstream({ method: "GET", path: "/v1/societies", token }, opts.fetcher);
  const items = socs.status === 200 ? ((socs.body as { items?: SocietySummary[] }).items ?? []) : [];
  return { view: deriveSession(me.body as Me, items, jar.get(COOKIE.society)), token, needsRefresh: false };
}

export class SessionUnavailable extends Error {
  constructor(readonly status: number) {
    super(`session_unavailable_${status}`);
  }
}
