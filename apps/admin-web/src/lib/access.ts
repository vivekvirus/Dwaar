// REQ: IAM-03, IAM-08, INV-01, PRD 5.2/6. The committee console menu is derived from the SERVER-computed effective roles of
// /v1/me (never from client-supplied claims). This table MIRRORS the permission declarations of the API
// (services/api/dwaar_api/modules/*/permissions.py); it only decides what to SHOW. Every API call is still authorised by the
// server, which is the one source of truth (blocked request BR-1: /v1/me should return effective permissions).

export const CONSOLE_ROLES = ["secretary", "treasurer", "committee", "estate_mgr", "auditor", "guard_sup"] as const;
export type ConsoleRole = (typeof CONSOLE_ROLES)[number];

const CONFIG_READERS = ["secretary", "treasurer", "committee", "estate_mgr", "auditor"] as const;
const GATE_READERS = ["secretary", "committee", "estate_mgr"] as const;

export const CAPABILITIES = {
  "society.read": CONFIG_READERS,
  "society.configure": ["secretary"],
  "unit.read": CONFIG_READERS,
  "unit.import": ["secretary"],
  "gate.configure.read": [...GATE_READERS, "guard_sup"],
  "gate.configure": ["secretary"],
  "gate.device.read": [...GATE_READERS, "guard_sup"],
  "gate.device.decide": ["secretary", "guard_sup"],
  "gate.visit.read": [...GATE_READERS, "guard_sup"],
  "gate.request.read": ["guard_sup"],
  "gate.exception.read": [...GATE_READERS, "guard_sup"],
  "gate.exception.manage": ["secretary", "guard_sup"],
  "integration.readiness": ["secretary"],
} as const satisfies Record<string, readonly string[]>;

export type Capability = keyof typeof CAPABILITIES;

export function isConsoleRole(role: string): role is ConsoleRole {
  return (CONSOLE_ROLES as readonly string[]).includes(role);
}

export function capabilitiesFor(roles: readonly string[]): Capability[] {
  return (Object.keys(CAPABILITIES) as Capability[]).filter((cap) =>
    (CAPABILITIES[cap] as readonly string[]).some((r) => roles.includes(r)),
  );
}

export type NavItem = {
  id: string;
  href: string;
  labelKey: "console.nav.overview" | "console.nav.units" | "console.nav.gates" | "console.nav.devices" | "console.nav.visits" | "console.nav.exceptions" | "console.nav.society";
  groupKey: "console.nav.group.overview" | "console.nav.group.residents" | "console.nav.group.security" | "console.nav.group.settings";
  requires: Capability[];
};

// Only RELEASED modules appear. Finance, Operations, Governance and Privacy have no released screens yet, so they are hidden
// (no empty nav items).
export const NAV: readonly NavItem[] = [
  { id: "overview", href: "/overview", labelKey: "console.nav.overview", groupKey: "console.nav.group.overview", requires: [] },
  { id: "units", href: "/residents/units", labelKey: "console.nav.units", groupKey: "console.nav.group.residents", requires: ["unit.read"] },
  { id: "gates", href: "/security/gates", labelKey: "console.nav.gates", groupKey: "console.nav.group.security", requires: ["gate.configure.read"] },
  { id: "devices", href: "/security/devices", labelKey: "console.nav.devices", groupKey: "console.nav.group.security", requires: ["gate.device.read"] },
  { id: "visits", href: "/security/visits", labelKey: "console.nav.visits", groupKey: "console.nav.group.security", requires: ["gate.visit.read"] },
  { id: "exceptions", href: "/security/exceptions", labelKey: "console.nav.exceptions", groupKey: "console.nav.group.security", requires: ["gate.exception.read"] },
  { id: "society", href: "/settings/society", labelKey: "console.nav.society", groupKey: "console.nav.group.settings", requires: ["society.read"] },
];

export function navFor(caps: readonly Capability[]): NavItem[] {
  return NAV.filter((item) => item.requires.every((c) => caps.includes(c)));
}

/** The route -> required capabilities map used by the server-side route guard (a hidden menu item is not a security control). */
export function requiredFor(pathname: string): Capability[] | null {
  const hit = NAV.find((n) => pathname === n.href || pathname.startsWith(`${n.href}/`));
  return hit ? hit.requires : null;
}
