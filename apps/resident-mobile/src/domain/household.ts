// REQ: INV-01 / PRD 6 ("selector never silently changes context"; stale object ids from another society fail closed).
// A household context is (society, unit, role) taken from the SERVER's /v1/me; the choice is stored locally but is always
// re-validated against the current /v1/me, and anything that is no longer offered is dropped, never replaced silently.
import type { Me } from "./types";

/** Roles that live in the unit and may decide approvals / create passes (gate.request.decide, gate.invitation.create). */
export const HOUSEHOLD_ROLES = ["owner_occ", "tenant", "family"] as const;
export type HouseholdRole = (typeof HOUSEHOLD_ROLES)[number];

export interface HouseholdContext {
  societyId: string;
  unitId: string;
  role: HouseholdRole;
}

export function isHouseholdRole(role: string): role is HouseholdRole {
  return (HOUSEHOLD_ROLES as readonly string[]).includes(role);
}

export function sameContext(a: HouseholdContext | null, b: HouseholdContext | null): boolean {
  return !!a && !!b && a.societyId === b.societyId && a.unitId === b.unitId && a.role === b.role;
}

/** Contexts the server currently grants this person (active, valid now, unit-scoped household roles), de-duplicated. */
export function deriveContexts(me: Me): HouseholdContext[] {
  const out: HouseholdContext[] = [];
  for (const s of me.societies) {
    for (const r of s.roles) {
      if (!isHouseholdRole(r.role) || !r.unit_id || !r.active || !r.valid_now) continue;
      const ctx: HouseholdContext = { societyId: s.society_id, unitId: r.unit_id, role: r.role };
      if (!out.some((c) => sameContext(c, ctx))) out.push(ctx);
    }
  }
  return out;
}

export type Resolution =
  | { kind: "none" }
  | { kind: "choose"; stale: boolean }
  | { kind: "active"; context: HouseholdContext; chosenByUser: boolean };

/**
 * Decide what to show after sign-in or a refresh of /v1/me.
 * - stored choice still offered      -> keep it
 * - stored choice gone               -> "choose" with a notice; NEVER pick another one for the person
 * - nothing stored, exactly one home -> that home is active (and visible in the header); no silent switch is possible
 * - nothing stored, several homes    -> "choose"
 */
export function resolveContext(offered: HouseholdContext[], stored: HouseholdContext | null): Resolution {
  if (offered.length === 0) return { kind: "none" };
  if (stored) {
    const still = offered.find((c) => sameContext(c, stored));
    return still ? { kind: "active", context: still, chosenByUser: true } : { kind: "choose", stale: true };
  }
  if (offered.length === 1) return { kind: "active", context: offered[0]!, chosenByUser: false };
  return { kind: "choose", stale: false };
}

/** Fail-closed check for any object received from the API: it must belong to the ACTIVE society and unit. */
export function belongsToContext(ctx: HouseholdContext, obj: { unit_id: string }): boolean {
  return obj.unit_id === ctx.unitId;
}
