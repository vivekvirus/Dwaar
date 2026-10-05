import { describe, expect, it } from "vitest";
import { CAPABILITIES, CONSOLE_ROLES, NAV, capabilitiesFor, navFor, requiredFor } from "@/lib/access";
import { deriveSession, effectiveRoles } from "@/server/session";
import { SOC_A, meWith } from "../server/fake-api";
import societies from "../fixtures/societies.json";

const navIds = (roles: string[]) => navFor(capabilitiesFor(roles)).map((n) => n.id);

describe("role-specific menu (PRD 6, IAM-03)", () => {
  it("gives each console role exactly the released screens it may use", () => {
    expect(navIds(["secretary"])).toEqual(["overview", "units", "gates", "devices", "visits", "exceptions", "society"]);
    expect(navIds(["committee"])).toEqual(["overview", "units", "gates", "devices", "visits", "exceptions", "society"]);
    expect(navIds(["estate_mgr"])).toEqual(["overview", "units", "gates", "devices", "visits", "exceptions", "society"]);
    expect(navIds(["treasurer"])).toEqual(["overview", "units", "society"]);
    expect(navIds(["auditor"])).toEqual(["overview", "units", "society"]);
    expect(navIds(["guard_sup"])).toEqual(["overview", "gates", "devices", "visits", "exceptions"]);
  });

  it("shows nothing beyond Overview to non-console roles, and unreleased modules never appear", () => {
    for (const role of ["guard", "owner_occ", "tenant", "family", "owner_nr"]) expect(capabilitiesFor([role])).toEqual([]);
    const labels = NAV.map((n) => n.labelKey + n.groupKey).join(" ");
    for (const unreleased of ["finance", "operations", "governance", "privacy"]) expect(labels).not.toContain(unreleased);
  });

  it("only the secretary can configure, import, or see integration readiness", () => {
    for (const cap of ["gate.configure", "unit.import", "society.configure", "integration.readiness"] as const) {
      expect(CAPABILITIES[cap]).toEqual(["secretary"]);
    }
    expect(CAPABILITIES["gate.device.decide"]).toEqual(["secretary", "guard_sup"]);
  });

  it("route guard table matches the menu", () => {
    expect(requiredFor("/security/devices")).toEqual(["gate.device.read"]);
    expect(requiredFor("/security/devices/anything")).toEqual(["gate.device.read"]);
    expect(requiredFor("/account/sessions")).toBeNull();
    expect(CONSOLE_ROLES).toContain("guard_sup");
  });
});

describe("effective roles from /v1/me", () => {
  it("treats an elevated role without the second factor as pending step-up, not as a granted role", () => {
    const me = meWith([{ role: "secretary", active: false, requires_mfa: true, mfa_satisfied: false }]);
    const r = effectiveRoles(me.societies[0]!.roles);
    expect(r.effective).toEqual([]);
    expect(r.stepUpPending).toBe(true);
  });

  it("ignores roles that are not valid now", () => {
    const me = meWith([{ role: "auditor" }]);
    me.societies[0]!.roles[0]!.valid_now = false;
    expect(effectiveRoles(me.societies[0]!.roles).effective).toEqual([]);
  });

  it("derives capabilities from server roles only", () => {
    const view = deriveSession(meWith([{ role: "treasurer", requires_mfa: true, mfa_satisfied: true }]), societies.items, undefined);
    if (!view.authenticated) throw new Error("unreachable");
    expect(view.selectedSocietyId).toBe(SOC_A);
    expect(view.capabilities).toContain("unit.read");
    expect(view.capabilities).not.toContain("gate.device.read");
    expect(view.nav.map((n) => n.id)).toEqual(["overview", "units", "society"]);
  });
});
