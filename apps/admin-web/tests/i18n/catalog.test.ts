import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { consoleKeys, message } from "@/i18n";
import en from "@/i18n/console.en.json";
import { IMPORT_CODES } from "@/features/units/import-panel";

function walk(dir: string, out: string[] = []): string[] {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(f)) out.push(p);
  }
  return out;
}

const SRC = resolve(__dirname, "../../src");
const keys = new Set(consoleKeys());

describe("console i18n catalog (UX-08)", () => {
  it("contains every literal console.* key used in source", () => {
    const missing: string[] = [];
    for (const file of walk(SRC)) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/["'`](console\.[a-z_]+(?:\.[a-z_0-9]+)+)["'`]/g)) {
        if (!keys.has(m[1]!)) missing.push(`${file.replace(SRC, "")}: ${m[1]}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("contains every key built from an enum value", () => {
    const families: Record<string, string[]> = {
      exception_kind: ["manual_entry", "emergency_entry", "unauthorised_entry", "exit_unknown", "overstay", "other"],
      exception_state: ["open", "supervisor_review", "escalated", "resolved"],
      device_state: ["pending_approval", "active", "rejected", "revoked"],
      visit_kind: ["guest", "delivery", "service", "cab", "staff", "vendor"],
      device_kind: ["terminal", "gateway", "reader", "camera", "relay", "meter_gw"],
      gate_kind: ["vehicle", "pedestrian", "mixed"],
      direction: ["in", "out", "both"],
      request_status: ["pending", "approved", "denied", "expired", "cancelled"],
      "devices.confirm_title": ["approve", "reject", "revoke"],
      "devices.confirm_body": ["approve", "reject", "revoke"],
      "devices.confirm_action": ["approve", "reject", "revoke"],
      "devices.receipt": ["approve", "reject", "revoke"],
      "exceptions.confirm_title": ["start_review", "escalate", "resolve"],
      "exceptions.confirm_body": ["start_review", "escalate", "resolve"],
      "exceptions.confirm_action": ["start_review", "escalate", "resolve"],
      "exceptions.receipt": ["start_review", "escalate", "resolve"],
      "settings.blocker": ["legal_pack_not_approved", "feature_flag_disabled"],
      "import.code": [...IMPORT_CODES],
    };
    const missing = Object.entries(families).flatMap(([fam, vals]) => vals.map((v) => `console.${fam}.${v}`)).filter((k) => !keys.has(k));
    expect(missing).toEqual([]);
  });

  it("has no empty values and balanced placeholders", () => {
    for (const [k, v] of Object.entries(en)) {
      expect(v.trim().length, k).toBeGreaterThan(0);
      expect((v.match(/\{/g) ?? []).length, k).toBe((v.match(/\}/g) ?? []).length);
    }
  });

  it("interpolates parameters and falls back from hi/mr to English", () => {
    expect(message("en", "console.society.switched_banner", { society: "Test Society" })).toContain("Test Society");
    expect(message("hi", "console.nav.overview")).toBe("Overview");
    expect(message("mr", "states.visit.approved")).not.toBe("states.visit.approved");
  });

  it("keeps INV-07 visit states distinct in the console", () => {
    const labels = ["states.visit.submitted", "states.visit.approved", "states.visit.entered", "console.visit_state.exited"].map((k) => message("en", k as never));
    expect(new Set(labels).size).toBe(labels.length);
  });
});
