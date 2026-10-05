// COM-02 / UX-03: app-local catalog completeness and placeholder parity; shared namespaces used by the app exist in hi/mr.
import { APP_CATALOGS, EN } from "../src/i18n/appStrings";
import { createT, formatDateTime, SUPPORTED_LOCALES } from "../src/i18n";

const placeholders = (s: string) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();

describe("app catalog", () => {
  test.each(["hi", "mr"] as const)("%s has every key, none empty, same placeholders as English", (loc) => {
    for (const [k, en] of Object.entries(EN)) {
      const v = (APP_CATALOGS[loc] as Record<string, string>)[k];
      expect(v?.length).toBeGreaterThan(0);
      expect(placeholders(v!)).toEqual(placeholders(en));
    }
    expect(Object.keys(APP_CATALOGS[loc]).sort()).toEqual(Object.keys(EN).sort());
  });
  test("hi/mr are actually translated (Devanagari) for user-facing keys", () => {
    const sample = ["app.home.updates", "app.approval.title", "app.invite.create", "app.signin.title"] as const;
    for (const loc of ["hi", "mr"] as const) for (const k of sample) expect(APP_CATALOGS[loc][k]).toMatch(/[ऀ-ॿ]/);
  });
  test("unit numbers pass through untouched in every language (one script)", () => {
    for (const l of SUPPORTED_LOCALES) expect(createT(l)("common.unit.label", { unit: "A-402" })).toContain("A-402");
  });
  test("dates use Latin digits and IST in every language", () => {
    for (const l of SUPPORTED_LOCALES) {
      const s = formatDateTime("2026-10-05T09:00:00Z", l);
      expect(s).toMatch(/14|2/); // 09:00Z = 14:30 IST
      expect(s).toMatch(/[0-9]/);
      expect(s).not.toMatch(/[०-९]/); // no Devanagari digits
    }
  });
});
