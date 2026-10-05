import { describe, expect, it } from "vitest";
import { ALL_KEYS, createTranslator, interpolate, lookup, resolveLocale, translate, SUPPORTED_LOCALES, t } from "../src/index";

describe("@dwaar/i18n", () => {
  it("translates the three guard tiles in each locale", () => {
    expect(translate("en", "guard.tile.guest")).toBe("Guest");
    expect(translate("hi", "guard.tile.guest")).toBe("मेहमान");
    expect(translate("mr", "guard.tile.guest")).toBe("पाहुणा");
  });

  it("uses the exact UX-04 truthful status strings", () => {
    expect(t("states.local.saved_awaiting_sync")).toBe("Saved on this device; awaiting sync");
    expect(t("states.payment.received_settlement_pending")).toBe("Payment received; settlement pending");
    expect(t("states.parcel.at_gate")).toBe("At gate until collected");
  });

  it("keeps INV-07 states distinct", () => {
    const labels = ["visit.submitted", "visit.approved", "visit.entered", "parcel.handed_over", "payment.paid", "payment.settled"].map(
      (k) => t(`states.${k}` as never),
    );
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("interpolates params and keeps unit numbers verbatim", () => {
    expect(translate("hi", "common.unit.label", { unit: "A-402" })).toBe("यूनिट A-402");
    expect(createTranslator("mr")("guard.queue.pending", { count: 3 })).toBe("3 सिंकच्या प्रतीक्षेत");
    expect(interpolate("x {a} {b}", { a: 1 })).toBe("x 1 {b}");
  });

  it("falls back to English then to the key", () => {
    expect(lookup("hi", "nope.key")).toBeUndefined();
    expect(translate("hi", "nope.key" as never)).toBe("nope.key");
  });

  it("resolves locales leniently", () => {
    expect(resolveLocale("hi-IN")).toBe("hi");
    expect(resolveLocale("MR_in")).toBe("mr");
    expect(resolveLocale("fr")).toBe("en");
    expect(resolveLocale(undefined)).toBe("en");
  });

  it("has every generated key non-empty in every locale", () => {
    expect(ALL_KEYS.length).toBeGreaterThan(100);
    for (const l of SUPPORTED_LOCALES) for (const k of ALL_KEYS) expect(lookup(l, k), `${l} ${k}`).toBeTruthy();
  });

  it("lock-screen approval text omits visitor and unit", () => {
    for (const l of SUPPORTED_LOCALES) {
      const body = translate(l, "notifications.approval.request.lockscreen.body");
      expect(body).not.toMatch(/\{(visitor|unit)\}/);
    }
  });
});
