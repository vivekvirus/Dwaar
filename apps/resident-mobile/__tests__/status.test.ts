// REQ: INV-07 / UX-04: submitted, approved, entered are distinct and truthful.
import { entryLine, invitationStatus, requestStatus, visitStatus } from "../src/domain/status";
import { createT, SUPPORTED_LOCALES } from "../src/i18n";

describe("truthful status vocabulary", () => {
  test("approved + entry_observed=false is 'Approved; not yet entered', never 'Entered'", () => {
    const s = requestStatus({ status: "approved", entry_observed: false });
    expect(s.key).toBe("states.visit.approved");
    expect(createT("en")(s.key)).toBe("Approved; not yet entered");
  });
  test("entered is only shown when the backend observed entry", () => {
    expect(requestStatus({ status: "approved", entry_observed: true }).key).toBe("states.visit.entered");
    expect(visitStatus({ state: "authorised", entry_observed: false }).key).toBe("states.visit.approved");
    expect(visitStatus({ state: "inside", entry_observed: true }).key).toBe("states.visit.entered");
    expect(visitStatus({ state: "requested", entry_observed: false }).key).toBe("app.status.requested");
  });
  test("a visit the household denied reads 'Denied' (the backend stores it as cancelled/denied), other cancellations read 'Withdrawn'", () => {
    expect(visitStatus({ state: "cancelled", entry_observed: false, closed_reason: "denied" }).key).toBe("states.visit.denied");
    expect(visitStatus({ state: "cancelled", entry_observed: false, closed_reason: "cancelled_by_guard" }).key).toBe("app.status.cancelled");
    expect(visitStatus({ state: "cancelled", entry_observed: false }).key).toBe("app.status.cancelled");
  });
  test("entry line: false -> 'Not yet at gate / not observed' in every language", () => {
    expect(createT("en")(entryLine(false))).toBe("Not yet at gate / not observed");
    for (const l of SUPPORTED_LOCALES) {
      expect(createT(l)(entryLine(false))).not.toBe(entryLine(false));
      expect(createT(l)(entryLine(true))).not.toBe(createT(l)(entryLine(false)));
    }
  });
  test("every status has a glyph (state is never colour alone) and a non-empty label in en/hi/mr", () => {
    const all = [
      ...(["pending", "approved", "denied", "expired", "cancelled"] as const).map((status) => requestStatus({ status, entry_observed: false })),
      ...(["requested", "authorised", "inside", "exited", "cancelled", "expired"] as const).map((state) => visitStatus({ state, entry_observed: state === "inside" })),
      ...(["draft", "active", "consumed", "expired", "revoked"] as const).map((state) => invitationStatus({ state })),
    ];
    for (const s of all) {
      expect(s.glyph.length).toBeGreaterThan(0);
      for (const l of SUPPORTED_LOCALES) expect(createT(l)(s.key)).not.toBe(s.key);
    }
  });
});
