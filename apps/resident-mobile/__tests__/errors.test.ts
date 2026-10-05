// REQ: PRD 12.2 - every error code has an i18n message in en/hi/mr; membership is never revealed.
import { ApiError, ERROR_CODES, NetworkError, errorMessage, isKnownCode } from "../src/api/errors";
import { createT, SUPPORTED_LOCALES } from "../src/i18n";

const mk = (status: number, code: string, extra: Record<string, unknown> = {}) => new ApiError(status, { code, request_id: "req-123", ...extra });

describe("error mapping", () => {
  test("the app covers exactly the codes of PRD 12.2", () => {
    expect([...ERROR_CODES].sort()).toEqual(
      ["invalid_schema", "unauthenticated", "not_authorised", "not_found", "stale_version", "duplicate_payload_mismatch", "already_decided", "request_expired", "policy_violation", "missing_tax_config", "legal_pack_not_approved", "rate_limited", "dependency_unavailable"].sort(),
    );
  });

  test.each(SUPPORTED_LOCALES.flatMap((l) => ERROR_CODES.map((c) => [l, c] as const)))("%s / %s has a real message", (locale, code) => {
    const t = createT(locale);
    const msg = errorMessage(mk(409, code, {}), t);
    expect(msg.length).toBeGreaterThan(5);
    expect(msg).not.toMatch(/^errors\./);
    expect(msg).not.toContain("{");
  });

  test("rate_limited shows the retry information", () => {
    const e = new ApiError(429, { code: "rate_limited", request_id: "r" }, 42);
    expect(errorMessage(e, createT("en"))).toContain("42");
  });

  test("an unknown code falls back to the generic message with the request id for support", () => {
    const msg = errorMessage(mk(500, "some_new_code"), createT("en"));
    expect(msg).toContain("req-123");
    expect(isKnownCode("some_new_code")).toBe(false);
  });

  test("403 and 404 never explain why or mention membership; server free text is never shown", () => {
    const t = createT("en");
    for (const code of ["not_authorised", "not_found"]) {
      const msg = errorMessage(mk(code === "not_found" ? 404 : 403, code, { message: "You are not a member of society X" } as never), t);
      expect(msg.toLowerCase()).not.toMatch(/member|society|unit|resident/);
    }
  });

  test("network failures have their own message that says nothing was changed", () => {
    expect(errorMessage(new NetworkError(), createT("en"))).toMatch(/Nothing was changed/);
  });

  test("canonical details are only trusted when they match the schema", () => {
    expect(mk(409, "already_decided", { details: { canonical: { status: "approved" } } }).canonical).toBeNull();
    const ok = mk(409, "already_decided", {
      details: { canonical: { request_id: "a", status: "approved", version: 2, decision_id: "d", permission_expires_at: null, entry_observed: false }, decided_by_role: "tenant" },
    });
    expect(ok.canonical?.status).toBe("approved");
    expect(ok.decidedByRole).toBe("tenant");
  });
});
