import { describe, expect, it } from "vitest";
import { ERROR_CODES, errorBody } from "@/server/errors";
import { CODE_TO_KEY, KNOWN_REASONS, mapError } from "@/lib/errors";
import { ApiCallError } from "@/lib/api-client";
import { lookup, SUPPORTED_LOCALES } from "@dwaar/i18n";
import { makeT, message } from "@/i18n";

describe("PRD 12.2 error mapping through i18n", () => {
  it("maps every PRD 12.2 code to a message key that exists in every locale of @dwaar/i18n", () => {
    expect(ERROR_CODES).toHaveLength(13);
    for (const code of ERROR_CODES) {
      const key = CODE_TO_KEY[code];
      expect(key, code).toBe(`errors.${code}`);
      for (const locale of SUPPORTED_LOCALES) expect(lookup(locale, key!), `${locale}:${code}`).toBeTruthy();
    }
  });

  it("renders the localised text, never the server message", () => {
    const err = new ApiCallError(404, "not_found", "req-1", {}, null);
    const m = mapError(err);
    expect(makeT("en")(m.key, m.params)).toBe("We could not find what you asked for.");
    expect(makeT("hi")(m.key, m.params)).not.toBe(makeT("en")(m.key, m.params));
    expect(m.requestId).toBe("req-1");
  });

  it("carries retry information for rate_limited", () => {
    const m = mapError(new ApiCallError(429, "rate_limited", "r", {}, 17));
    expect(makeT("en")(m.key, m.params)).toContain("17 seconds");
  });

  it("falls back to errors.unknown with the request id for an unrecognised code", () => {
    const m = mapError(new ApiCallError(500, "weird_new_code", "abc-123", {}, null));
    expect(makeT("en")(m.key, m.params)).toContain("abc-123");
    expect(mapError(new Error("boom")).key).toBe("errors.unknown");
  });

  it("gives not_found and not_authorised the same neutral wording regardless of detail (no membership disclosure)", () => {
    const a = mapError(new ApiCallError(404, "not_found", "r", { reason: "not_a_member" }, null));
    expect(a.reasonKey).toBeNull(); // unknown reasons are never echoed
    const t = makeT("en");
    expect(t(a.key, a.params)).not.toMatch(/member|society|belong/i);
  });

  it("explains the known policy reasons and the society-changed case", () => {
    const r = mapError(new ApiCallError(422, "policy_violation", "r", { reason: "maker_checker" }, null));
    expect(r.reasonKey).toBe("console.reason.maker_checker");
    expect(message("en", r.reasonKey!)).toMatch(/different person/);
    const s = mapError(new ApiCallError(409, "stale_version", "r", { reason: "society_context_changed" }, null));
    expect(s.key).toBe("console.error.society_changed");
    for (const reason of KNOWN_REASONS) expect(message("en", `console.reason.${reason}` as never)).not.toContain("console.reason");
  });

  it("BFF-originated error bodies carry request_id, stable code, message key and details", () => {
    for (const code of ERROR_CODES) {
      const b = errorBody(code, { a: 1 });
      expect(b).toMatchObject({ code, message_key: `errors.${code}`, details: { a: 1 } });
      expect(b.request_id).toBeTruthy();
    }
  });
});
