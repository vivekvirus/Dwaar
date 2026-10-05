import { beforeEach, describe, expect, it } from "vitest";
import {
  __resetProxyStateForTests, devOtp, logout, mfaVerify, otpRequest, otpVerify, proxy, refreshRedirect, selectSociety, sessionGet,
} from "@/server/handlers";
import { __resetTokenStateForTests } from "@/server/tokens";
import { CSRF, SOC_A, SOC_B, fakeApi, meWith, post, request, setCookies, tokenPair } from "./fake-api";
import societies from "../fixtures/societies.json";

beforeEach(() => {
  __resetProxyStateForTests();
  __resetTokenStateForTests();
  process.env.DWAAR_ENV = "local";
});

const signedIn = { dwaar_at: "access-1", dwaar_rt: "refresh-1" };

describe("sign-in handlers (IAM-03, IAM-08, IAM-09)", () => {
  it("stores tokens ONLY in HttpOnly SameSite=Strict cookies and never returns them in the body", async () => {
    const { fetcher, calls } = fakeApi({ "POST /v1/auth/otp/verify": () => ({ json: tokenPair() }) });
    const res = await otpVerify(post("/api/auth/otp/verify", { phone: "+919999901001", code: "123456" }), { fetcher });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain("access-1");
    expect(text).not.toContain("refresh-1");
    const cookies = setCookies(res);
    const at = cookies.find((c) => c.startsWith("dwaar_at="))!;
    const rt = cookies.find((c) => c.startsWith("dwaar_rt="))!;
    for (const c of [at, rt]) {
      expect(c).toContain("HttpOnly");
      expect(c).toContain("SameSite=Strict");
    }
    expect(rt).toContain("Path=/api"); // the refresh token is never even sent to page routes
    expect(JSON.parse(calls[0]!.body!).device.platform).toBe("web");
  });

  it("clears the selected society on a fresh sign-in (no inherited context)", async () => {
    const { fetcher } = fakeApi({ "POST /v1/auth/otp/verify": () => ({ json: tokenPair() }) });
    const res = await otpVerify(post("/api/auth/otp/verify", { phone: "+919999901001", code: "123456" }, { dwaar_soc: SOC_B }), { fetcher });
    expect(setCookies(res).some((c) => c.startsWith("dwaar_soc=;") && c.includes("Max-Age=0"))).toBe(true);
  });

  it("rejects unsafe requests without a valid CSRF token or from another origin", async () => {
    const { fetcher, calls } = fakeApi();
    const noHeader = request("/api/auth/otp/request", { method: "POST", body: JSON.stringify({ phone: "+919999901001" }), cookies: { dwaar_csrf: CSRF }, headers: { origin: "http://localhost:3100" } });
    expect((await otpRequest(noHeader, { fetcher })).status).toBe(403);
    const wrong = post("/api/auth/otp/request", { phone: "+919999901001" }, {}, { "x-csrf-token": "b".repeat(64) });
    expect((await otpRequest(wrong, { fetcher })).status).toBe(403);
    const crossOrigin = post("/api/auth/otp/request", { phone: "+919999901001" }, {}, { origin: "https://evil.example" });
    expect((await otpRequest(crossOrigin, { fetcher })).status).toBe(403);
    const crossSite = post("/api/auth/otp/request", { phone: "+919999901001" }, {}, { "sec-fetch-site": "cross-site" });
    expect((await otpRequest(crossSite, { fetcher })).status).toBe(403);
    expect(calls).toHaveLength(0); // nothing reached the API
  });

  it("validates input before calling the API and relays API errors with their stable code", async () => {
    const { fetcher } = fakeApi({ "POST /v1/auth/otp/verify": () => ({ status: 401, json: { request_id: "r1", code: "unauthenticated", message: "x", message_key: "errors.unauthenticated", details: {} } }) });
    const bad = await otpVerify(post("/api/auth/otp/verify", { phone: "abc", code: "1" }), { fetcher });
    expect(bad.status).toBe(400);
    expect((await bad.json()).code).toBe("invalid_schema");
    const wrong = await otpVerify(post("/api/auth/otp/verify", { phone: "+919999901001", code: "000000" }), { fetcher });
    expect(wrong.status).toBe(401);
    expect((await wrong.json()).code).toBe("unauthenticated");
    expect(setCookies(wrong).some((c) => c.startsWith("dwaar_at="))).toBe(false);
  });

  it("relays rate limits with Retry-After", async () => {
    const { fetcher } = fakeApi({ "POST /v1/auth/otp/request": () => ({ status: 429, headers: { "retry-after": "42" }, json: { request_id: "r", code: "rate_limited", message: "", message_key: "errors.rate_limited", details: {} } }) });
    const res = await otpRequest(post("/api/auth/otp/request", { phone: "+919999901001" }), { fetcher });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("42");
  });

  it("only exposes the simulator OTP when the API itself says local simulation", async () => {
    const local = fakeApi({ "GET /v1/meta": () => ({ json: { environment: "local", simulation: true } }), "GET /v1/dev/otp": () => ({ json: { otp: "424242" } }) });
    const ok = await devOtp(request("/api/auth/dev-otp?phone=%2B919999901001"), { fetcher: local.fetcher });
    expect(await ok.json()).toEqual({ otp: "424242", simulation: true });
    const prod = fakeApi({ "GET /v1/meta": () => ({ json: { environment: "production", simulation: false } }), "GET /v1/dev/otp": () => ({ json: { otp: "424242" } }) });
    const closed = await devOtp(request("/api/auth/dev-otp?phone=%2B919999901001"), { fetcher: prod.fetcher });
    expect(closed.status).toBe(404);
    expect(prod.calls.some((c) => c.path === "/v1/dev/otp")).toBe(false);
  });

  it("step-up posts the TOTP code with the server-held bearer token", async () => {
    const { fetcher, calls } = fakeApi({ "POST /v1/auth/mfa/verify": () => ({ json: { session_elevated: true } }) });
    const res = await mfaVerify(post("/api/auth/mfa", { code: "123456" }, signedIn), { fetcher });
    expect(res.status).toBe(200);
    expect(calls[0]!.headers.authorization).toBe("Bearer access-1");
    const bad = await mfaVerify(post("/api/auth/mfa", { code: "12" }, signedIn), { fetcher });
    expect(bad.status).toBe(400);
  });

  it("logout revokes upstream and clears every auth cookie", async () => {
    const { fetcher, calls } = fakeApi({ "POST /v1/auth/logout": () => ({ status: 204 }) });
    const res = await logout(post("/api/auth/logout", {}, { ...signedIn, dwaar_soc: SOC_A }), { fetcher });
    expect(calls.some((c) => c.path === "/v1/auth/logout")).toBe(true);
    const cleared = setCookies(res).filter((c) => c.includes("Max-Age=0")).map((c) => c.split("=")[0]);
    expect(cleared).toEqual(expect.arrayContaining(["dwaar_at", "dwaar_rt", "dwaar_soc"]));
  });

  it("refresh redirect only goes to same-site paths", async () => {
    const { fetcher } = fakeApi({ "POST /v1/auth/refresh": () => ({ json: tokenPair(2) }) });
    const ok = await refreshRedirect(request("/api/auth/refresh?next=/security/devices", { cookies: { dwaar_rt: "refresh-1" } }), { fetcher });
    expect(ok.status).toBe(303);
    expect(ok.headers.get("location")).toBe("http://localhost:3100/security/devices");
    const evil = await refreshRedirect(request("/api/auth/refresh?next=//evil.example/x", { cookies: { dwaar_rt: "refresh-1" } }), { fetcher });
    expect(evil.headers.get("location")).toBe("http://localhost:3100/overview");
  });
});

describe("session and society selection (INV-01, PRD 6)", () => {
  it("derives the menu from the server's /v1/me, not from anything the client sends", async () => {
    const { fetcher } = fakeApi();
    const res = await sessionGet(request("/api/session", { cookies: { ...signedIn, dwaar_roles: "secretary", dwaar_soc: SOC_A }, headers: { "x-roles": "secretary" } }), { fetcher });
    const s = await res.json();
    expect(s.authenticated).toBe(true);
    expect(s.societies[0].roles).toEqual(["secretary"]);
  });

  it("does not auto-select when several societies are usable, and never trusts a foreign cookie", async () => {
    const two = {
      ...meWith([{ role: "secretary" }], SOC_A),
      societies: [...meWith([{ role: "secretary" }], SOC_A).societies, ...meWith([{ role: "committee" }], SOC_B).societies],
    };
    const { fetcher } = fakeApi({}, two, societies);
    const none = await (await sessionGet(request("/api/session", { cookies: signedIn }), { fetcher })).json();
    expect(none.selectedSocietyId).toBeNull();
    const foreign = await (await sessionGet(request("/api/session", { cookies: { ...signedIn, dwaar_soc: "019b76da-a800-7fff-b000-00000000dead" } }), { fetcher })).json();
    expect(foreign.selectedSocietyId).toBeNull();
  });

  it("switches only on explicit confirmation, and answers not_found for a society that is not the person's", async () => {
    const two = {
      ...meWith([{ role: "secretary" }], SOC_A),
      societies: [...meWith([{ role: "secretary" }], SOC_A).societies, ...meWith([{ role: "committee" }], SOC_B).societies],
    };
    const { fetcher } = fakeApi({}, two, societies);
    const noConfirm = await selectSociety(post("/api/session/society", { society_id: SOC_B }, signedIn), { fetcher });
    expect(noConfirm.status).toBe(400);
    expect(setCookies(noConfirm).some((c) => c.startsWith("dwaar_soc="))).toBe(false);
    const ok = await selectSociety(post("/api/session/society", { society_id: SOC_B, confirm: true }, signedIn), { fetcher });
    expect(ok.status).toBe(200);
    expect(setCookies(ok).find((c) => c.startsWith("dwaar_soc="))).toContain(`dwaar_soc=${SOC_B}`);
    expect(setCookies(ok).find((c) => c.startsWith("dwaar_soc="))).toContain("HttpOnly");
    const foreign = await selectSociety(post("/api/session/society", { society_id: "019b76da-a800-7fff-b000-00000000dead", confirm: true }, signedIn), { fetcher });
    expect(foreign.status).toBe(404);
    expect((await foreign.json()).code).toBe("not_found");
  });

  it("marks elevated roles as pending step-up until the TOTP is verified", async () => {
    const pending = meWith([{ role: "secretary", active: false, requires_mfa: true, mfa_satisfied: false }]);
    const { fetcher } = fakeApi({}, pending);
    const s = await (await sessionGet(request("/api/session", { cookies: signedIn }), { fetcher })).json();
    expect(s.stepUpRequired).toBe(true);
    expect(s.societies[0].consoleAccess).toBe(false);
    expect(s.capabilities).toEqual([]);
  });
});

describe("generic proxy (INV-01: every call carries the selected society)", () => {
  const cookies = { ...signedIn, dwaar_soc: SOC_A };
  const getReq = (path: string, society = SOC_A) =>
    request(path, { cookies, headers: { "x-dwaar-society": society } });

  it("injects the selected society into the path and X-Society-Id, ignoring any society in the query", async () => {
    const { fetcher, calls } = fakeApi({ [`GET /v1/societies/${SOC_A}/units`]: () => ({ json: { items: [], next_cursor: null } }) });
    const res = await proxy(getReq(`/api/bff/society/units?limit=5&society_id=${SOC_B}&status=active&evil=1`), ["society", "units"], { fetcher });
    expect(res.status).toBe(200);
    const call = calls.find((c) => c.path.endsWith("/units"))!;
    expect(call.path).toBe(`/v1/societies/${SOC_A}/units`);
    expect(call.headers["x-society-id"]).toBe(SOC_A);
    expect(call.search).toContain("limit=5");
    expect(call.search).toContain("status=active");
    expect(call.search).not.toContain("society_id");
    expect(call.search).not.toContain("evil");
    expect(call.headers.authorization).toBe("Bearer access-1");
  });

  it("refuses a call whose society differs from the selected one (another tab switched)", async () => {
    const { fetcher, calls } = fakeApi();
    const res = await proxy(getReq("/api/bff/society/units", SOC_B), ["society", "units"], { fetcher });
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.code).toBe("stale_version");
    expect(body.details.reason).toBe("society_context_changed");
    expect(calls.some((c) => c.path.includes("/units"))).toBe(false);
    const missing = await proxy(request("/api/bff/society/units", { cookies }), ["society", "units"], { fetcher });
    expect(missing.status).toBe(409);
  });

  it("is not an open relay: unknown routes, path tricks and the society prefix via /v1 are refused", async () => {
    const { fetcher, calls } = fakeApi();
    for (const segs of [["society", "role-grants"], ["v1", `societies`, SOC_A, "units"], ["society", "..", "..", "auth", "logout"], ["v1", "auth", "otp", "request"], ["other", "x"]]) {
      const res = await proxy(getReq(`/api/bff/${segs.join("/")}`), segs, { fetcher });
      expect(res.status, segs.join("/")).toBe(404);
    }
    expect(calls.filter((c) => !["/v1/me", "/v1/societies"].includes(c.path))).toHaveLength(0);
  });

  it("requires CSRF on writes, forwards the client's idempotency key, and sends JSON/CSV bodies unchanged", async () => {
    const dev = "019b76da-a800-71d7-ba59-c28b9f6a93aa";
    const { fetcher, calls } = fakeApi({ [`POST /v1/societies/${SOC_A}/devices/${dev}/decision`]: () => ({ json: { ok: true } }), [`POST /v1/societies/${SOC_A}/units:import`]: () => ({ json: { valid: true } }) });
    const noCsrf = request(`/api/bff/society/devices/${dev}/decision`, { method: "POST", body: "{}", cookies, headers: { "x-dwaar-society": SOC_A, "content-type": "application/json" } });
    expect((await proxy(noCsrf, ["society", "devices", dev, "decision"], { fetcher })).status).toBe(403);

    const ok = post(`/api/bff/society/devices/${dev}/decision`, { decision: "approve", expected_version: 1 }, cookies, { "x-dwaar-society": SOC_A, "idempotency-key": "client-key-0001" });
    expect((await proxy(ok, ["society", "devices", dev, "decision"], { fetcher })).status).toBe(200);
    const sent = calls.find((c) => c.path.endsWith("/decision"))!;
    expect(sent.headers["idempotency-key"]).toBe("client-key-0001");
    expect(JSON.parse(sent.body!)).toEqual({ decision: "approve", expected_version: 1 });

    const csv = request("/api/bff/society/units:import?dry_run=true", { method: "POST", body: "block,label,floor\r\nA,1,1\r\n", cookies: { ...cookies, dwaar_csrf: CSRF }, headers: { "x-dwaar-society": SOC_A, "content-type": "text/csv", "x-csrf-token": CSRF, origin: "http://localhost:3100" } });
    expect((await proxy(csv, ["society", "units:import"], { fetcher })).status).toBe(200);
    const imp = calls.find((c) => c.path.endsWith("units:import"))!;
    expect(imp.headers["content-type"]).toBe("text/csv");
    expect(imp.search).toContain("dry_run=true");
    expect(imp.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/); // generated when the client sent none
  });

  it("refuses people with no console role in the selected society (guards, residents)", async () => {
    const guard = meWith([{ role: "guard" }]);
    const { fetcher, calls } = fakeApi({}, guard);
    const res = await proxy(getReq("/api/bff/society/units"), ["society", "units"], { fetcher });
    // no console society at all: nothing is selectable, and the answer is the generic not_found (no membership disclosure)
    expect(res.status).toBe(404);
    expect((await res.json()).code).toBe("not_found");
    expect(calls.some((c) => c.path.includes("/units"))).toBe(false);
  });

  it("refuses a selected society where the person holds no console role (cookie names it, /v1/me does not allow it)", async () => {
    const mixed = { ...meWith([{ role: "guard" }], SOC_A), societies: [...meWith([{ role: "guard" }], SOC_A).societies, ...meWith([{ role: "committee" }], SOC_B).societies] };
    const { fetcher, calls } = fakeApi({}, mixed);
    const res = await proxy(request("/api/bff/society/units", { cookies: { ...signedIn, dwaar_soc: SOC_A }, headers: { "x-dwaar-society": SOC_A } }), ["society", "units"], { fetcher });
    expect(res.status).toBe(404);
    expect(calls.some((c) => c.path.includes("/units"))).toBe(false);
  });

  it("a person with exactly one console society gets it selected on first load (no prior context to change)", async () => {
    const { fetcher } = fakeApi({ [`GET /v1/societies/${SOC_A}/gates`]: () => ({ json: { items: [] } }) });
    const res = await proxy(request("/api/bff/society/gates", { cookies: signedIn, headers: { "x-dwaar-society": SOC_A } }), ["society", "gates"], { fetcher });
    expect(res.status).toBe(200);
  });

  it("with several societies and none chosen, the proxy refuses instead of guessing", async () => {
    const two = { ...meWith([{ role: "secretary" }], SOC_A), societies: [...meWith([{ role: "secretary" }], SOC_A).societies, ...meWith([{ role: "committee" }], SOC_B).societies] };
    const { fetcher, calls } = fakeApi({}, two);
    const res = await proxy(request("/api/bff/society/gates", { cookies: signedIn, headers: { "x-dwaar-society": SOC_A } }), ["society", "gates"], { fetcher });
    expect(res.status).toBe(404);
    expect(calls.some((c) => c.path.includes("/gates"))).toBe(false);
  });

  it("refreshes ONCE for parallel requests (rotating refresh token, reuse detection) and retries after a 401", async () => {
    let refreshCalls = 0;
    const { fetcher, calls } = fakeApi({
      "POST /v1/auth/refresh": async () => {
        refreshCalls += 1;
        await new Promise((r) => setTimeout(r, 20));
        return { json: tokenPair(2) };
      },
      [`GET /v1/societies/${SOC_A}/gates`]: (c) => (c.headers.authorization === "Bearer access-2" ? { json: { items: [] } } : { status: 401, json: { request_id: "r", code: "unauthenticated", message: "", message_key: "errors.unauthenticated", details: {} } }),
    });
    const noAccess = { dwaar_rt: "refresh-1", dwaar_soc: SOC_A };
    const mk = () => request("/api/bff/society/gates", { cookies: noAccess, headers: { "x-dwaar-society": SOC_A } });
    const [a, b, c] = await Promise.all([proxy(mk(), ["society", "gates"], { fetcher }), proxy(mk(), ["society", "gates"], { fetcher }), proxy(mk(), ["society", "gates"], { fetcher })]);
    expect([a.status, b.status, c.status]).toEqual([200, 200, 200]);
    expect(refreshCalls).toBe(1);
    expect(setCookies(a).some((x) => x.startsWith("dwaar_at=access-2"))).toBe(true);
    expect(calls.filter((x) => x.path === "/v1/auth/refresh")).toHaveLength(1);
  });

  it("answers unauthenticated and clears cookies when the session is gone", async () => {
    const { fetcher } = fakeApi({ "POST /v1/auth/refresh": () => ({ status: 401, json: { request_id: "r", code: "unauthenticated", message: "", message_key: "errors.unauthenticated", details: {} } }) });
    const res = await proxy(request("/api/bff/society/gates", { cookies: { dwaar_rt: "stale", dwaar_soc: SOC_A }, headers: { "x-dwaar-society": SOC_A } }), ["society", "gates"], { fetcher });
    expect(res.status).toBe(401);
    expect(setCookies(res).some((c) => c.startsWith("dwaar_rt=;"))).toBe(true);
  });

  it("maps an unreachable API to dependency_unavailable (503)", async () => {
    const fetcher = async () => {
      throw new Error("ECONNREFUSED");
    };
    const res = await proxy(getReq("/api/bff/society/gates"), ["society", "gates"], { fetcher });
    expect(res.status).toBe(503);
  });
});
