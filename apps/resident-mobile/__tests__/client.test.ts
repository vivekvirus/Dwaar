// REQ: PRD 12 (Idempotency-Key, X-Society-Id), 12.2, IAM-14 (refresh rotation). API client against recorded fixtures.
import { ApiClient } from "../src/api/client";
import { createApi } from "../src/api/endpoints";
import { ApiError, ContractError, NetworkError } from "../src/api/errors";
import { SessionManager, REFRESH_SKEW_MS } from "../src/auth/session";
import { MemoryTokenStore } from "../src/auth/tokenStore";
import { fromFixture, jsonResponse, recorded } from "./fixtures";

const BASE = "http://api.test";
type Call = { url: string; init: RequestInit & { headers: Record<string, string> } };

async function setup(handler: (call: Call, n: number) => Response | Promise<Response>, opts: { expiresInMs?: number } = {}) {
  const calls: Call[] = [];
  const fetchImpl = jest.fn(async (url: string, init: any) => {
    const call = { url, init };
    calls.push(call);
    return handler(call, calls.length);
  }) as unknown as typeof fetch;
  const store = new MemoryTokenStore();
  store.value = { accessToken: "old-access-token", accessExpiresAt: Date.now() + (opts.expiresInMs ?? 600_000), refreshToken: "old-refresh-token", sessionId: "s1" };
  const session = new SessionManager(store, BASE, fetchImpl);
  await session.restore();
  const client = new ApiClient({ baseUrl: BASE, session, fetchImpl, sleep: async () => undefined });
  return { calls, store, session, client, api: createApi(client), fetchImpl };
}

const tokenBody = (n: number) => ({ token_type: "Bearer", access_token: `new-access-token-${n}`, refresh_token: `new-refresh-token-${n}`, expires_in: 900, session_id: "s1", simulation: true });

describe("ApiClient with recorded fixtures", () => {
  test("GET /v1/me sends the bearer token and parses the recorded body", async () => {
    const { api, calls } = await setup(() => fromFixture("me"));
    const me = await api.me();
    expect(me.person.display_name).toBe("Sanjay Deshpande");
    expect(calls[0]!.init.headers["Authorization"]).toBe("Bearer old-access-token");
    expect(calls[0]!.url).toBe(`${BASE}/v1/me`);
  });

  test("approval routes carry X-Society-Id (their path has no society); decisions carry Idempotency-Key and the PRD 12.3 body", async () => {
    const { api, calls } = await setup(() => fromFixture("decision-approved"));
    const canonical = await api.decide({
      requestId: "r1",
      societyId: "soc-1",
      idempotencyKey: "idem-key-0001",
      body: { decision: "approve", expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11", channel: "app" },
    });
    expect(canonical).toMatchObject({ status: "approved", version: 2, entry_observed: false });
    const h = calls[0]!.init.headers;
    expect(h["X-Society-Id"]).toBe("soc-1");
    expect(h["Idempotency-Key"]).toBe("idem-key-0001");
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({ decision: "approve", expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11", channel: "app" });
  });

  test("409 already_decided becomes an ApiError that exposes the canonical result of the winner", async () => {
    const { api } = await setup(() => fromFixture("decision-409-already-decided"));
    const err = await api.decide({ requestId: "r", societyId: "s", idempotencyKey: "idem-key-0002", body: { decision: "deny", expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b12" } }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(err.code).toBe("already_decided");
    expect(err.canonical).toMatchObject({ status: "approved", version: 2, entry_observed: false });
    expect(err.decidedByRole).toBe("owner_occ");
    expect(err.requestId).toBeTruthy();
  });

  test("404 keeps the server request id and a stable code", async () => {
    const { api } = await setup(() => fromFixture("error-404-not-found"));
    const err = await api.getApprovalRequest("s", "x").catch((e) => e);
    expect(err).toMatchObject({ status: 404, code: "not_found" });
  });

  test("a 2xx body that breaks the contract fails closed with ContractError", async () => {
    const { api } = await setup(() => jsonResponse(200, { items: [{ id: "x" }] }));
    await expect(api.listApprovalRequests("s", "u")).rejects.toBeInstanceOf(ContractError);
  });

  test("429 exposes Retry-After; 503 maps to dependency_unavailable even without a body", async () => {
    const a = await setup(() => jsonResponse(429, { request_id: "r", code: "rate_limited", message: "m", message_key: "errors.rate_limited" }, { "Retry-After": "17" }));
    const e1 = await a.api.me().catch((e) => e);
    expect(e1.retryAfterSeconds).toBe(17);
    const b = await setup(() => new Response("<html>bad gateway</html>", { status: 503 }));
    const e2: any = await b.api.logout().catch((e) => e);
    expect(e2.code).toBe("dependency_unavailable");
  });

  test("list/unit/invitation/visit fixtures parse", async () => {
    for (const [name, call] of [
      ["approval-list-pending", (a: ReturnType<typeof createApi>) => a.listApprovalRequests("s", "u")],
      ["approval-request-pending", (a: ReturnType<typeof createApi>) => a.getApprovalRequest("s", "r")],
      ["invitation-created", (a: ReturnType<typeof createApi>) => a.getInvitation("s", "i")],
      ["invitation-list", (a: ReturnType<typeof createApi>) => a.listInvitations("s", "u")],
      ["invitation-revoked", (a: ReturnType<typeof createApi>) => a.revokeInvitation("s", "i")],
      ["unit-visits", (a: ReturnType<typeof createApi>) => a.unitVisits("s", "u")],
      ["society", (a: ReturnType<typeof createApi>) => a.society("s")],
      ["unit", (a: ReturnType<typeof createApi>) => a.unit("s", "u")],
      ["profile-updated", (a: ReturnType<typeof createApi>) => a.updateProfile({ preferred_language: "mr" })],
    ] as const) {
      const { api } = await setup(() => fromFixture(name));
      await expect(call(api)).resolves.toBeDefined();
    }
  });
});

describe("refresh-token rotation", () => {
  test("a 401 triggers ONE refresh, the rotated pair is stored, and the original request is replayed with the new token and the SAME Idempotency-Key", async () => {
    let n = 0;
    const { api, calls, store } = await setup((call) => {
      if (call.url.endsWith("/v1/auth/refresh")) return jsonResponse(200, tokenBody(1));
      n += 1;
      return n === 1 ? fromFixture("error-401-unauthenticated") : fromFixture("decision-approved");
    });
    const cmd = { requestId: "r", societyId: "s", idempotencyKey: "idem-key-0003", body: { decision: "approve" as const, expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b13" } };
    await api.decide(cmd);
    const urls = calls.map((c) => c.url.replace(BASE, ""));
    expect(urls).toEqual(["/v1/approval-requests/r/decision", "/v1/auth/refresh", "/v1/approval-requests/r/decision"]);
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual({ refresh_token: "old-refresh-token" });
    expect(calls[0]!.init.headers["Authorization"]).toBe("Bearer old-access-token");
    expect(calls[2]!.init.headers["Authorization"]).toBe("Bearer new-access-token-1");
    expect(calls[2]!.init.headers["Idempotency-Key"]).toBe("idem-key-0003");
    expect(store.value?.refreshToken).toBe("new-refresh-token-1"); // rotated token persisted
  });

  test("parallel 401s share a single refresh (a second use of the rotated token would look like reuse)", async () => {
    let refreshes = 0;
    const { api } = await setup((call) => {
      if (call.url.endsWith("/v1/auth/refresh")) {
        refreshes += 1;
        return jsonResponse(200, tokenBody(refreshes));
      }
      return call.init.headers["Authorization"] === "Bearer old-access-token" ? fromFixture("error-401-unauthenticated") : fromFixture("me");
    });
    await Promise.all([api.me(), api.me(), api.me()]);
    expect(refreshes).toBe(1);
  });

  test("an access token about to expire is refreshed BEFORE the request", async () => {
    const { api, calls } = await setup((call) => (call.url.endsWith("/v1/auth/refresh") ? jsonResponse(200, tokenBody(1)) : fromFixture("me")), { expiresInMs: REFRESH_SKEW_MS - 1000 });
    await api.me();
    expect(calls.map((c) => c.url.replace(BASE, ""))).toEqual(["/v1/auth/refresh", "/v1/me"]);
    expect(calls[1]!.init.headers["Authorization"]).toBe("Bearer new-access-token-1");
  });

  test("a rejected refresh token ends the session: tokens wiped, 'expired' emitted, original error surfaced", async () => {
    const { api, store, session } = await setup((call) => (call.url.endsWith("/v1/auth/refresh") ? fromFixture("error-401-unauthenticated") : fromFixture("error-401-unauthenticated")));
    const events: string[] = [];
    session.subscribe((e) => events.push(e));
    const err = await api.me().catch((e) => e);
    expect(err).toMatchObject({ status: 401, code: "unauthenticated" });
    expect(store.value).toBeNull();
    expect(events).toContain("expired");
  });

  test("a refresh that cannot reach the server keeps the stored tokens (the person is not signed out by a bad network)", async () => {
    const { api, store } = await setup((call) => {
      if (call.url.endsWith("/v1/auth/refresh")) throw new TypeError("Failed to fetch");
      return fromFixture("error-401-unauthenticated");
    });
    const err = await api.me().catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(store.value?.refreshToken).toBe("old-refresh-token");
  });

  test("sign-in endpoints do not send a bearer token and a 401 there does not wipe a session", async () => {
    const { api, calls, store } = await setup(() => fromFixture("error-401-unauthenticated"));
    await api.otpVerify("+919999900000", "000000", { device_id: "d" }).catch(() => undefined);
    expect(calls[0]!.init.headers["Authorization"]).toBeUndefined();
    expect(store.value).not.toBeNull();
  });
});

describe("idempotent retry", () => {
  test("a command with an Idempotency-Key is re-sent after a network failure with identical key and body", async () => {
    let n = 0;
    const { api, calls } = await setup(() => {
      n += 1;
      if (n === 1) throw new TypeError("Failed to fetch");
      return fromFixture("decision-approved");
    });
    const cmd = { requestId: "r", societyId: "s", idempotencyKey: "idem-key-0004", body: { decision: "approve" as const, expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b14" } };
    await expect(api.decide(cmd)).resolves.toMatchObject({ status: "approved" });
    expect(calls).toHaveLength(2);
    expect(calls[1]!.init.headers["Idempotency-Key"]).toBe(calls[0]!.init.headers["Idempotency-Key"]);
    expect(calls[1]!.init.body).toBe(calls[0]!.init.body);
  });

  test("a POST WITHOUT an Idempotency-Key is never auto-retried", async () => {
    const { client, calls } = await setup(() => {
      throw new TypeError("Failed to fetch");
    });
    await expect(client.request({ method: "POST", path: "/v1/x", body: {}, schema: null })).rejects.toBeInstanceOf(NetworkError);
    expect(calls).toHaveLength(1);
  });

  test("gives up after the retry budget and reports a NetworkError (caller keeps the same command for a manual retry)", async () => {
    const { api, calls } = await setup(() => {
      throw new TypeError("Failed to fetch");
    });
    const cmd = { requestId: "r", societyId: "s", idempotencyKey: "idem-key-0005", body: { decision: "deny" as const, expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b15" } };
    await expect(api.decide(cmd)).rejects.toBeInstanceOf(NetworkError);
    expect(calls).toHaveLength(3); // 1 + 2 retries
  });

  test("a 409 is never retried", async () => {
    const { api, calls } = await setup(() => fromFixture("decision-409-already-decided"));
    await api.decide({ requestId: "r", societyId: "s", idempotencyKey: "idem-key-0006", body: { decision: "deny", expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b16" } }).catch(() => undefined);
    expect(calls).toHaveLength(1);
  });

  test("recorded fixtures were recorded from a real API (sanity: ids, no real tokens)", () => {
    const v = recorded("otp-verify").body;
    expect(v.access_token).toBe("REDACTED.ACCESS.TOKEN");
    expect(recorded("me").body.person.id).toMatch(/^[0-9a-f-]{36}$/);
  });
});
