// REQ: PRD 12 contract. Validates (a) every request the client builds against the OpenAPI request schemas, (b) recorded real
// responses against the OpenAPI response schemas and status codes, (c) that every operation the client calls exists in the
// spec with its required headers/params, (d) that the generated types are current. Ajv 2020-12 (OpenAPI 3.1 = JSON Schema).
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { ApiClient } from "../src/api/client";
import { createApi } from "../src/api/endpoints";
import { SessionManager } from "../src/auth/session";
import { MemoryTokenStore } from "../src/auth/tokenStore";
import { createDecisionCommand } from "../src/state/approvalFlow";
import { buildInvitationBody } from "../src/screens/InviteNewScreen";
import { ApprovalRequestSchema } from "../src/domain/types";
import { recorded } from "./fixtures";

const specPath = join(__dirname, "../../../packages/contracts/openapi/dwaar.v1.json");
const spec = JSON.parse(readFileSync(specPath, "utf8"));

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
ajv.addSchema(spec, "openapi");
const schemaOf = (name: string) => {
  const v = ajv.getSchema(`openapi#/components/schemas/${name}`);
  if (!v) throw new Error(`schema ${name} not in spec`);
  return v;
};
const expectValid = (name: string, value: unknown) => {
  const v = schemaOf(name);
  const ok = v(value);
  if (!ok) throw new Error(`${name}: ${ajv.errorsText(v.errors)}`);
};

// ----------------------------------------------------------------------------------------- calls made by the client
type Recorded = { method: string; path: string; headers: Record<string, string>; query: URLSearchParams; body: any };
async function recordCalls(): Promise<Recorded[]> {
  const calls: Recorded[] = [];
  const fetchImpl = (async (url: string, init: any) => {
    const u = new URL(url);
    calls.push({ method: init.method, path: u.pathname, headers: init.headers, query: u.searchParams, body: init.body ? JSON.parse(init.body) : undefined });
    // any shape: validation errors of the response are irrelevant here, only the request matters
    return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
  const store = new MemoryTokenStore();
  store.value = { accessToken: "a-token-0000000", accessExpiresAt: Date.now() + 1e7, refreshToken: "r-token-0000000", sessionId: "s" };
  const session = new SessionManager(store, "http://x", fetchImpl);
  await session.restore();
  const api = createApi(new ApiClient({ baseUrl: "http://x", session, fetchImpl, sleep: async () => undefined }));
  const S = "019b76da-a800-713c-a879-90fe5f48356e";
  const U = "019b76da-a800-739d-a307-bbc64b8d8f4e";
  const R = "01a10dcd-d084-72d9-88f4-f25b042c6421";
  const pending = ApprovalRequestSchema.parse(recorded("approval-request-pending").body);
  const cmd = createDecisionCommand(pending, S, "approve");
  const inv = buildInvitationBody({ unitId: U, purpose: "Family lunch", alias: "Aunt", people: 3, startOffsetMin: 0, durationMin: 180, plate: "mh12ab1234", now: new Date() });
  const swallow = (p: Promise<unknown>) => p.catch(() => undefined);
  await Promise.all([
    swallow(api.meta()),
    swallow(api.otpRequest("+919999901202")),
    swallow(api.otpVerify("+919999901202", "123456", { device_id: "dev-1", label: "Dwaar resident app (web)", platform: "web" })),
    swallow(api.devOtp("+919999901202")),
    swallow(api.logout()),
    swallow(api.me()),
    swallow(api.updateProfile({ preferred_language: "hi" })),
    swallow(api.society(S)),
    swallow(api.unit(S, U)),
    swallow(api.listApprovalRequests(S, U, "pending")),
    swallow(api.getApprovalRequest(S, R)),
    swallow(api.decide({ ...cmd, requestId: R })),
    swallow(api.listInvitations(S, U)),
    swallow(api.getInvitation(S, R)),
    swallow(api.createInvitation(S, inv, "idem-key-inv-1")),
    swallow(api.revokeInvitation(S, R)),
    swallow(api.unitVisits(S, U, "cursor-1")),
  ]);
  return calls;
}

const toTemplate = (path: string): string | undefined =>
  Object.keys(spec.paths).find((tpl) => new RegExp(`^${tpl.replace(/\{[^}]+\}/g, "[^/]+")}$`).test(path));

describe("OpenAPI contract: requests the client sends", () => {
  let calls: Recorded[];
  beforeAll(async () => {
    calls = await recordCalls();
  });

  test("the client exercised every operation it owns", () => {
    expect(calls.length).toBeGreaterThanOrEqual(16);
  });

  test("every call is a documented operation (path + method)", () => {
    for (const c of calls) {
      const tpl = toTemplate(c.path);
      expect({ call: `${c.method} ${c.path}`, documented: tpl !== undefined }).toEqual({ call: `${c.method} ${c.path}`, documented: true });
      expect(spec.paths[tpl!][c.method.toLowerCase()]).toBeDefined();
    }
  });

  test("every REQUIRED header/query parameter of the operation is sent (Idempotency-Key on approvals and command creation)", () => {
    for (const c of calls) {
      const op = spec.paths[toTemplate(c.path)!][c.method.toLowerCase()];
      for (const p of op.parameters ?? []) {
        if (!p.required || p.in === "path") continue;
        if (p.in === "header") expect({ op: c.path, header: p.name, sent: c.headers[p.name] !== undefined }).toEqual({ op: c.path, header: p.name, sent: true });
        if (p.in === "query") expect({ op: c.path, query: p.name, sent: c.query.has(p.name) }).toEqual({ op: c.path, query: p.name, sent: true });
      }
    }
  });

  test("every query parameter the client sends is declared by the operation (allow-listed filters)", () => {
    for (const c of calls) {
      const op = spec.paths[toTemplate(c.path)!][c.method.toLowerCase()];
      const declared = new Set((op.parameters ?? []).filter((p: any) => p.in === "query").map((p: any) => p.name));
      for (const k of c.query.keys()) expect({ path: c.path, k, declared: declared.has(k) }).toEqual({ path: c.path, k, declared: true });
    }
  });

  test("operations that require an Idempotency-Key in the spec get a key matching its pattern", () => {
    let checked = 0;
    for (const c of calls) {
      const op = spec.paths[toTemplate(c.path)!][c.method.toLowerCase()];
      const p = (op.parameters ?? []).find((x: any) => x.name === "Idempotency-Key" && x.required);
      if (p) {
        expect(c.headers["Idempotency-Key"]).toMatch(new RegExp(p.schema.pattern));
        checked += 1;
      }
    }
    expect(checked).toBe(2); // decision + invitation create
  });

  test("request bodies validate against the OpenAPI request schemas", () => {
    const by = (m: string, suffix: string) => calls.find((c) => c.method === m && c.path.endsWith(suffix))!;
    expectValid("DecisionIn", by("POST", "/decision").body);
    expectValid("InvitationCreate", by("POST", "/invitations").body);
    expectValid("OtpRequestIn", by("POST", "/v1/auth/otp/request").body);
    expectValid("OtpVerifyIn", by("POST", "/v1/auth/otp/verify").body);
    expectValid("ProfileIn", by("PATCH", "/v1/me/profile").body);
    expectValid("RefreshIn", { refresh_token: "r-token-0000000" });
  });

  test("negative controls: the validator rejects what the server would reject", () => {
    const v = schemaOf("DecisionIn");
    expect(v({ decision: "approve", expected_version: 0, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11" })).toBe(false); // min 1
    expect(v({ decision: "maybe", expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11" })).toBe(false);
    expect(v({ decision: "approve", expected_version: 1, client_action_id: "not-a-uuid" })).toBe(false);
    expect(v({ decision: "approve", expected_version: 1, client_action_id: "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11", extra: 1 })).toBe(false);
    expect(schemaOf("InvitationCreate")({ unit_id: "019b76da-a800-739d-a307-bbc64b8d8f4e", purpose: "x", windows: [] })).toBe(false); // minItems 1
  });
});

describe("OpenAPI contract: recorded real responses", () => {
  const errors = ["decision-409-already-decided", "error-404-not-found", "error-401-unauthenticated"];
  test.each(errors)("%s validates against ErrorBody and documents a status the spec lists", (name) => {
    const { status, body } = recorded(name);
    expectValid("ErrorBody", body);
    const anyOp = spec.paths["/v1/approval-requests/{request_id}/decision"].post;
    expect(Object.keys(anyOp.responses)).toContain(String(status));
  });

  const success: Array<[string, string, string]> = [
    ["decision-approved", "/v1/approval-requests/{request_id}/decision", "post"],
    ["invitation-created", "/v1/societies/{society_id}/invitations", "post"],
    ["approval-list-pending", "/v1/societies/{society_id}/approval-requests", "get"],
    ["approval-request-pending", "/v1/approval-requests/{request_id}", "get"],
    ["me", "/v1/me", "get"],
    ["society", "/v1/societies/{society_id}", "get"],
    ["profile-updated", "/v1/me/profile", "patch"],
    ["otp-verify", "/v1/auth/otp/verify", "post"],
  ];
  test.each(success)("%s: status is documented and body satisfies the response schema", (name, path, method) => {
    const { status, body } = recorded(name);
    const op = spec.paths[path][method];
    expect(Object.keys(op.responses)).toContain(String(status));
    const schema = op.responses[String(status)].content?.["application/json"]?.schema;
    if (schema && Object.keys(schema).length > 0) {
      const v = ajv.compile({ ...schema, $defs: undefined });
      expect(v(body)).toBe(true);
    }
  });

  test("the spec leaves most 2xx bodies free-form, so the client ALSO validates them with zod (documented gap)", () => {
    const free = ["/v1/me", "/v1/approval-requests/{request_id}"].map((p) => {
      const s = spec.paths[p].get.responses["200"].content["application/json"].schema;
      return s.additionalProperties === true && s.type === "object" && !s.properties;
    });
    expect(free).toEqual([true, true]);
  });

  test("X-Society-Id is used by approval routes but is not declared in the spec (open issue reported to the API owner)", () => {
    const params = spec.paths["/v1/approval-requests/{request_id}/decision"].post.parameters.map((p: any) => p.name);
    expect(params).not.toContain("X-Society-Id");
  });
});

describe("generated types", () => {
  test("src/api/generated/schema.d.ts is current with the committed OpenAPI file", () => {
    expect(() => execFileSync("node", ["scripts/gen-api.mjs", "--check"], { cwd: join(__dirname, ".."), stdio: "pipe" })).not.toThrow();
  });
  test("a recorded fixture used above is real: the decision 200 matches PRD 12.3 keys exactly", () => {
    const f = recorded("decision-approved");
    expect(Object.keys(f.body).sort()).toEqual(["decision_id", "entry_observed", "permission_expires_at", "request_id", "status", "version"]);
    expect(f.body.entry_observed).toBe(false);
  });
});
