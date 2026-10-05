import { expect, test } from "@playwright/test";
import { makeAjv, validateComponent, validateResponse } from "../tests/helpers-contract";
import { PHONES } from "./env";
import { apiLogin, dev, societies } from "./fixtures";
import type { ResponseSchemaName } from "../src/api/response-schemas";

// Contract tests against the LIVE backend: every response shape the console reads is validated against src/api/response-schemas.ts,
// every error body against the OpenAPI ErrorBody schema, and request bodies against the OpenAPI request components.
const ajv = makeAjv();

test("live API responses match the shapes the console relies on", async () => {
  const sec = await apiLogin(PHONES.secretaryMh, { mfa: true });
  const sup = await apiLogin(PHONES.guardSupMh, { mfa: true });
  const { mh } = await societies(sec);
  const get = async (token: string, path: string) => {
    const r = await dev(path, { headers: { authorization: `Bearer ${token}` } });
    expect(r.status, path).toBe(200);
    return r.json();
  };
  const S = `/v1/societies/${mh.id}`;
  const gates = await get(sec, `${S}/gates`);
  const checks: [ResponseSchemaName, unknown][] = [
    ["me", await get(sec, "/v1/me")],
    ["societies", await get(sec, "/v1/societies")],
    ["units", await get(sec, `${S}/units?limit=5`)],
    ["blocks", await get(sec, `${S}/blocks`)],
    ["gates", gates],
    ["lanes", await get(sec, `${S}/gates/${gates.items[0].id}/lanes`)],
    ["devices", await get(sec, `${S}/devices`)],
    ["gatePolicy", await get(sec, `${S}/gate-policy`)],
    ["exceptions", await get(sec, `${S}/exceptions`)],
    ["visits", await get(sec, `${S}/visits?purpose=contract%20test&limit=5`)],
    ["configuration", await get(sec, `${S}/configuration`)],
    ["authSessions", await get(sec, "/v1/auth/sessions")],
    ["meta", await (await dev("/v1/meta")).json()],
    ["approvalRequests", await get(sup, `${S}/approval-requests?gate_id=${gates.items[0].id}&state=pending`)],
  ];
  for (const [name, body] of checks) {
    const r = validateResponse(ajv, name, body);
    expect(r.errors, name).toBe("");
  }
});

test("live error bodies carry request_id, a stable PRD 12.2 code, a message key and details", async () => {
  const sec = await apiLogin(PHONES.secretaryMh, { mfa: true });
  const guard = await apiLogin(PHONES.guardMh);
  const { mh } = await societies(sec);
  const S = `/v1/societies/${mh.id}`;
  const auth = (t: string, extra: Record<string, string> = {}) => ({ authorization: `Bearer ${t}`, ...extra });
  const cases: { label: string; status: number; code: string; call: () => Promise<Response> }[] = [
    { label: "400 invalid_schema", status: 400, code: "invalid_schema", call: () => dev(`${S}/units?floor=notanumber`, { headers: auth(sec) }) },
    { label: "401 unauthenticated", status: 401, code: "unauthenticated", call: () => dev("/v1/me", { headers: auth("not-a-token") }) },
    { label: "403 not_authorised", status: 403, code: "not_authorised", call: () => dev(`${S}/approval-requests`, { headers: auth(sec) }) },
    { label: "404 not_found", status: 404, code: "not_found", call: () => dev(`${S}/devices/00000000-0000-7000-8000-000000000000`, { headers: auth(sec) }) },
    {
      label: "409 stale_version", status: 409, code: "stale_version",
      call: async () => {
        const list = await (await dev(`${S}/devices`, { headers: auth(sec) })).json();
        const active = list.items.find((d: { state: string }) => d.state === "active");
        return dev(`${S}/devices/${active.id}/revoke`, { method: "POST", headers: auth(sec, { "content-type": "application/json", "idempotency-key": "contract-stale-0001" }), body: JSON.stringify({ expected_version: 1999, reason: "contract test stale version" }) });
      },
    },
    {
      label: "422 policy_violation", status: 422, code: "policy_violation",
      call: () => dev(`${S}/units:import?dry_run=false`, { method: "POST", headers: auth(sec, { "content-type": "text/csv", "idempotency-key": "contract-import-0001" }), body: "block,label,floor\r\nA,101,1\r\n" }),
    },
    { label: "403 for a guard session on a committee route", status: 403, code: "not_authorised", call: () => dev(`${S}/devices`, { headers: auth(guard) }) },
  ];
  for (const c of cases) {
    const r = await c.call();
    expect(r.status, c.label).toBe(c.status);
    const body = await r.json();
    expect(body.code, c.label).toBe(c.code);
    const v = validateComponent(ajv, "ErrorBody", body);
    expect(v.errors, c.label).toBe("");
    expect(body.message_key).toBe(`errors.${c.code}`);
  }
});

test("the request bodies the console builds are accepted by the live API (and the OpenAPI schema)", async () => {
  const sec = await apiLogin(PHONES.secretaryMh, { mfa: true });
  const { mh } = await societies(sec);
  const S = `/v1/societies/${mh.id}`;
  const policy = { expected_version: 0, approval_expiry_seconds: 90 };
  expect(validateComponent(ajv, "PolicyPut", policy).errors).toBe("");
  const cur = await (await dev(`${S}/gate-policy`, { headers: { authorization: `Bearer ${sec}` } })).json();
  const body = { expected_version: cur.version, approval_expiry_seconds: cur.approval_expiry_seconds };
  expect(validateComponent(ajv, "PolicyPut", body).errors).toBe("");
  const r = await dev(`${S}/gate-policy`, { method: "PUT", headers: { authorization: `Bearer ${sec}`, "content-type": "application/json", "idempotency-key": "contract-policy-0001" }, body: JSON.stringify(body) });
  expect(r.status).toBe(200);
});
