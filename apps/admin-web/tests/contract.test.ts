import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { OPENAPI, makeAjv, validateComponent, validateResponse } from "./helpers-contract";
import { PROXY_ALLOW } from "@/server/config";
import { ERROR_CODES, errorBody } from "@/server/errors";
import { RESPONSE_SCHEMAS, type ResponseSchemaName } from "@/api/response-schemas";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => JSON.parse(readFileSync(resolve(here, "fixtures", `${name}.json`), "utf8")) as unknown;
const ajv = makeAjv();

describe("contract: recorded API responses match the schemas the UI relies on", () => {
  // Recorded from the real local backend (DWAAR_ENV=local, seeded dataset); regenerate with scripts documented in tests/fixtures/README.
  const names = readdirSync(resolve(here, "fixtures")).filter((f) => f.endsWith(".json") && !f.startsWith("error")).map((f) => f.replace(".json", ""));
  for (const name of Object.keys(RESPONSE_SCHEMAS) as ResponseSchemaName[]) {
    it(`${name}`, () => {
      expect(names).toContain(name);
      const r = validateResponse(ajv, name, fixture(name));
      expect(r.errors).toBe("");
      expect(r.ok).toBe(true);
    });
  }

  it("recorded error bodies validate against the OpenAPI ErrorBody schema", () => {
    for (const f of ["error403", "error404"]) {
      const r = validateComponent(ajv, "ErrorBody", fixture(f));
      expect(r.errors).toBe("");
    }
  });

  it("BFF-originated errors validate against ErrorBody too", () => {
    for (const code of ERROR_CODES) expect(validateComponent(ajv, "ErrorBody", errorBody(code)).ok, code).toBe(true);
  });

  it("the schemas actually fail on a wrong shape (the check has teeth)", () => {
    expect(validateResponse(ajv, "devices", { items: [{ id: 1 }] }).ok).toBe(false);
    expect(validateResponse(ajv, "gatePolicy", { ...(fixture("gatePolicy") as object), auto_allow_on_timeout: true }).ok).toBe(false);
  });
});

describe("contract: request bodies the console sends validate against OpenAPI components", () => {
  const cases: [string, unknown][] = [
    ["DeviceDecision", { decision: "approve", expected_version: 1 }],
    ["DeviceDecision", { decision: "reject", expected_version: 3, reason: "Not our device" }],
    ["DeviceRevoke", { expected_version: 2, reason: "Lost at the gate" }],
    ["ExceptionTransition", { action: "start_review", expected_version: 1 }],
    ["ExceptionTransition", { action: "resolve", expected_version: 2, note: "Checked CCTV" }],
    ["PolicyPut", { expected_version: 1, approval_expiry_seconds: 120, overstay_minutes: { delivery: 25 } }],
    ["CodeIn", { code: "123456" }],
    ["RefreshIn", { refresh_token: "x".repeat(40) }],
  ];
  for (const [name, body] of cases) {
    it(`${name} ${JSON.stringify(body).slice(0, 50)}`, () => {
      const r = validateComponent(ajv, name, body);
      expect(r.errors).toBe("");
    });
  }

  it("rejects what the server would reject", () => {
    expect(validateComponent(ajv, "DeviceDecision", { decision: "maybe", expected_version: 1 }).ok).toBe(false);
    expect(validateComponent(ajv, "CodeIn", { code: "12" }).ok).toBe(false);
  });
});

describe("contract: the BFF allow-list only names routes that exist in the OpenAPI file", () => {
  const spec = Object.entries(OPENAPI.paths).flatMap(([p, ops]) => Object.keys(ops).map((m) => ({ m: m.toUpperCase(), regex: new RegExp(`^${p.replace(/\{[^}]+\}/g, "[^/]+")}$`) })));
  const uuid = "019b76da-a800-713c-a879-90fe5f48356e";
  const concrete = (re: RegExp) => {
    // turn each allow-list regex into one concrete path by hand-rolled substitution of its alternations
    let s = re.source.replace(/^\^|\$$/g, "").replace(/\\\//g, "/").replace(/\[0-9a-f-\]\{36\}/g, uuid);
    s = s.replace(/\(([^()]+)\)/g, (_m, alt: string) => alt.split("|")[0]!);
    return s;
  };
  it("every allowed (method, path) is a real API operation", () => {
    for (const rule of PROXY_ALLOW) {
      const path = concrete(rule.pattern);
      expect(spec.some((s) => s.m === rule.method && s.regex.test(path)), `${rule.method} ${path}`).toBe(true);
    }
  });
});
