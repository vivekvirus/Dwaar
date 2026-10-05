import Ajv from "ajv";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { RESPONSE_SCHEMAS, type ResponseSchemaName } from "../src/api/response-schemas";

export const OPENAPI = JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../../packages/contracts/openapi/dwaar.v1.json"), "utf8")) as {
  paths: Record<string, Record<string, unknown>>;
  components: { schemas: Record<string, unknown> };
};

export function makeAjv() {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  ajv.addSchema({ $id: "openapi", ...OPENAPI } as object);
  return ajv;
}

/** Validate a value against a named OpenAPI component schema (request bodies, ErrorBody). */
export function validateComponent(ajv: Ajv, name: string, value: unknown): { ok: boolean; errors: string } {
  const validate = ajv.compile({ $ref: `openapi#/components/schemas/${name}` });
  const ok = validate(value) as boolean;
  return { ok, errors: ok ? "" : ajv.errorsText(validate.errors) };
}

export function validateResponse(ajv: Ajv, name: ResponseSchemaName, value: unknown): { ok: boolean; errors: string } {
  const validate = ajv.compile(RESPONSE_SCHEMAS[name] as object);
  const ok = validate(value) as boolean;
  return { ok, errors: ok ? "" : ajv.errorsText(validate.errors) };
}
