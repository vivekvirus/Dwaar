import { readFileSync } from "node:fs";
import { join } from "node:path";

/** A response recorded from the real local API (scripts/record-fixtures.mjs). */
export function recorded<T = any>(name: string): { status: number; body: T } {
  return JSON.parse(readFileSync(join(__dirname, "fixtures", "recorded", `${name}.json`), "utf8"));
}

export function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

export function fromFixture(name: string, headers: Record<string, string> = {}): Response {
  const f = recorded(name);
  return jsonResponse(f.status, f.body, headers);
}
