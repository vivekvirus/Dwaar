import { IDEMPOTENCY_KEY_PATTERN, newClientActionId, newIdempotencyKey, uuidv7 } from "../src/api/ids";

describe("client ids", () => {
  test("uuidv7 has RFC 9562 shape: version 7, RFC variant, time-ordered", () => {
    const a = uuidv7(1_700_000_000_000);
    const b = uuidv7(1_700_000_000_001);
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(a.slice(0, 13) < b.slice(0, 13)).toBe(true);
  });
  test("encodes the millisecond timestamp in the first 48 bits", () => {
    const ms = 1_791_232_234_000;
    const id = uuidv7(ms).replace(/-/g, "");
    expect(parseInt(id.slice(0, 12), 16)).toBe(ms);
  });
  test("idempotency keys satisfy the OpenAPI header pattern and are unique", () => {
    const keys = new Set(Array.from({ length: 200 }, () => newIdempotencyKey()));
    expect(keys.size).toBe(200);
    for (const k of keys) expect(k).toMatch(IDEMPOTENCY_KEY_PATTERN);
  });
  test("client_action_id is a uuid (DecisionIn.client_action_id format: uuid)", () => {
    expect(newClientActionId()).toMatch(/^[0-9a-f-]{36}$/);
  });
});
