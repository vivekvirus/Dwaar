// REQ: PRD 12 (Idempotency-Key + client_action_id on approvals/commands). UUIDv7 (RFC 9562) from a CSPRNG.
import * as ExpoCrypto from "expo-crypto";

function randomBytes(n: number): Uint8Array {
  return ExpoCrypto.getRandomValues(new Uint8Array(n));
}

const HEX: string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

export function uuidv7(nowMs: number = Date.now()): string {
  const b = randomBytes(16);
  const ts = Math.floor(nowMs);
  // 48-bit big-endian millisecond timestamp
  b[0] = Math.floor(ts / 2 ** 40) & 0xff;
  b[1] = Math.floor(ts / 2 ** 32) & 0xff;
  b[2] = Math.floor(ts / 2 ** 24) & 0xff;
  b[3] = Math.floor(ts / 2 ** 16) & 0xff;
  b[4] = Math.floor(ts / 2 ** 8) & 0xff;
  b[5] = ts & 0xff;
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x70; // version 7
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80; // RFC variant
  const h = Array.from(b, (x) => HEX[x]!).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Matches ^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$ of the OpenAPI Idempotency-Key header. */
export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$/;

export function newIdempotencyKey(): string {
  return uuidv7();
}

export function newClientActionId(): string {
  return uuidv7();
}
