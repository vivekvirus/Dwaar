// Records REAL responses from a locally running API (DWAAR_ENV=local, seeded) into __tests__/fixtures/recorded/.
// Tokens and one-time codes are redacted; ids are the seed's synthetic ids. Usage: node scripts/record-fixtures.mjs [baseUrl]
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const base = (process.argv[2] ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../__tests__/fixtures/recorded");
mkdirSync(out, { recursive: true });

const save = (name, status, body) => writeFileSync(`${out}/${name}.json`, JSON.stringify({ status, body }, null, 2) + "\n");
const call = async (method, path, { token, body, headers = {} } = {}) => {
  const res = await fetch(base + path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
};
const uuid = () => crypto.randomUUID();
async function login(phone, deviceId) {
  await call("POST", "/v1/auth/otp/request", { body: { phone } });
  const otp = (await call("GET", `/v1/dev/otp?phone=${encodeURIComponent(phone)}`)).body.otp;
  return call("POST", "/v1/auth/otp/verify", { body: { phone, code: otp, device: { device_id: deviceId, label: "fixture recorder" } } });
}
const redact = (o) => ({ ...o, access_token: "REDACTED.ACCESS.TOKEN", refresh_token: "REDACTED_REFRESH_TOKEN_0000" });

const meta = await call("GET", "/v1/meta");
save("meta", meta.status, meta.body);

const resident = await login("+919999901202", `fixtures-${uuid()}`);
save("otp-verify", resident.status, redact(resident.body));
const token = resident.body.access_token;
const me = await call("GET", "/v1/me", { token });
save("me", me.status, me.body);
const home = me.body.societies[0].roles.find((r) => r.role === "owner_occ");
const S = me.body.societies[0].society_id;
const U = home.unit_id;
save("society", ...Object.values(await call("GET", `/v1/societies/${S}`, { token })));
save("unit", ...Object.values(await call("GET", `/v1/societies/${S}/units/${U}`, { token })));

const guard = await login("+919999901006", `fixtures-guard-${uuid()}`);
const gates = await call("GET", `/v1/societies/${S}/gates`, { token: guard.body.access_token });
const created = await call("POST", "/v1/approval-requests", {
  token: guard.body.access_token,
  headers: { "X-Society-Id": S, "Idempotency-Key": uuid() },
  body: { unit_id: U, visitor_alias: "Fixture Courier", gate_id: gates.body.items[0].id, destination_confirmed: true, notice: { version: "v1", language: "en", consent_given: true } },
});
const R = created.body.id;
save("approval-request-pending", 200, (await call("GET", `/v1/approval-requests/${R}`, { token, headers: { "X-Society-Id": S } })).body);
save("approval-list-pending", ...Object.values(await call("GET", `/v1/societies/${S}/approval-requests?unit_id=${U}&state=pending`, { token })));
const decide = (key, decision, version) =>
  call("POST", `/v1/approval-requests/${R}/decision`, {
    token,
    headers: { "X-Society-Id": S, "Idempotency-Key": key },
    body: { decision, expected_version: version, client_action_id: uuid(), channel: "app" },
  });
save("decision-approved", ...Object.values(await decide(uuid(), "approve", 1)));
save("decision-409-already-decided", ...Object.values(await decide(uuid(), "deny", 1)));
save("error-404-not-found", ...Object.values(await call("GET", `/v1/approval-requests/${uuid()}`, { token, headers: { "X-Society-Id": S } })));
save("error-401-unauthenticated", ...Object.values(await call("GET", "/v1/me")));

const now = new Date();
const inv = await call("POST", `/v1/societies/${S}/invitations`, {
  token,
  headers: { "Idempotency-Key": uuid() },
  body: { unit_id: U, purpose: "Fixture lunch", people_count: 2, windows: [{ start: now.toISOString(), end: new Date(now.getTime() + 3 * 3600e3).toISOString() }], max_uses: 1, with_code: true },
});
// the signature is dropped: a recorded pass must not be a usable credential, even though the key is a local dev key
save("invitation-created", inv.status, { ...inv.body, code: "000000", qr: `${inv.body.qr.split(".")[0]}.ed25519:REDACTED` });
save("invitation-list", ...Object.values(await call("GET", `/v1/societies/${S}/invitations?unit_id=${U}&state=active`, { token })));
save("unit-visits", ...Object.values(await call("GET", `/v1/societies/${S}/units/${U}/visits`, { token })));
save("invitation-revoked", ...Object.values(await call("DELETE", `/v1/invitations/${inv.body.id}`, { token, headers: { "X-Society-Id": S } })));
save("profile-updated", ...Object.values(await call("PATCH", "/v1/me/profile", { token, body: { preferred_language: "mr" } })));
console.log("recorded fixtures into", out);
