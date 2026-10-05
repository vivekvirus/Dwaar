import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { API_URL, APP, PHONES, REPO, stackEnv } from "./env";

// A TOTP step is single-use, and global-setup runs in another process than the tests: remember used codes on disk.
const USED = `${APP}/e2e/.state/totp-used.json`;
const used = (): Record<string, string> => {
  try {
    return JSON.parse(readFileSync(USED, "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
};
const remember = (phone: string, code: string) => {
  mkdirSync(dirname(USED), { recursive: true });
  writeFileSync(USED, JSON.stringify({ ...used(), [phone]: code }));
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** TOTP of a SEEDED synthetic person (the secret is derived from the number by the seed tool). A code can be used once per
 *  30-second step, so a second sign-in of the same person in the same step waits for the next one. */
export async function totpFor(phone: string): Promise<string> {
  for (let attempt = 0; attempt < 3; attempt++) {
    // a code generated just before a step boundary may expire before the API checks it: start from a fresh step instead
    const remaining = 30_000 - (Date.now() % 30_000);
    if (remaining < 5_000) await sleep(remaining + 300);
    const code = execFileSync("uv", ["run", "--no-sync", "python", "tools/dev/devenv.py", "exec", "--", "python", "-m", "dwaar_api.seed", "totp", phone], {
      cwd: REPO, env: stackEnv(), encoding: "utf8",
    }).trim();
    if (used()[phone] !== code) {
      remember(phone, code);
      return code;
    }
    await sleep(30_000 - (Date.now() % 30_000) + 500);
  }
  throw new Error("could not obtain a fresh TOTP code");
}

export async function dev(path: string, init: RequestInit = {}) {
  return fetch(`${API_URL}${path}`, init);
}

export async function otpFor(phone: string): Promise<string> {
  const r = await dev(`/v1/dev/otp?phone=${encodeURIComponent(phone)}`);
  return ((await r.json()) as { otp: string }).otp;
}

/** Direct API sign-in (fixtures and contract checks only; the console itself never does this from the browser). */
// Playwright loads each spec file with its own module registry, so a fixture session is shared through a file (synthetic
// data only; removed with the stack). OTP requests are rate limited per number (3 per 5 minutes) and a session lives 15 minutes.
const TOKENS = `${APP}/e2e/.state/tokens.json`;
type TokenCache = Record<string, { token: string; at: number }>;
const readTokens = (): TokenCache => {
  try {
    return JSON.parse(readFileSync(TOKENS, "utf8")) as TokenCache;
  } catch {
    return {};
  }
};

export async function apiLogin(phone: string, opts: { mfa?: boolean } = {}): Promise<string> {
  const key = `${phone}|${opts.mfa ? "mfa" : "otp"}`;
  const hit = readTokens()[key];
  if (hit && Date.now() - hit.at < 10 * 60_000) return hit.token;
  const token = await apiLoginFresh(phone, opts);
  mkdirSync(dirname(TOKENS), { recursive: true });
  writeFileSync(TOKENS, JSON.stringify({ ...readTokens(), [key]: { token, at: Date.now() } }));
  return token;
}

async function apiLoginFresh(phone: string, opts: { mfa?: boolean }): Promise<string> {
  const req = await dev("/v1/auth/otp/request", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ phone }) });
  if (req.status !== 202) throw new Error(`otp request for ${phone} failed: ${req.status} ${await req.text()}`);
  const code = await otpFor(phone);
  const r = await dev("/v1/auth/otp/verify", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ phone, code, device: { device_id: `e2e-${randomUUID()}`, label: "e2e fixture" } }),
  });
  if (r.status !== 200) throw new Error(`otp verify for ${phone} failed: ${r.status} ${await r.text()}`);
  const token = ((await r.json()) as { access_token: string }).access_token;
  if (opts.mfa) {
    const m = await dev("/v1/auth/mfa/verify", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ code: await totpFor(phone) }),
    });
    if (m.status !== 200) throw new Error(`mfa verify failed: ${m.status} ${await m.text()} (${phone})`);
  }
  return token;
}

export async function societies(token: string): Promise<Record<"mh" | "ka", { id: string; name: string }>> {
  const r = await dev("/v1/societies", { headers: { authorization: `Bearer ${token}` } });
  const items = ((await r.json()) as { items: { id: string; name: string }[] }).items;
  const mh = items.find((s) => s.name.startsWith("Sahyadri"));
  const ka = items.find((s) => s.name.startsWith("Nandana"));
  return { mh: mh ?? { id: "", name: "" }, ka: ka ?? { id: "", name: "" } };
}

/** Fixture: the seed has no person with committee roles in two societies, so the Sahyadri secretary grants the Nandana
 *  secretary (Meera Joshi) the committee role in Sahyadri through the real role-grant API (secretary-only, MFA, reason). */
export async function grantCrossSocietyRole() {
  const token = await apiLogin(PHONES.secretaryMh, { mfa: true });
  const soc = await societies(token);
  const r = await dev(`/v1/societies/${soc.mh.id}/role-grants`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}`, "idempotency-key": "e2e-cross-society-grant" },
    body: JSON.stringify({ person_phone: PHONES.secretaryKa, role: "committee", reason: "E2E fixture: two-society committee member" }),
  });
  if (r.status !== 201 && r.status !== 200) throw new Error(`role grant fixture failed: ${r.status} ${await r.text()}`);
}
