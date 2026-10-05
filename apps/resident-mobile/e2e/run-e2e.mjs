// End-to-end check of the web export against the REAL local backend (DWAAR_ENV=local, labelled simulator sign-in).
//   pnpm e2e            (from apps/resident-mobile)
// It starts postgres (if needed), applies migrations + seed, starts uvicorn, builds the web export against that API, serves it,
// drives chromium with Playwright and verifies database state with psql, then stops everything it started.
// Scenarios: A approve (+ offline retry with the same idempotency key, entry_observed stays false), B expired request,
// C already_decided race, D Hindi + server-side language, E accessibility probes (axe-core, targets, 200% reflow).
// Honest scope: this is chromium on react-native-web. It is NOT a native device/emulator or screen-reader run.
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const here = dirname(fileURLToPath(import.meta.url));
const app = resolve(here, "..");
const repo = resolve(app, "../..");
const shots = join(here, "screenshots");
const tmp = join(here, ".tmp");
const dist = join(tmp, "dist");
const require = createRequire(import.meta.url);

const API_PORT = Number(process.env.E2E_API_PORT ?? 8000);
const WEB_PORT = Number(process.env.E2E_WEB_PORT ?? 8081); // must be one of DWAAR_CORS_ORIGINS (.env.example: localhost:8081)
const API = `http://127.0.0.1:${API_PORT}`;
const WEB = `http://localhost:${WEB_PORT}`;
const RESIDENT = "+919999901201"; // Neha Patil, owner-occupier A-101, plain single-society member (synthetic)
const GUARD = "+919999901006"; // Ramesh Shinde, guard (synthetic)

let residentApi = null;
let originalLanguage = null;
let personId = null;
const ctx = {};
const results = [];
const started = { db: false };
let apiProc = null;
let webServer = null;
const step = (name, ok, detail = "") => {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) throw new Error(`assertion failed: ${name} ${detail}`);
};
const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const psql = (sql) => sh("tools/dev/pg.sh", ["psql", "-d", process.env.DWAAR_DB_NAME ?? "dwaar", "-At", "-c", sql]).trim();

// ------------------------------------------------------------------------------------------------ infrastructure
async function waitFor(fn, what, ms = 60000) {
  const t0 = Date.now();
  for (;;) {
    try {
      if (await fn()) return;
    } catch {
      /* retry */
    }
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${what}`);
    await sleep(300);
  }
}

async function startBackend() {
  const status = (() => {
    try {
      return sh("tools/dev/pg.sh", ["status"]);
    } catch {
      return "";
    }
  })();
  if (!/running|accepting/i.test(status)) {
    sh("make", ["db-up"]);
    started.db = true;
  }
  sh("make", ["migrate"]);
  sh("make", ["seed"]);
  try {
    await fetch(`${API}/healthz`);
    throw new Error(`port ${API_PORT} is already serving something; set E2E_API_PORT`);
  } catch (e) {
    if (String(e.message).includes("already serving")) throw e;
  }
  apiProc = spawn(
    "uv",
    ["run", "--no-sync", "python", "tools/dev/devenv.py", "exec", "--", "uvicorn", "dwaar_api.main:app", "--no-access-log", "--host", "127.0.0.1", "--port", String(API_PORT)],
    { cwd: repo, detached: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  let log = "";
  apiProc.stdout.on("data", (d) => (log += d));
  apiProc.stderr.on("data", (d) => (log += d));
  apiProc.on("exit", (code) => console.log(`[api exited code=${code}]\n${log.slice(-1500)}`));
  await waitFor(async () => (await fetch(`${API}/healthz`)).ok, "API health", 60000).catch((e) => {
    console.error(log);
    throw e;
  });
  const meta = await (await fetch(`${API}/v1/meta`)).json();
  step("backend up in local mode with the simulator", meta.environment === "local" && meta.simulation === true, `environment=${meta.environment} simulation=${meta.simulation}`);
}

function stopBackend() {
  if (webServer) webServer.close();
  if (apiProc?.pid) {
    try {
      process.kill(-apiProc.pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  if (started.db) {
    try {
      sh("make", ["db-down"]);
    } catch (e) {
      console.error("db-down failed", e.message);
    }
  }
}

async function buildWeb() {
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  // async on purpose: a blocked event loop leaves idle keep-alive sockets to the API half-closed (UND_ERR_SOCKET)
  await new Promise((resolveBuild, reject) => {
    const p = spawn("npx", ["expo", "export", "--platform", "web", "--output-dir", dist], {
      cwd: app,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, CI: "1", EXPO_NO_TELEMETRY: "1", EXPO_PUBLIC_API_BASE_URL: API },
    });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("exit", (code) => (code === 0 ? resolveBuild() : reject(new Error(`expo export failed (${code}): ${out.slice(-1500)}`))));
  });
  step("web export built against the local API", existsSync(join(dist, "index.html")));
}

function serveWeb() {
  const types = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json", ".ttf": "font/ttf" };
  webServer = createServer((req, res) => {
    const path = decodeURIComponent((req.url ?? "/").split("?")[0]);
    let file = join(dist, path);
    if (!file.startsWith(dist) || !existsSync(file) || statSync(file).isDirectory()) file = join(dist, "index.html"); // SPA fallback
    res.writeHead(200, { "Content-Type": types[extname(file)] ?? "application/octet-stream" });
    res.end(readFileSync(file));
  });
  return new Promise((r) => webServer.listen(WEB_PORT, "127.0.0.1", r));
}

// ------------------------------------------------------------------------------------------------ API helpers (a second device / the guard)
async function api(method, path, { token, body, headers = {} } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  }).catch((e) => {
    throw new Error(`${method} ${path} failed: ${e.cause?.code ?? e.cause ?? e.message} (api alive: ${apiProc && apiProc.exitCode === null})`);
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
async function login(phone, device) {
  for (let i = 0; i < 4; i++) {
    const r = await api("POST", "/v1/auth/otp/request", { body: { phone } });
    if (r.status !== 429) break;
    const wait = (r.body?.details?.retry_after_seconds ?? 30) + 1; // per-phone OTP token bucket (3 per 5 min): wait for the refill
    console.log(`otp rate limit for ${phone}: waiting ${wait}s`);
    await sleep(wait * 1000);
  }
  const otp = (await api("GET", `/v1/dev/otp?phone=${encodeURIComponent(phone)}`)).body.otp;
  const r = await api("POST", "/v1/auth/otp/verify", { body: { phone, code: otp, device: { device_id: device, label: "e2e second device" } } });
  if (r.status !== 200) throw new Error(`login ${phone} -> ${r.status}`);
  return r.body.access_token;
}

async function newRequest(guardToken, ctx, alias) {
  const r = await api("POST", "/v1/approval-requests", {
    token: guardToken,
    headers: { "X-Society-Id": ctx.societyId, "Idempotency-Key": crypto.randomUUID() },
    body: { unit_id: ctx.unitId, visitor_alias: alias, gate_id: ctx.gateId, destination_confirmed: true, notice: { version: "v1", language: "en", consent_given: true } },
  });
  if (r.status !== 201) throw new Error(`create request -> ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.id;
}

const row = (id) => psql(`select state||'|'||version||'|'||coalesce(closed_reason,'') from approval_requests where id='${id}'`);
const decisions = (id) => Number(psql(`select count(*) from approval_decisions where request_id='${id}'`));
const entryEvents = (id) => Number(psql(`select count(*) from access_events e join approval_requests r on r.visit_id=e.visit_id where r.id='${id}' and e.event_type='EntryObserved'`));
const visitState = (id) => psql(`select v.state from visits v join approval_requests r on r.visit_id=v.id where r.id='${id}'`);

// ------------------------------------------------------------------------------------------------ browser helpers
async function shot(page, name) {
  mkdirSync(shots, { recursive: true });
  await page.screenshot({ path: join(shots, `${name}.jpg`), type: "jpeg", quality: 60, fullPage: false, animations: "disabled" });
}

async function signIn(page, phone) {
  await page.goto(WEB, { waitUntil: "networkidle" });
  await page.getByTestId("input-phone").waitFor({ timeout: 20000 });
  const banner = page.getByTestId("simulator-banner");
  await banner.waitFor({ timeout: 10000 });
  step("sign-in shows the 'Simulator' banner", /Simulator/.test(await banner.innerText()));
  await page.getByTestId("input-phone").fill(phone);
  for (let attempt = 0; attempt < 4; attempt++) {
    await page.getByRole("button", { name: "Send code" }).click();
    const outcome = await Promise.race([
      page.getByTestId("input-code").waitFor({ timeout: 30000 }).then(() => "code"),
      page.getByText(/Too many attempts/).waitFor({ timeout: 30000 }).then(() => "limited"),
    ]);
    if (outcome === "code") break;
    const seconds = Number((await page.getByText(/Too many attempts/).innerText()).match(/(\d+) seconds/)?.[1] ?? 30) + 1;
    console.log(`otp rate limit in the UI (the app shows the retry information): waiting ${seconds}s`);
    await sleep(seconds * 1000);
  }
  await page.getByTestId("input-code").waitFor();
  await page.getByTestId("btn-sim-code").click();
  await page.waitForFunction(() => /^\d{6}$/.test(document.querySelector('[data-testid="input-code"]')?.value ?? ""));
  await shot(page, "01-sign-in-simulator");
  await page.getByRole("button", { name: "Verify and sign in" }).click();
  await page.getByTestId("screen-home").waitFor({ timeout: 20000 });
}

async function axe(page, label) {
  await page.addScriptTag({ content: readFileSync(require.resolve("axe-core/axe.min.js"), "utf8") });
  const out = await page.evaluate(async () => {
    const r = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
    return r.violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, help: v.help, where: v.nodes.slice(0, 3).map((n) => n.html.slice(0, 160)) }));
  });
  return { label, violations: out };
}

async function targets(page) {
  return page.evaluate(() => {
    const els = [...document.querySelectorAll('[role="button"],[role="tab"],[role="radio"],a[href],input,textarea')].filter((e) => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== "hidden");
    return els.map((e) => ({ role: e.getAttribute("role") ?? e.tagName.toLowerCase(), name: e.getAttribute("aria-label") ?? e.textContent?.trim().slice(0, 40), h: Math.round(e.getBoundingClientRect().height), w: Math.round(e.getBoundingClientRect().width) }));
  });
}

async function reflow(page, label) {
  const size = page.viewportSize();
  await page.setViewportSize({ width: Math.round(size.width / 2), height: size.height }); // 200% browser zoom == half the CSS width
  await sleep(400);
  const r = await page.evaluate(() => {
    const overflowing = [...document.querySelectorAll('[role="button"],[role="tab"],[role="radio"],[role="alert"],[role="header"],div,span')].filter((e) => e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflowX === "visible" && e.children.length === 0 && e.clientWidth > 0);
    return { docOverflow: document.documentElement.scrollWidth > window.innerWidth + 1, clippedText: overflowing.slice(0, 5).map((e) => e.textContent?.slice(0, 40)) };
  });
  await shot(page, label);
  await page.setViewportSize(size);
  return r;
}

// ------------------------------------------------------------------------------------------------ main
async function main() {
  rmSync(shots, { recursive: true, force: true });
  mkdirSync(shots, { recursive: true });
  await startBackend();
  await buildWeb();
  await serveWeb();

  // OTP requests are rate limited per phone (3 per 5 minutes), so the resident signs in ONCE (through the UI); the guard is
  // the only other sign-in. The resident's API calls ("another client of the same account") reuse the browser session's token.
  const guardApi = await login(GUARD, "e2e-guard-device");

  const browser = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium", args: ["--no-sandbox"] });
  const context = await browser.newContext({ viewport: { width: 390, height: 780 }, deviceScaleFactor: 1, locale: "en-IN" });
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  const tokensInStorage = async () => page.evaluate(() => ({ local: Object.keys(localStorage).filter((k) => /session|token/i.test(k)), session: Object.keys(sessionStorage).filter((k) => /session/i.test(k)) }));

  try {
    // ---- sign in through the labelled simulator
    await signIn(page, RESIDENT);
    residentApi = await page.evaluate(() => JSON.parse(sessionStorage.getItem("dwaar.session.v1")).accessToken);
    const me = (await api("GET", "/v1/me", { token: residentApi })).body;
    personId = me.person.id;
    originalLanguage = me.person.preferred_language;
    ctx.societyId = me.societies[0].society_id;
    ctx.unitId = me.societies[0].roles.find((r) => r.role === "owner_occ").unit_id;
    ctx.gateId = (await api("GET", `/v1/societies/${ctx.societyId}/gates`, { token: guardApi })).body.items[0].id;
    const header = await page.getByTestId("active-context").innerText();
    step("signed in; active household is visible in the header", /Sahyadri/.test(header) && /101/.test(header), header.replace(/\n/g, " | "));
    step("the account's server-side language (Marathi in the seed) drives the UI after sign-in", originalLanguage === "mr" && /[\u0900-\u097F]/.test(header));
    await shot(page, "02-home-marathi-from-profile");
    await page.getByTestId("tab-profile").click();
    await page.getByTestId("lang-en").click();
    await page.getByTestId("lang-saved").waitFor({ timeout: 20000 });
    step("language switched to English through the UI and saved server-side", psql(`select preferred_language from iam.persons where id='${personId}'`) === "en");
    await page.getByTestId("tab-index").click();
    await page.getByTestId("screen-home").waitFor();
    const stored = await tokensInStorage();
    step("web tokens live in sessionStorage only, never localStorage", stored.local.length === 0 && stored.session.length === 1, JSON.stringify(stored));
    await shot(page, "03-home-empty");

    // ---- A: pending request appears by polling, then approve (with an offline retry using the same idempotency key)
    const reqA = await newRequest(guardApi, ctx, "Courier A");
    await page.getByText("Courier A is at the gate").waitFor({ timeout: 20000 });
    step("a request created through the API appears on Home without reload (polling) and is pinned above quick actions", true);
    const order = await page.evaluate(() => {
      const t = document.body.innerText;
      return [t.indexOf("Waiting for your approval"), t.indexOf("Courier A is at the gate"), t.indexOf("Quick actions")];
    });
    step("pending approval is pinned at the top (UX-01)", order[0] >= 0 && order[0] < order[1] && order[1] < order[2], JSON.stringify(order));
    await shot(page, "04-home-pending-pinned");
    await page.getByTestId(`open-${reqA}`).click();
    await page.getByTestId("btn-approve").waitFor();
    const before = await page.evaluate(() => document.body.innerText);
    step("decision screen shows pending status and 'Not yet at gate / not observed'", before.includes("Waiting for your decision") && before.includes("Not yet at gate / not observed"));
    await shot(page, "05-approval-pending");

    await context.setOffline(true);
    await page.getByTestId("btn-approve").click();
    await page.getByTestId("approval-send-failed").waitFor({ timeout: 20000 });
    step("offline: the decision is reported as NOT sent and nothing was decided", /nothing was decided/.test(await page.getByTestId("approval-send-failed").innerText()) && row(reqA).startsWith("pending|1"), row(reqA));
    await shot(page, "06-approval-offline-not-sent");
    await context.setOffline(false);
    await page.getByTestId("btn-retry").click();
    await page.getByTestId("approval-closed").waitFor({ timeout: 20000 });
    const closed = await page.evaluate(() => document.body.innerText);
    step("approved: UI says 'Approved; not yet entered' and 'Not yet at gate / not observed', never 'Entered'", closed.includes("Approved; not yet entered") && closed.includes("Not yet at gate / not observed") && !/\bEntered\b/.test(closed));
    await shot(page, "07-approval-approved-not-entered");
    step("DB: request approved at version 2, exactly ONE decision row (idempotent retry), no EntryObserved event", row(reqA) === "approved|2|approved" && decisions(reqA) === 1 && entryEvents(reqA) === 0, `${row(reqA)} decisions=${decisions(reqA)} entry_events=${entryEvents(reqA)}`);
    const viaApi = (await api("GET", `/v1/approval-requests/${reqA}`, { token: residentApi, headers: { "X-Society-Id": ctx.societyId } })).body;
    step("API after approval: status approved, entry_observed false, visit authorised (not inside)", viaApi.status === "approved" && viaApi.entry_observed === false && visitState(reqA) === "authorised", visitState(reqA));

    // ---- B: stale screen on an expired request -> 409 request_expired
    const reqB = await newRequest(guardApi, ctx, "Courier B");
    await page.getByTestId("btn-back-home").click();
    await page.getByText("Courier B is at the gate").waitFor({ timeout: 20000 });
    await page.getByTestId(`open-${reqB}`).click();
    await page.getByTestId("btn-approve").waitFor();
    psql(`update approval_requests set expires_at = clock_timestamp() - interval '3 seconds' where id='${reqB}'`); // the 90 s window passes while the screen is open
    await page.getByTestId("btn-approve").click();
    await page.getByTestId("state-expired").waitFor({ timeout: 20000 });
    const exp = await page.evaluate(() => document.body.innerText);
    step("expired: UI shows expiry, 'No entry was allowed', no permission and no Approve button", exp.includes("No entry was allowed") && exp.includes("Expired") && !exp.includes("Permission valid until") && (await page.getByTestId("btn-approve").count()) === 0);
    await shot(page, "08-approval-expired-409");
    step("DB: request expired, NO decision recorded, visit not authorised, no entry", row(reqB).startsWith("expired|") && decisions(reqB) === 0 && visitState(reqB) !== "authorised" && entryEvents(reqB) === 0, `${row(reqB)} visit=${visitState(reqB)}`);

    // ---- C: another device decided first -> 409 already_decided shows the canonical result
    const reqC = await newRequest(guardApi, ctx, "Courier C");
    await page.getByTestId("btn-back-home").click();
    await page.getByText("Courier C is at the gate").waitFor({ timeout: 20000 });
    await page.getByTestId(`open-${reqC}`).click();
    await page.getByTestId("btn-approve").waitFor();
    const other = await api("POST", `/v1/approval-requests/${reqC}/decision`, {
      token: residentApi,
      headers: { "X-Society-Id": ctx.societyId, "Idempotency-Key": crypto.randomUUID() },
      body: { decision: "deny", expected_version: 1, client_action_id: crypto.randomUUID(), channel: "app" },
    });
    step("the other device's denial was accepted by the API", other.status === 200 && other.body.status === "denied");
    await page.getByTestId("btn-approve").click();
    await page.getByTestId("approval-decided-elsewhere").waitFor({ timeout: 20000 });
    const lost = await page.evaluate(() => document.body.innerText);
    step("already_decided: UI shows the OTHER device's result (Denied), not our approval", lost.includes("Already decided on another device") && lost.includes("Denied") && !lost.includes("You approved") && !lost.includes("Approved; not yet entered"));
    await shot(page, "09-approval-already-decided-409");
    step("DB: denied with exactly one decision row", row(reqC) === "denied|2|denied" && decisions(reqC) === 1, row(reqC));

    // ---- invite + QR + revoke through the real API
    await page.getByTestId("btn-back-home").click();
    await page.getByTestId("qa-invite").click();
    await page.getByTestId("input-purpose").fill("Family lunch");
    await page.getByTestId("input-plate").fill("mh12ab1234");
    await page.getByTestId("people-more").click();
    await page.getByTestId("btn-create-invite").click();
    await page.getByTestId("invite-qr").waitFor({ timeout: 20000 });
    const code = await page.getByTestId("invite-code").innerText();
    step("invitation created: signed QR rendered from the API payload and a one-time 6-digit code shown", /^\d{6}$/.test(code.trim()) && (await page.locator('[data-testid="invite-qr"] svg').count()) > 0);
    const invId = page.url().split("/").pop();
    const apiInv = (await api("GET", `/v1/societies/${ctx.societyId}/invitations/${invId}`, { token: residentApi })).body;
    step("API agrees: active, 2 people, vehicle recorded, QR payload carries opaque ids only", apiInv.state === "active" && apiInv.people_count === 2 && apiInv.vehicle_plate === "MH12AB1234" && !/phone|address/i.test(Buffer.from(apiInv.qr.split(".")[0], "base64url").toString()));
    await shot(page, "10-invite-qr");
    await page.getByTestId("btn-revoke").click();
    await page.getByTestId("revoke-confirm").waitFor();
    await page.getByTestId("btn-revoke-confirm").click();
    await page.getByTestId("invite-revoked-receipt").waitFor({ timeout: 20000 });
    await page.getByTestId("invite-qr").waitFor({ state: "detached", timeout: 20000 }); // the pass is re-read from the API after the revoke
    step("revoked: receipt shown, QR gone, DB state revoked", (await page.getByTestId("invite-qr").count()) === 0 && psql(`select state from invitations where id='${invId}'`) === "revoked");
    await shot(page, "11-invite-revoked");

    // ---- visitors history
    await page.getByTestId("btn-to-visitors").click();
    await page.getByTestId("screen-visitors").waitFor();
    await page.getByText("Courier A").first().waitFor({ timeout: 20000 });
    const vis = await page.evaluate(() => document.body.innerText);
    step("visitor history shows the approved visit as 'Approved; not yet entered' with 'Entry not observed'", vis.includes("Approved; not yet entered") && vis.includes("Entry not observed"));
    await shot(page, "12-visitors");

    // ---- D: Hindi, saved server-side
    await page.getByTestId("tab-profile").click();
    await page.getByTestId("lang-hi").click();
    await page.getByTestId("lang-saved").waitFor({ timeout: 20000 });
    step("language Hindi saved to the account (DB persons.preferred_language)", psql(`select preferred_language from iam.persons where id='${personId}'`) === "hi");
    await page.getByTestId("tab-index").click();
    await page.getByTestId("screen-home").waitFor();
    const hi = await page.evaluate(() => document.body.innerText);
    step("Hindi UI renders Devanagari copy and the unit number stays Latin", /[ऀ-ॿ]/.test(hi) && /101/.test(hi) && !/[०-९]/.test(hi));
    await shot(page, "13-home-hindi");

    // ---- E: accessibility probes on the web build
    const a11y = [];
    a11y.push(await axe(page, "home (hi)"));
    await page.getByTestId("tab-profile").click();
    await page.getByTestId("lang-en").click();
    await page.getByTestId("lang-saved").waitFor();
    await page.getByTestId("tab-index").click();
    await page.getByTestId("screen-home").waitFor();
    const reqE = await newRequest(guardApi, ctx, "Courier E");
    await page.getByText("Courier E is at the gate").waitFor({ timeout: 20000 });
    a11y.push(await axe(page, "home (en, pending)"));
    const homeTargets = await targets(page);
    await page.getByTestId(`open-${reqE}`).click();
    await page.getByTestId("btn-approve").waitFor();
    a11y.push(await axe(page, "approval (pending)"));
    const approvalTargets = await targets(page);
    const small = [...homeTargets, ...approvalTargets].filter((t) => t.h < 48 && !/^input|^textarea/.test(t.role));
    step("every button/tab/radio on Home and the decision screen is >= 48 px tall", small.length === 0, small.length ? JSON.stringify(small.slice(0, 4)) : `${homeTargets.length + approvalTargets.length} controls checked`);
    const reflowApproval = await reflow(page, "14-approval-200pct-reflow");
    step("200% browser zoom (195 px wide): no horizontal page scroll and no clipped text on the decision screen", !reflowApproval.docOverflow && reflowApproval.clippedText.length === 0, JSON.stringify(reflowApproval));
    await page.getByTestId("btn-deny").click();
    await page.getByTestId("approval-closed").waitFor({ timeout: 20000 });
    await page.getByTestId("btn-back-home").click();
    await page.getByTestId("screen-home").waitFor();
    const reflowHome = await reflow(page, "15-home-200pct-reflow");
    step("200% browser zoom: Home has no horizontal scroll", !reflowHome.docOverflow && reflowHome.clippedText.length === 0, JSON.stringify(reflowHome));
    const serious = a11y.flatMap((r) => r.violations.filter((v) => v.impact === "critical" || v.impact === "serious").map((v) => ({ ...v, label: r.label })));
    writeFileSync(join(tmp, "axe.json"), JSON.stringify(a11y, null, 2));
    console.log("axe-core violations (all impacts):", JSON.stringify(a11y.map((r) => ({ page: r.label, v: r.violations.map((v) => `${v.id}:${v.impact}:${v.nodes}`) }))));
    step("axe-core (wcag2a/aa) reports no critical or serious violations on Home and the decision screen", serious.length === 0, JSON.stringify(serious));

    step("no uncaught page errors during the run", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));

    // restore the seed's language BEFORE signing out (the token dies with the session), so the dataset stays pristine for the next run
    await api("PATCH", "/v1/me/profile", { token: residentApi, body: { preferred_language: originalLanguage } });
    step("seed language restored", psql(`select preferred_language from iam.persons where id='${personId}'`) === originalLanguage, originalLanguage);

    // ---- sign out wipes the session
    await page.getByTestId("tab-profile").click();
    await page.getByTestId("btn-sign-out").click();
    await page.getByTestId("input-phone").waitFor({ timeout: 20000 });
    step("sign out returns to sign-in and clears the stored session", (await tokensInStorage()).session.length === 0);
  } finally {
    await browser.close();
    if (personId && originalLanguage) {
      // an early failure must not leave the seed person in another language for the next run
      try {
        psql(`update iam.persons set preferred_language='${originalLanguage}' where id='${personId}'`);
      } catch {
        /* best effort */
      }
    }
  }
}

let failed = null;
try {
  await main();
} catch (e) {
  failed = e;
  console.error(String(e?.stack ?? e));
} finally {
  stopBackend();
  mkdirSync(tmp, { recursive: true });
  const summary = { date: new Date().toISOString(), passed: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length + (failed ? 1 : 0), results };
  writeFileSync(join(here, "last-run.json"), JSON.stringify(summary, null, 2) + "\n");
  console.log(`\ne2e: ${summary.passed} passed, ${summary.failed} failed (details: e2e/last-run.json)`);
  process.exit(failed ? 1 : 0);
}
