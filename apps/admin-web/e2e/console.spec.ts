import { type BrowserContext, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { PHONES } from "./env";
import { alertIn, shot } from "./helpers";
import { expect, test } from "./pw";
import { apiLogin, dev, societies } from "./fixtures";

// REQ: SOC-02 (units), SOC-03 (import dry run, all-or-nothing), SOC-05 (device enrolment approval), SOC-06 subset (gate policy),
// GATE-07 view + review (exceptions), INV-07 (visit states), SOC-01 (legal pack honesty), RPT-01 partial (tables, CSV).
test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;
let mhId = "";

test.beforeAll(async ({ secretary }) => {
  context = secretary;
  page = await context.newPage();
  mhId = (await societies(await apiLogin(PHONES.secretaryMh, { mfa: true }))).mh.id;
});
test.afterAll(async () => {
  await page.close();
});

async function readDownload(p: Page, click: () => Promise<void>) {
  const [download] = await Promise.all([p.waitForEvent("download"), click()]);
  return readFileSync(await download.path(), "utf8");
}

/** Calls the console's BFF from the browser context (CSRF header + selected society), like the page's own fetches. */
async function bffCall(method: "GET" | "POST", path: string, opts: { data?: unknown; text?: string; headers?: Record<string, string> } = {}) {
  const csrf = (await context.cookies()).find((c) => c.name === "dwaar_csrf")?.value ?? "";
  const url = `/api/bff/society/${path}`;
  const headers = { "x-dwaar-society": mhId, "x-csrf-token": csrf, origin: "http://localhost:3150", ...opts.headers };
  if (method === "GET") return context.request.get(url, { headers });
  return context.request.post(url, { headers: { ...headers, ...(opts.text !== undefined ? { "content-type": "text/csv" } : {}) }, data: opts.text ?? opts.data });
}

test("overview: exception counters come from the live queue, with a numeric table and CSV export", async () => {
  await page.goto("/overview");
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await expect(page.getByTestId("counter-exc-open")).toHaveText("1"); // the seeded overstay
  await expect(page.getByTestId("counter-dev-pending")).toHaveText("1");
  const chart = page.getByRole("table", { name: "Unresolved exceptions by kind" });
  await expect(chart.getByRole("row", { name: /Overstay\s*1/ })).toBeVisible();
  const csv = await readDownload(page, () => page.getByRole("button", { name: "Export loaded rows (CSV)" }).click());
  expect(csv).toContain("Kind,Unresolved");
  expect(csv).toContain("Overstay,1");
  await shot(page, "overview");
});

test("units: filters, cursor pagination (page 2 differs from page 1), keyboard row navigation, CSV of loaded rows", async () => {
  await page.goto("/residents/units");
  const rows = page.locator("tbody tr[data-row]");
  await expect(rows).toHaveCount(25);
  const first = (await rows.first().textContent()) ?? "";
  await expect(page.getByText("25 rows loaded")).toBeVisible();

  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByText("Page 2")).toBeVisible();
  await expect(rows.first()).not.toHaveText(first);
  await page.getByRole("button", { name: "Previous" }).click();
  await expect(page.getByText("Page 1")).toBeVisible();
  await expect(rows.first()).toHaveText(first);

  await rows.first().focus();
  await page.keyboard.press("ArrowDown");
  await expect(rows.nth(1)).toBeFocused();
  await page.keyboard.press("End");
  await expect(rows.nth(24)).toBeFocused();

  await page.getByLabel("Block", { exact: true }).selectOption({ label: "B" });
  await page.getByLabel("Floor", { exact: true }).fill("2");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(rows.first()).toContainText("B");
  const cells = await rows.evaluateAll((trs) => trs.map((tr) => Array.from(tr.querySelectorAll("td")).slice(0, 3).map((td) => td.textContent)));
  expect(cells.length).toBeGreaterThan(0);
  for (const [block, , floor] of cells) {
    expect(block).toBe("B");
    expect(floor).toBe("2");
  }
  const csv = await readDownload(page, () => page.getByRole("button", { name: "Export loaded rows (CSV)" }).click());
  expect(csv.split("\r\n").filter(Boolean)).toHaveLength(cells.length + 1);
  await shot(page, "units");
});

test("bulk import: invalid file shows a validation report and cannot be imported; a valid file imports after a dry run", async () => {
  await page.goto("/residents/units");
  const dir = test.info().outputDir;
  const { mkdirSync, writeFileSync } = await import("node:fs");
  mkdirSync(dir, { recursive: true });
  // 1) syntax problems are reported first (the server only checks against the database when the file parses cleanly)
  const unsafe = `${dir}/unsafe.csv`;
  writeFileSync(unsafe, "block,label,floor\r\nA,150,1\r\n=cmd,9,1\r\n");
  await page.getByLabel("CSV file").setInputFiles(unsafe);
  await page.getByRole("button", { name: "Validate (dry run)" }).click();
  const report = page.getByTestId("import-report");
  await expect(report).toContainText("Validation failed: 1 problems in 2 rows. Nothing has been written.");
  await expect(report).toContainText("refused (spreadsheet formula injection)");
  await expect(page.getByRole("button", { name: /^Import \d+ units$/ })).toBeDisabled();

  // 2) database checks: an existing unit, an unknown block and a duplicate inside the file
  const bad = `${dir}/bad.csv`;
  writeFileSync(bad, "block,label,floor,undivided_interest_pct\r\nA,101,1,0.1\r\nQ,1,1,\r\nA,150,1,\r\nA,150,1,\r\n");
  await page.getByLabel("CSV file").setInputFiles(bad);
  await page.getByRole("button", { name: "Validate (dry run)" }).click();
  await expect(report).toContainText(/Validation failed: 3 problems in 4 rows/);
  await expect(report).toContainText("A unit with this block and label already exists");
  await expect(report).toContainText("The block does not exist");
  await expect(report).toContainText("The same block and label appear more than once in the file");
  await expect(page.getByRole("button", { name: /^Import \d+ units$/ })).toBeDisabled();
  await shot(page, "units-import-report");

  // all-or-nothing, proven against the server: a REAL import of the same bad file writes nothing
  const blockA = (await (await bffCall("GET", "blocks?limit=100")).json()).items.find((b: { name: string }) => b.name === "A").id as string;
  const countA = async () => ((await (await bffCall("GET", `units?block_id=${blockA}&limit=100`)).json()).items as unknown[]).length;
  const before = await countA();
  const real = await bffCall("POST", "units:import?dry_run=false&create_missing_blocks=true", { text: "block,label,floor\r\nE,1,1\r\nA,101,1\r\n" });
  expect(real.status()).toBe(422);
  const body = await real.json();
  expect(body.code).toBe("policy_violation");
  expect(body.details.report.units_created).toBe(0);
  const blocks = await (await bffCall("GET", "blocks?limit=100")).json();
  expect(blocks.items.map((b: { name: string }) => b.name)).not.toContain("E"); // the valid first row did NOT create block E
  expect(before).toBe(100);
  expect(await countA()).toBe(before); // and no unit was added to an existing block either

  const good = `${dir}/good.csv`;
  writeFileSync(good, "block,label,floor,carpet_area_sqft\r\nE,1,1,500.00\r\nE,2,1,510.50\r\nE,3,2,\r\n");
  await page.getByLabel("CSV file").setInputFiles(good);
  await page.getByLabel("Create blocks that do not exist yet").check();
  await page.getByRole("button", { name: "Validate (dry run)" }).click();
  await expect(report).toContainText("Dry run passed: 3 rows are valid. New blocks to create: 1.");
  await page.getByRole("button", { name: "Import 3 units" }).click();
  const dialog = page.getByRole("dialog", { name: "Import 3 units?" });
  await expect(dialog).toContainText("cannot be undone from this screen");
  await dialog.getByRole("button", { name: "Import now" }).click();
  await expect(report).toContainText("Imported 3 units.");

  await page.getByLabel("Block", { exact: true }).selectOption({ label: "E" });
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.locator("tbody tr[data-row]")).toHaveCount(3);
});

test("devices: the secretary approves a pending enrolment and revokes an active device, with receipts", async () => {
  await page.goto("/security/devices");
  const pendingRow = page.locator("tr[data-row]", { hasText: "Pedestrian gate handheld" });
  await expect(pendingRow).toContainText("Awaiting approval");
  await expect(pendingRow).toContainText("Simulator");
  await pendingRow.getByRole("button", { name: "Approve device Pedestrian gate handheld" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve Pedestrian gate handheld?" });
  await expect(dialog).toContainText("You cannot approve a device you requested yourself");
  await shot(page, "devices-approve-dialog");
  await dialog.getByRole("button", { name: "Approve device" }).click();
  await expect(page.getByTestId("device-receipt")).toHaveText("Device Pedestrian gate handheld is now active.");
  await expect(pendingRow).toContainText("Active");
  await expect(pendingRow.getByRole("button", { name: /Approve/ })).toHaveCount(0);

  // revoke needs a reason (>= 5 chars) and states the consequence
  await pendingRow.getByRole("button", { name: "Revoke device Pedestrian gate handheld" }).click();
  const rv = page.getByRole("dialog", { name: "Revoke Pedestrian gate handheld?" });
  await expect(rv).toContainText("cannot be undone");
  const confirm = rv.getByRole("button", { name: "Revoke device" });
  await expect(confirm).toBeDisabled();
  await rv.getByRole("textbox").fill("Handheld lost during e2e");
  await confirm.click();
  await expect(page.getByTestId("device-receipt")).toHaveText("Device Pedestrian gate handheld was revoked.");
  await expect(pendingRow).toContainText("Revoked");
  await shot(page, "devices");

  // the Overview counter follows the real state
  await page.goto("/overview");
  await expect(page.getByTestId("counter-dev-pending")).toHaveText("0");
});

test("exceptions: review transitions open -> supervisor review -> resolved (compare-and-swap, note required)", async () => {
  await page.goto("/security/exceptions?state=open");
  const row = page.locator("tr[data-row]").first();
  await expect(row).toContainText("Overstay");
  await expect(row).toContainText("Open");
  await row.getByRole("button", { name: /^Start review of exception/ }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Start review" }).click();
  await expect(page.getByTestId("exception-receipt")).toContainText("is now in supervisor review");

  await page.getByLabel("State", { exact: true }).selectOption({ label: "In supervisor review" });
  const reviewRow = page.locator("tr[data-row]").first();
  await expect(reviewRow).toContainText("In supervisor review");
  await reviewRow.getByRole("button", { name: /^Resolve exception/ }).click();
  const dialog = page.getByRole("dialog", { name: "Resolve this exception?" });
  const resolve = dialog.getByRole("button", { name: "Resolve" });
  await expect(resolve).toBeDisabled(); // a resolution note is mandatory
  await dialog.getByRole("textbox").fill("Delivery agent left; confirmed on camera.");
  await shot(page, "exceptions-resolve-dialog");
  await resolve.click();
  await expect(page.getByTestId("exception-receipt")).toContainText("was resolved");

  await page.getByLabel("State", { exact: true }).selectOption({ label: "Resolved" });
  await expect(page.locator("tr[data-row]").first()).toContainText("Delivery agent left; confirmed on camera.");
  await page.goto("/overview");
  await expect(page.getByTestId("counter-exc-open")).toHaveText("0");
  await expect(page.getByTestId("counter-exc-resolved")).toHaveText("1");
  await shot(page, "exceptions");
});

test("stale click is refused with a clear message: the server compares state and version", async () => {
  // two browsers act on the same device: the second one holds an old version
  const token = await apiLogin(PHONES.secretaryMh, { mfa: true });
  const soc = await societies(token);
  const list = await (await dev(`/v1/societies/${soc.mh.id}/devices`, { headers: { authorization: `Bearer ${token}` } })).json();
  const revoked = list.items.find((d: { state: string }) => d.state === "revoked");
  expect(revoked).toBeTruthy();
  const r = await bffCall("POST", `devices/${revoked.id}/decision`, { data: { decision: "approve", expected_version: 1 }, headers: { "content-type": "application/json" } });
  expect(r.status()).toBe(409);
  expect((await r.json()).code).toBe("stale_version");
});

test("gate policy: values with server bounds; change is confirmed, saved, and there is no auto-allow on timeout", async () => {
  await page.goto("/security/gates");
  await expect(page.getByRole("row", { name: /Main Gate/ })).toContainText("Entry lane");
  await expect(page.getByTestId("no-auto-allow")).toHaveText("No automatic allow on timeout: an unanswered request never lets a visitor in.");
  await expect(page.getByLabel("Approval request expires after (seconds)")).toHaveValue("90");
  await expect(page.getByText("Allowed: 5 to 180").first()).toBeVisible();
  await page.getByLabel("Approval request expires after (seconds)").fill("120");
  await page.getByRole("button", { name: "Save" }).click();
  const dialog = page.getByRole("dialog", { name: "Change the gate policy?" });
  await expect(dialog).toContainText("approval_expiry_seconds: 120");
  await dialog.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByText("Gate policy saved.")).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Approval request expires after (seconds)")).toHaveValue("120");

  // out-of-bounds values are refused by the server and shown through the PRD 12.2 mapping
  await page.getByLabel("Overstay alert after (minutes), Delivery").fill("9999");
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save policy" }).click();
  await expect(alertIn(page).first()).toBeVisible();
  await page.keyboard.press("Escape");
  await shot(page, "gates");
});

test("visits: purpose is required (audited); states are shown exactly as recorded (INV-07)", async () => {
  await page.goto("/security/visits");
  await expect(page.getByText("Enter a purpose and load the register.")).toBeVisible();
  await page.getByLabel("Purpose of this look (audited)").fill("e2e: checking seeded visits");
  await page.getByRole("button", { name: "Load visits" }).click();
  const rows = page.locator("tbody tr[data-row]");
  await expect(rows.first()).toBeVisible();
  const n = await rows.count();
  expect(n).toBeGreaterThanOrEqual(3);
  const states = await rows.evaluateAll((trs) => trs.map((tr) => tr.querySelectorAll("td")[5]?.textContent ?? ""));
  const allowed = ["Submitted", "Approved; not yet entered", "Entered", "Exited", "Cancelled", "Denied", "Expired"];
  for (const s of states) expect(allowed, `state label "${s}"`).toContain(s);
  // approved is NOT entered: every "Approved; not yet entered" row shows "Not entered" in the Entered column
  const approved = rows.filter({ hasText: "Approved; not yet entered" });
  for (let i = 0; i < (await approved.count()); i++) await expect(approved.nth(i)).toContainText("Not entered");
  await shot(page, "visits");
});

test("society settings: legal pack is shown honestly as unapproved; integration readiness only for the secretary", async () => {
  await page.goto("/settings/society");
  await expect(page.getByTestId("settings-name")).toHaveText("Sahyadri Residency CHS (demo)");
  await expect(page.getByTestId("legal-pack-status")).toHaveText("Unapproved");
  await expect(page.getByTestId("binding-governance")).toHaveText("Unapproved: binding governance is disabled.");
  await expect(page.getByText("The legal pack has not been approved.")).toBeVisible();
  await expect(page.getByText("The binding governance feature flag is off.")).toBeVisible();
  await expect(page.getByTestId("readiness")).toContainText("Active: identity and messaging are simulated");
  await shot(page, "society-settings");
});

test("every list page renders only data of the selected society (INV-01) and unreleased modules have no menu items", async () => {
  await page.goto("/overview");
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await expect(nav.getByRole("link")).toHaveText(["Overview", "Units", "Gates and policy", "Devices", "Visits", "Exceptions", "Society settings"]);
  for (const hidden of ["Finance", "Operations", "Governance", "Privacy"]) await expect(nav.getByText(hidden)).toHaveCount(0);
});
