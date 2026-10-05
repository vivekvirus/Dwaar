import { expect, test } from "@playwright/test";
import { PHONES } from "./env";
import { apiLogin, dev, societies } from "./fixtures";
import { alertIn, expectNoAxeViolations, signIn } from "./helpers";

// REQ: IAM-03 / PRD 5.2 / PRD 6 (role-specific menu), INV-01. The menu AND every route are decided by the server's /v1/me.
const MENU_FULL = ["Overview", "Units", "Gates and policy", "Devices", "Visits", "Exceptions", "Society settings"];

test("committee member: full read menu, but no import panel, no device actions, no integration readiness", async ({ browser }) => {
  const context = await browser.newContext();
  await signIn(context, PHONES.committeeMh, { mfa: true });
  const page = await context.newPage();
  await page.goto("/overview");
  await expect(page.getByRole("navigation", { name: "Main navigation" }).getByRole("link")).toHaveText(MENU_FULL);
  await page.goto("/residents/units");
  await expect(page.locator("tr[data-row]").first()).toBeVisible();
  await expect(page.getByText("Bulk import of units")).toHaveCount(0);
  await page.goto("/security/devices");
  await expect(page.getByText(/Approval and revocation are done by the secretary or the guard supervisor/)).toBeVisible();
  await expect(page.getByRole("button", { name: /^(Approve|Reject|Revoke) device/ })).toHaveCount(0);
  await page.goto("/settings/society");
  await expect(page.getByTestId("binding-governance")).toBeVisible();
  await expect(page.getByTestId("readiness")).toHaveCount(0);
  await context.close();
});

test("treasurer: finance-side menu only; security routes are refused even by typing the URL", async ({ browser }) => {
  const context = await browser.newContext();
  await signIn(context, PHONES.treasurerMh, { mfa: true });
  const page = await context.newPage();
  await page.goto("/overview");
  await expect(page.getByRole("navigation", { name: "Main navigation" }).getByRole("link")).toHaveText(["Overview", "Units", "Society settings"]);
  await expect(page.getByText(/no operational counters for your role/i)).toBeVisible();
  for (const path of ["/security/devices", "/security/gates", "/security/exceptions", "/security/visits"]) {
    await page.goto(path);
    await expect(alertIn(page).filter({ hasText: "You cannot do this action." })).toBeVisible();
    await expect(page.locator("table")).toHaveCount(0);
  }
  await context.close();
});

test("guard supervisor: security screens only, may review exceptions and approve devices, sees approval requests per gate", async ({ browser }) => {
  const context = await browser.newContext();
  await signIn(context, PHONES.guardSupMh, { mfa: true });
  const page = await context.newPage();
  await page.goto("/overview");
  await expect(page.getByRole("navigation", { name: "Main navigation" }).getByRole("link")).toHaveText(["Overview", "Gates and policy", "Devices", "Visits", "Exceptions"]);
  await page.goto("/residents/units");
  await expect(alertIn(page).filter({ hasText: "You cannot do this action." })).toBeVisible();
  await page.goto("/settings/society");
  await expect(alertIn(page).filter({ hasText: "You cannot do this action." })).toBeVisible();

  await page.goto("/security/visits");
  // the supervisor sees active visits of ONE gate, masked, with no purpose field (guard audience)
  await expect(page.getByLabel("Purpose of this look (audited)")).toHaveCount(0);
  await page.getByLabel("Gate", { exact: true }).first().selectOption({ label: "Main Gate" });
  await page.getByRole("button", { name: "Load visits" }).click();
  await expect(page.getByText("Approval requests at a gate")).toBeVisible();
  await page.getByLabel("Gate", { exact: true }).last().selectOption({ label: "Main Gate" });
  await page.getByLabel("State", { exact: true }).last().selectOption({ label: "Approved" });
  const requests = page.locator('div[role="region"][aria-label="Approval requests at a gate"] tr[data-row]');
  await expect(requests.first()).toBeVisible(); // the seeded approved requests of the Main Gate
  await expect(requests.first()).toContainText("Approved");

  // the supervisor raises a fresh exception through the API (earlier specs resolved the seeded overstay), then reviews it in the UI
  const token = await apiLogin(PHONES.guardSupMh, { mfa: true });
  const soc = await societies(await apiLogin(PHONES.secretaryMh, { mfa: true })); // the supervisor role cannot list societies (BR-8)
  const raised = await dev(`/v1/societies/${soc.mh.id}/exceptions`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "idempotency-key": "e2e-supervisor-exception" },
    body: JSON.stringify({ kind: "other", reason: "E2E: visitor left a bag at the gate" }),
  });
  expect(raised.status, await raised.clone().text()).toBe(201);
  await page.goto("/security/exceptions?state=open");
  // the supervisor may review: the open exception offers Start review and Escalate (but resolve only after review)
  await expect(page.getByRole("button", { name: /^Start review of exception/ }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /^Escalate exception/ }).first()).toBeVisible();
  await context.close();
});

test("guard (no second factor): signed in, but the committee console shows nothing and every route and API call is refused", async ({ browser }) => {
  const context = await browser.newContext();
  await signIn(context, PHONES.guardMh); // OTP only: guards have no TOTP
  const page = await context.newPage();
  for (const path of ["/overview", "/residents/units", "/security/devices", "/security/exceptions", "/settings/society", "/security/gates"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { name: "No committee console access" })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main navigation" })).toHaveCount(0);
    await expect(page.locator("table")).toHaveCount(0);
  }
  await expectNoAxeViolations(page, "no console access");
  // the BFF refuses too, with the same neutral answer whatever the society, and nothing reaches the API's data
  const token = await apiLogin(PHONES.guardMh);
  const soc = await societies(token);
  const csrf = (await context.cookies()).find((c) => c.name === "dwaar_csrf")?.value ?? "";
  for (const society of [soc.mh.id, soc.ka.id]) {
    for (const path of ["units", "devices", "exceptions", "configuration"]) {
      const r = await context.request.get(`/api/bff/society/${path}`, { headers: { "x-dwaar-society": society, "x-csrf-token": csrf } });
      expect(r.status(), `${path}`).toBe(404);
      expect((await r.json()).code).toBe("not_found");
    }
  }
  // and the API itself: a guard session is refused the committee device list (403) without any role claim from the client
  const direct = await dev(`/v1/societies/${soc.mh.id}/devices`, { headers: { authorization: `Bearer ${token}` } });
  expect([403, 404]).toContain(direct.status);
  await context.close();
});

test("a resident (owner-occupier) has no console access either", async ({ browser }) => {
  const context = await browser.newContext();
  await signIn(context, PHONES.residentMh);
  const page = await context.newPage();
  await page.goto("/residents/units");
  await expect(page.getByRole("heading", { name: "No committee console access" })).toBeVisible();
  await context.close();
});

test("signed-out visitors are sent to sign-in and the BFF answers 401", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto("/security/devices");
  await expect(page).toHaveURL(/\/signin$/);
  await page.goto("/signin");
  const csrf = (await context.cookies()).find((c) => c.name === "dwaar_csrf")?.value ?? "";
  const r = await context.request.get("/api/bff/society/units", { headers: { "x-dwaar-society": "x", "x-csrf-token": csrf } });
  expect(r.status()).toBe(401);
  expect((await r.json()).code).toBe("unauthenticated");
  await context.close();
});
