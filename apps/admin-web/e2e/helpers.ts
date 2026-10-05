import type { BrowserContext, Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { expect } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { APP } from "./env";
import { otpFor, totpFor } from "./fixtures";

/** Signs in through the console's own BFF endpoints (same as the sign-in page does), inside the browser context, so the
 *  HttpOnly cookies belong to that context. The UI path itself is covered in auth.spec.ts. */
export async function signIn(context: BrowserContext, phone: string, opts: { mfa?: boolean } = {}) {
  const page = await context.newPage();
  await page.goto("/signin");
  const csrf = (await context.cookies()).find((c) => c.name === "dwaar_csrf")?.value ?? "";
  const headers = { "x-csrf-token": csrf, "content-type": "application/json", origin: new URL(page.url()).origin };
  const req = context.request;
  let r = await req.post("/api/auth/otp/request", { data: { phone }, headers });
  expect(r.status()).toBe(202);
  r = await req.post("/api/auth/otp/verify", { data: { phone, code: await otpFor(phone) }, headers });
  expect(r.status()).toBe(200);
  if (opts.mfa) {
    r = await req.post("/api/auth/mfa", { data: { code: await totpFor(phone) }, headers });
    expect(r.status()).toBe(200);
  }
  await page.close();
}

export async function selectSocietyViaUi(page: Page, name: string) {
  await page.getByRole("radio", { name: new RegExp(name) }).check();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.waitForURL("**/overview");
}

/** Automated WCAG 2.2 AA scan (axe-core rule tags wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa). */
export async function expectNoAxeViolations(page: Page, context?: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  const summary = results.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
  expect(summary, `axe violations${context ? ` on ${context}` : ""}`).toEqual([]);
  return results.passes.length;
}

/** Small JPEG screenshots (kept in the repo as evidence of the real UI against the seeded dataset). */
export async function shot(page: Page, name: string) {
  mkdirSync(`${APP}/e2e/screenshots`, { recursive: true });
  await page.screenshot({ path: `${APP}/e2e/screenshots/${name}.jpg`, type: "jpeg", quality: 55, scale: "css" });
}

export const reachedOverview = async (page: Page) => {
  await page.goto("/overview");
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
};

/** The app's own error/alert box (Next also renders an empty route-announcer with role=alert). */
export const alertIn = (page: Page) => page.locator('[role="alert"]:not(#__next-route-announcer__)');
