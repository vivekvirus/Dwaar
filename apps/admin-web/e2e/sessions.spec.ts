import { expect, test } from "@playwright/test";
import { PHONES } from "./env";
import { expectNoAxeViolations, shot, signIn } from "./helpers";

// REQ: IAM-08 (device/session list, revocation), IAM-09. One person with three browsers (the OTP limit is 3 per 5 minutes).
test("session list shows every browser; revoking one signs it out at once; revoke all others leaves only this one", async ({ browser }) => {
  const mine = await browser.newContext({ viewport: { width: 1180, height: 760 } });
  const second = await browser.newContext();
  const third = await browser.newContext();
  for (const c of [second, third, mine]) await signIn(c, PHONES.committee2Mh, { mfa: true });
  const secondPage = await second.newPage();
  await secondPage.goto("/overview");
  await expect(secondPage.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();

  const page = await mine.newPage();
  await page.goto("/account/sessions");
  await expect(page.getByRole("heading", { level: 1, name: "Your sessions" })).toBeVisible();
  const rows = page.locator("tr[data-row]");
  await expect(rows).toHaveCount(3);
  await expect(page.getByText("This session")).toHaveCount(1);
  await expect(rows.first()).toContainText("Committee console (web)");
  await expectNoAxeViolations(page, "sessions");
  await shot(page, "sessions");

  // revoke ONE other session
  await page.getByRole("button", { name: /^Revoke session on/ }).first().click();
  const dialog = page.getByRole("dialog", { name: "Revoke this session?" });
  await expect(dialog).toContainText("signed out at once");
  await dialog.getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByTestId("session-receipt")).toContainText("was revoked");
  await expect(rows).toHaveCount(2);

  // the revoked browser is signed out: its access token is dead and its refresh token is refused
  await Promise.all([second, third].map(async (c) => {
    const p = await c.newPage();
    await p.goto("/overview");
    return p.url();
  })).then(async (urls) => {
    // exactly one of the two other browsers lost its session
    expect(urls.filter((u) => u.includes("/signin"))).toHaveLength(1);
  });

  // revoke all others
  await page.getByRole("button", { name: "Revoke all other sessions" }).click();
  await page.getByRole("dialog", { name: "Revoke the other sessions (1)?" }).getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByTestId("session-receipt")).toContainText("Other sessions revoked: 1");
  await expect(rows).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Revoke all other sessions" })).toBeDisabled();
  for (const c of [mine, second, third]) await c.close();
});
