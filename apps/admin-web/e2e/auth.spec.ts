import { expect, test } from "@playwright/test";
import { PHONES } from "./env";
import { totpFor } from "./fixtures";
import { alertIn, expectNoAxeViolations, shot } from "./helpers";

// REQ: IAM-03 (OTP + TOTP step-up), IAM-08, IAM-09 (HttpOnly cookies, CSRF), UX (accessibility).
test.describe("sign-in through the real UI against the real backend", () => {
  test("estate manager: phone OTP via the labelled simulator, then TOTP step-up; tokens never reach browser JS", async ({ page, context }) => {
    await page.goto("/signin");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expectNoAxeViolations(page, "sign-in (phone step)");

    await page.getByLabel("Mobile number").fill(PHONES.estateMgrMh);
    await page.getByRole("button", { name: "Send code" }).click();
    await expect(page.getByLabel("One-time code")).toBeFocused(); // focus moves to the new step
    await expect(page.getByText(/Local simulator \(simulation=true\)/)).toBeVisible();
    await expectNoAxeViolations(page, "sign-in (OTP step)");
    await page.getByRole("button", { name: "Fill in the simulator code" }).click();
    await page.getByRole("button", { name: "Verify" }).click();

    // elevated role: the console is NOT reachable on the OTP alone
    await expect(page.getByLabel("6-digit code")).toBeFocused();
    await page.goto("/overview");
    await expect(page).toHaveURL(/\/signin\?step=mfa/);
    await expect(page.getByLabel("6-digit code")).toBeVisible();
    await expectNoAxeViolations(page, "sign-in (TOTP step)");

    await page.getByLabel("6-digit code").fill("000000");
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(alertIn(page)).toContainText("Please sign in to continue.");

    await page.getByLabel("6-digit code").fill(await totpFor(PHONES.estateMgrMh));
    await page.getByRole("button", { name: "Verify" }).click();
    await page.waitForURL("**/overview");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await expect(page.getByTestId("society-name")).toHaveText("Sahyadri Residency CHS (demo)");
    await shot(page, "overview-estate-manager");

    // tokens: HttpOnly cookies only, not in document.cookie / storage
    const cookies = await context.cookies();
    const at = cookies.find((c) => c.name === "dwaar_at")!;
    const rt = cookies.find((c) => c.name === "dwaar_rt")!;
    expect(at.httpOnly).toBe(true);
    expect(rt.httpOnly).toBe(true);
    expect(at.sameSite).toBe("Strict");
    expect(rt.path).toBe("/api");
    const visible = await page.evaluate(() => ({ cookie: document.cookie, ls: JSON.stringify(localStorage), ss: JSON.stringify(sessionStorage) }));
    expect(visible.cookie).not.toContain(at.value.slice(0, 20));
    expect(visible.cookie).not.toContain("dwaar_at");
    expect(visible.cookie).not.toContain("dwaar_rt");
    expect(visible.ls + visible.ss).not.toContain(at.value.slice(0, 20));
    expect(visible.cookie).toContain("dwaar_csrf"); // the non-secret double-submit value is the only readable cookie
  });

  test("CSRF: a state-changing BFF call without the double-submit header is refused, and nothing changes", async ({ page, context }) => {
    await page.goto("/signin");
    const origin = new URL(page.url()).origin;
    const noToken = await context.request.post("/api/auth/otp/request", { data: { phone: PHONES.estateMgrMh }, headers: { origin } });
    expect(noToken.status()).toBe(403);
    expect((await noToken.json()).code).toBe("not_authorised");
    const forged = await context.request.post("/api/auth/otp/request", { data: { phone: PHONES.estateMgrMh }, headers: { origin: "https://evil.example", "x-csrf-token": "0".repeat(64) } });
    expect(forged.status()).toBe(403);
  });

  test("a wrong phone/OTP is answered generically and 401 is shown through the i18n mapping", async ({ page }) => {
    await page.goto("/signin");
    await page.getByLabel("Mobile number").fill("+919999900999"); // not a seeded person
    await page.getByRole("button", { name: "Send code" }).click();
    await page.getByLabel("One-time code").fill("123456");
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(alertIn(page)).toContainText("Please sign in to continue.");
    await shot(page, "signin-error");
  });
});
