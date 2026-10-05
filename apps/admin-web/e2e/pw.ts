import { test as base, type BrowserContext } from "@playwright/test";
import { PHONES } from "./env";
import { signIn } from "./helpers";

// OTP requests are limited to 3 per number per 5 minutes by the API, so each persona signs in ONCE per run: worker-scoped browser
// contexts (one per persona) are shared by the specs that need them. Nothing is copied between contexts (refresh tokens rotate).
type Workers = { secretary: BrowserContext; meera: BrowserContext };

export const test = base.extend<object, Workers>({
  secretary: [
    async ({ browser }, use) => {
      const c = await browser.newContext({ viewport: { width: 1180, height: 760 } });
      await signIn(c, PHONES.secretaryMh, { mfa: true });
      await use(c);
      await c.close();
    },
    { scope: "worker" },
  ],
  meera: [
    async ({ browser }, use) => {
      const c = await browser.newContext({ viewport: { width: 1180, height: 760 } });
      await signIn(c, PHONES.secretaryKa, { mfa: true });
      await use(c);
      await c.close();
    },
    { scope: "worker" },
  ],
});
export { expect } from "@playwright/test";
