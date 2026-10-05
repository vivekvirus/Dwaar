import { defineConfig } from "@playwright/test";

// REQ: IAM-03, SOC-02/03/05/06, GATE-07 (view), UX. Runs against the REAL local backend (Postgres + FastAPI) that
// e2e/global-setup.ts starts with the repo's make targets (DWAAR_ENV=local) and stops afterwards.
export const WEB_PORT = Number(process.env.E2E_WEB_PORT ?? 3150);

export default defineConfig({
  testDir: "./e2e",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { outputFolder: "e2e/report", open: "never" }]],
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
  outputDir: "test-results",
  use: {
    baseURL: `http://localhost:${WEB_PORT}`,
    viewport: { width: 1280, height: 800 },
    launchOptions: { executablePath: "/opt/pw-browsers/chromium", args: ["--no-sandbox"] },
    trace: "off",
    screenshot: "off",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
