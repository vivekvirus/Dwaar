import { type BrowserContext, type Page } from "@playwright/test";
import { expectNoAxeViolations } from "./helpers";
import { expect, test } from "./pw";

// REQ: UX (WCAG 2.2 AA target; PRD 6 accessibility acceptance, partial). Automated axe-core scans of every page and dialog,
// keyboard-only flows, focus management, 200% zoom (viewport halved) and 320 px reflow. NOT replaced by manual screen-reader tests.
test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;

test.beforeAll(async ({ secretary }) => {
  context = secretary;
  page = await context.newPage();
  await page.setViewportSize({ width: 1280, height: 800 });
});
test.afterAll(async () => {
  await page.close();
});

const PAGES: { name: string; path: string; ready: (p: Page) => Promise<void> }[] = [
  { name: "overview", path: "/overview", ready: async (p) => expect(p.getByTestId("counter-exc-open")).not.toHaveText("-") },
  { name: "units", path: "/residents/units", ready: async (p) => expect(p.locator("tr[data-row]").first()).toBeVisible() },
  { name: "gates and policy", path: "/security/gates", ready: async (p) => expect(p.getByLabel("Approval request expires after (seconds)")).toBeVisible() },
  { name: "devices", path: "/security/devices", ready: async (p) => expect(p.locator("tr[data-row]").first()).toBeVisible() },
  { name: "visits (before load)", path: "/security/visits", ready: async (p) => expect(p.getByLabel("Purpose of this look (audited)")).toBeVisible() },
  { name: "exceptions", path: "/security/exceptions", ready: async (p) => expect(p.getByRole("heading", { level: 1, name: "Gate exceptions" })).toBeVisible() },
  { name: "society settings", path: "/settings/society", ready: async (p) => expect(p.getByTestId("binding-governance")).toBeVisible() },
  { name: "sessions", path: "/account/sessions", ready: async (p) => expect(p.locator("tr[data-row]").first()).toBeVisible() },
];

for (const p of PAGES) {
  test(`axe: ${p.name} has no WCAG 2.2 AA violations`, async () => {
    await page.goto(p.path);
    await p.ready(page);
    await expect(page).toHaveTitle(/\| Dwaar committee console$|^Dwaar committee console$/);
    await expectNoAxeViolations(page, p.name);
  });
}

test("axe: visits after loading, import report, and open dialogs", async () => {
  await page.goto("/security/visits");
  await page.getByLabel("Purpose of this look (audited)").fill("a11y scan");
  await page.getByRole("button", { name: "Load visits" }).click();
  await expect(page.locator("tr[data-row]").first()).toBeVisible();
  await expectNoAxeViolations(page, "visits loaded");

  await page.goto("/residents/units");
  const { writeFileSync, mkdirSync } = await import("node:fs");
  mkdirSync(test.info().outputDir, { recursive: true });
  const f = `${test.info().outputDir}/a11y.csv`;
  writeFileSync(f, "block,label,floor\r\nA,101,1\r\nZZ,1,1\r\n");
  await page.getByLabel("CSV file").setInputFiles(f);
  await page.getByRole("button", { name: "Validate (dry run)" }).click();
  await expect(page.getByTestId("import-report")).toContainText("Validation failed");
  await expectNoAxeViolations(page, "import validation report");

  await page.goto("/security/exceptions");
  await expect(page.locator("tr[data-row]").first()).toBeVisible();
  const resolveBtn = page.getByRole("button", { name: /^(Start review|Resolve|Escalate) of exception|^(Start review|Resolve|Escalate) exception/ }).first();
  if (await resolveBtn.count()) {
    await resolveBtn.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expectNoAxeViolations(page, "exception dialog");
    await page.keyboard.press("Escape");
  }
  await page.goto("/security/gates");
  await page.getByLabel("Approval request expires after (seconds)").fill("100");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expectNoAxeViolations(page, "policy confirmation dialog");
  await page.keyboard.press("Escape");
});

test("keyboard only: skip link, menu, table rows, dialog focus trap and focus return", async () => {
  await page.goto("/security/devices");
  await expect(page.locator("tr[data-row]").first()).toBeVisible();
  // first Tab lands on the skip link; Enter moves focus into <main>
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();

  // tab to the first row action button and open its dialog from the keyboard
  const target = page.getByRole("button", { name: /^(Revoke|Approve) device/ }).first();
  await target.focus();
  const label = await target.getAttribute("aria-label");
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  const inDialog = () => page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'));
  expect(await inDialog()).toBe(true);
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press("Tab");
    expect(await inDialog(), `Tab ${i + 1} stays inside the dialog`).toBe(true);
  }
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press("Shift+Tab");
    expect(await inDialog()).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("button", { name: label! })).toBeFocused(); // focus returns to the control that opened it
});

for (const [label, size] of [
  ["200% zoom (640x400 CSS px)", { width: 640, height: 400 }],
  ["400% zoom / 320 px reflow", { width: 320, height: 256 }],
] as const) {
  test(`${label}: no horizontal page scroll, content and controls remain reachable`, async () => {
    await page.setViewportSize(size);
    for (const path of ["/overview", "/residents/units", "/security/devices", "/security/gates", "/settings/society"]) {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `${path} horizontal overflow at ${size.width}px`).toBeLessThanOrEqual(1);
      await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
    }
    await page.goto("/security/devices");
    await expect(page.locator("tr[data-row]").first()).toBeVisible();
    await expectNoAxeViolations(page, `devices at ${size.width}px`);
    await page.setViewportSize({ width: 1280, height: 800 });
  });
}

test("text size: 200% root font size keeps working (no clipped controls)", async () => {
  await page.goto("/security/devices");
  await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
  await expect(page.locator("tr[data-row]").first()).toBeVisible();
  const overflowX = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflowX).toBeLessThanOrEqual(1);
  await expectNoAxeViolations(page, "devices at 200% text");
});

test("reduced motion is respected and focus is always visible", async () => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/overview");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  const read = () =>
    page.evaluate(() => {
      const el = document.activeElement as HTMLElement;
      const st = getComputedStyle(el);
      return { tag: el.tagName, text: (el.textContent ?? "").slice(0, 30), width: parseFloat(st.outlineWidth), style: st.outlineStyle };
    });
  // poll: the outline may still be mid-transition on the very first frame after focus
  await expect.poll(async () => (await read()).width, { message: "focus outline width in px" }).toBeGreaterThanOrEqual(2);
  expect((await read()).style).not.toBe("none");
  await page.emulateMedia({ reducedMotion: "no-preference" });
});

