import { alertIn, expectNoAxeViolations, shot } from "./helpers";
import { expect, test } from "./pw";

// REQ: INV-01 (multi-society isolation), PRD 6 ("society selector never silently changes context"), IAM-03.
// Meera Joshi is secretary of Nandana (KA) and, by the global-setup fixture, committee member of Sahyadri (MH).
test.describe.configure({ mode: "serial" });

test("switching society is explicit and confirmed; no data of the other society is ever shown", async ({ meera: context }) => {
  const page = await context.newPage();
  const societyHeaders: string[] = [];
  page.on("request", (r) => {
    const h = r.headers()["x-dwaar-society"];
    if (r.url().includes("/api/bff/") && h) societyHeaders.push(h);
  });

  // two societies, none preselected: the person must choose
  await page.goto("/overview");
  await expect(page.getByRole("heading", { name: "Choose a society" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Main navigation" })).toHaveCount(0); // no console, no data, before choosing
  await shot(page, "society-picker");
  await expectNoAxeViolations(page, "society picker");
  // keyboard only: radio with Space, Continue with Enter
  await page.getByRole("radio", { name: /Nandana/ }).focus();
  await page.keyboard.press("Space");
  await page.getByRole("button", { name: "Continue" }).focus();
  await page.keyboard.press("Enter");
  await page.waitForURL("**/overview");
  await expect(page.getByTestId("society-selector")).toContainText("Nandana Apartments Owners Association (demo)");

  // KA data only
  await page.goto("/residents/units");
  const blockCells = page.locator("tbody tr[data-row] td:first-child");
  await expect(blockCells.first()).toBeVisible();
  const kaBlocks = new Set(await blockCells.allInnerTexts());
  expect([...kaBlocks].every((b) => b.startsWith("Tower"))).toBe(true);
  await expect(page.getByText("Bulk import of units")).toBeVisible(); // secretary in KA
  await page.goto("/security/gates");
  await expect(page.getByRole("row", { name: /Main Gate/ })).toHaveCount(0); // that gate belongs to Sahyadri
  const kaGateNames = await page.locator("tbody tr[data-row] td:first-child").allInnerTexts();
  const kaId = societyHeaders.at(-1)!;
  expect(new Set(societyHeaders).size).toBe(1); // every call so far carried the KA society

  // changing the dropdown does NOT switch; confirmation does
  const select = page.getByRole("combobox", { name: "Working in society" });
  await select.selectOption({ label: "Sahyadri Residency CHS (demo)" });
  await page.reload();
  await expect(page.getByTestId("society-selector")).toContainText("Nandana"); // nothing changed without the confirmation
  await page.getByRole("combobox", { name: "Working in society" }).selectOption({ label: "Sahyadri Residency CHS (demo)" });
  await page.getByRole("button", { name: "Switch society" }).click();
  const dialog = page.getByRole("dialog", { name: "Switch to Sahyadri Residency CHS (demo)?" });
  await expect(dialog).toContainText("show only data of the society you choose");
  await shot(page, "society-switch-dialog");
  await dialog.getByRole("button", { name: "Switch society" }).click();
  await page.waitForURL("**/overview");
  await expect(page.getByTestId("switch-banner")).toContainText("You are now working in Sahyadri Residency CHS (demo)");
  await expect(page.getByRole("combobox", { name: "Working in society" })).toHaveValue(/.+/);

  // MH data only; role is per society (committee in MH: no import panel)
  await page.goto("/residents/units");
  await expect(blockCells.first()).toBeVisible();
  const mhBlocks = new Set(await blockCells.allInnerTexts());
  expect([...mhBlocks].every((b) => ["A", "B", "C"].includes(b))).toBe(true);
  expect(await page.locator("table").innerText()).not.toContain("Tower");
  await expect(page.getByText("Bulk import of units")).toHaveCount(0);
  await page.goto("/security/gates");
  await expect(page.getByRole("row", { name: /Main Gate/ })).toBeVisible();
  for (const name of kaGateNames) await expect(page.getByRole("cell", { name, exact: true })).toHaveCount(0);
  const ids = new Set(societyHeaders);
  expect(ids.size).toBe(2);
  expect(societyHeaders.indexOf([...ids].find((i) => i !== kaId)!)).toBeGreaterThan(societyHeaders.lastIndexOf(kaId)); // the old society is never used again
  await shot(page, "society-mh-units");
  await page.close();
});

test("a stale tab cannot silently act in the other society: the BFF refuses and the page says so", async ({ meera: context }) => {
  // state after the previous test: Sahyadri selected
  const a = await context.newPage();
  await a.goto("/overview");
  await expect(a.getByTestId("society-selector")).toContainText("Sahyadri");
  const b = await context.newPage();
  await b.goto("/residents/units");
  await expect(b.locator("tbody tr[data-row]").first()).toContainText(/^(A|B|C)\d/);

  // tab A switches to Nandana
  await a.getByRole("combobox", { name: "Working in society" }).selectOption({ label: "Nandana Apartments Owners Association (demo)" });
  await a.getByRole("button", { name: "Switch society" }).click();
  await a.getByRole("dialog").getByRole("button", { name: "Switch society" }).click();
  await a.waitForURL("**/overview");
  await expect(a.getByTestId("switch-banner")).toContainText("Nandana");

  // tab B still believes it is in Sahyadri; its next request carries that claim and is refused
  await b.getByRole("link", { name: "Devices" }).click();
  await expect(alertIn(b)).toContainText("The society selected in this browser changed in another tab or window");
  await expect(b.locator("tbody tr[data-row]")).toHaveCount(0);
  await a.close();
  await b.close();
});

test("keyboard only: the society switch dialog, its focus trap and focus return", async ({ meera: context }) => {
  const p = await context.newPage();
  await p.goto("/overview"); // Nandana is selected now
  const select = p.getByRole("combobox", { name: "Working in society" });
  await select.focus();
  await select.selectOption({ label: "Sahyadri Residency CHS (demo)" });
  await expect(p.getByTestId("switch-banner")).toHaveCount(0); // the dropdown alone never switches
  await p.getByRole("button", { name: "Switch society" }).focus();
  await p.keyboard.press("Enter");
  const dialog = p.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expectNoAxeViolations(p, "society switch dialog");
  for (let i = 0; i < 6; i++) {
    await p.keyboard.press("Tab");
    expect(await p.evaluate(() => !!document.activeElement?.closest('[role="dialog"]'))).toBe(true);
  }
  await p.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(p.getByRole("button", { name: "Switch society" })).toBeFocused();
  await p.close();
});
