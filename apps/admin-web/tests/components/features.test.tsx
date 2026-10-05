import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { ImportPanel } from "@/features/units/import-panel";
import { DevicesPage } from "@/features/security/devices-page";
import { SocietySettingsPage } from "@/features/settings/society-page";
import { SignInFlow } from "@/features/auth/sign-in";
import { Shell } from "@/components/shell/shell";
import { Providers } from "@/components/providers";
import { navFor, capabilitiesFor } from "@/lib/access";
import { mockFetch, renderConsole, SOCIETY } from "./render";
import devices from "../fixtures/devices.json";
import gates from "../fixtures/gates.json";
import configuration from "../fixtures/configuration.json";

vi.mock("next/navigation", () => ({ usePathname: () => "/overview", useSearchParams: () => new URLSearchParams(), useRouter: () => ({ push: vi.fn() }) }));
vi.mock("next/link", () => ({ default: ({ href, children, ...p }: { href: string; children: React.ReactNode }) => <a href={href} {...p}>{children}</a> }));

beforeEach(() => {
  document.cookie = "dwaar_csrf=abc; path=/";
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const validReport = { dry_run: true, valid: true, rows_total: 2, rows_valid: 2, units_created: 0, blocks_created: ["E"], errors: [], errors_total: 0, errors_truncated: false };
const csvFile = (text: string) => new File([text], "units.csv", { type: "text/csv" });
Object.defineProperty(File.prototype, "text", { value: function text(this: File) { return new Promise<string>((r) => { const fr = new FileReader(); fr.onload = () => r(String(fr.result)); fr.readAsText(this); }); }, configurable: true });

describe("SOC-03 bulk import: dry run first, all-or-nothing", () => {
  it("offers Import only after a clean dry run of the same file, then imports with one idempotency key per attempt", async () => {
    const calls = mockFetch({
      "POST /api/bff/society/units:import": (c) => (c.url.includes("dry_run=true") ? { json: validReport } : { json: { ...validReport, dry_run: false, units_created: 2 } }),
    });
    renderConsole(<ImportPanel />);
    const importBtn = () => screen.getByRole("button", { name: /^Import \d+ units$/ });
    expect(importBtn()).toBeDisabled();
    await userEvent.upload(screen.getByLabelText("CSV file"), csvFile("block,label,floor\r\nE,1,1\r\nE,2,1\r\n"));
    expect(importBtn()).toBeDisabled(); // not validated yet
    await userEvent.click(screen.getByRole("button", { name: "Validate (dry run)" }));
    await screen.findByText(/Dry run passed: 2 rows are valid/);
    expect(importBtn()).toBeEnabled();
    const dry = calls[0]!;
    expect(dry.url).toContain("dry_run=true");
    expect(dry.headers["content-type"]).toBe("text/csv");
    expect(dry.headers["x-dwaar-society"]).toBe(SOCIETY);
    expect(dry.headers["x-csrf-token"]).toBe("abc");
    expect(dry.body).toBe("block,label,floor\r\nE,1,1\r\nE,2,1\r\n");

    // changing an option invalidates the dry run
    await userEvent.click(screen.getByLabelText("Create blocks that do not exist yet"));
    expect(importBtn()).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Validate (dry run)" }));
    await waitFor(() => expect(importBtn()).toBeEnabled());

    await userEvent.click(importBtn());
    const dialog = await screen.findByRole("dialog", { name: "Import 2 units?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Import now" }));
    await screen.findByText("Imported 2 units.");
    const real = calls.filter((c) => !c.url.includes("dry_run=true")).pop()!;
    expect(real.url).toContain("dry_run=false");
    expect(real.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("shows the validation report with readable problems and never offers Import for an invalid file", async () => {
    mockFetch({
      "POST /api/bff/society/units:import": () => ({
        json: { ...validReport, valid: false, rows_valid: 0, errors_total: 2, errors: [{ row: 2, field: "label", code: "already_exists" }, { row: 0, field: "undivided_interest_pct", code: "undivided_interest_total_exceeds_100" }] },
      }),
    });
    renderConsole(<ImportPanel />);
    await userEvent.upload(screen.getByLabelText("CSV file"), csvFile("block,label,floor\r\nA,101,1\r\n"));
    await userEvent.click(screen.getByRole("button", { name: "Validate (dry run)" }));
    await screen.findByText(/Validation failed: 2 problems in 2 rows\. Nothing has been written\./);
    expect(screen.getByRole("button", { name: /^Import \d+ units$/ })).toBeDisabled();
    expect(screen.getByText(/A unit with this block and label already exists/)).toBeInTheDocument();
    expect(screen.getByText("Whole file")).toBeInTheDocument();
    expect(screen.getByText(/exceed 100 percent/)).toBeInTheDocument();
  });

  it("when the server rejects the real import (422 policy_violation with a report) it says NOTHING was written", async () => {
    const report = { ...validReport, dry_run: false, valid: false, rows_valid: 0, errors_total: 1, errors: [{ row: 2, field: "label", code: "duplicate_in_file" }] };
    mockFetch({
      "POST /api/bff/society/units:import": (c) =>
        c.url.includes("dry_run=true") ? { json: validReport } : { status: 422, json: { request_id: "r", code: "policy_violation", message: "", message_key: "errors.policy_violation", details: { reason: "import_validation_failed", report } } },
    });
    renderConsole(<ImportPanel />);
    await userEvent.upload(screen.getByLabelText("CSV file"), csvFile("block,label,floor\r\nE,1,1\r\n"));
    await userEvent.click(screen.getByRole("button", { name: "Validate (dry run)" }));
    await userEvent.click(await screen.findByRole("button", { name: /^Import 2 units$/ }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Import now" }));
    await screen.findByText("Nothing was imported: the whole file was rejected.");
  });
});

describe("devices: approve, reject, revoke (SOC-05 subset)", () => {
  it("states scope and effect first, sends expected_version, and ends with a receipt", async () => {
    const pending = devices.items.find((d) => d.state === "pending_approval")!;
    const calls = mockFetch({
      "GET /api/bff/society/devices": () => ({ json: devices }),
      "GET /api/bff/society/gates": () => ({ json: gates }),
      [`POST /api/bff/society/devices/${pending.id}/decision`]: () => ({ json: { ...pending, state: "active" } }),
    });
    renderConsole(<DevicesPage />);
    await userEvent.click(await screen.findByRole("button", { name: `Approve device ${pending.name}` }));
    const dialog = await screen.findByRole("dialog", { name: `Approve ${pending.name}?` });
    expect(dialog).toHaveTextContent(/You cannot approve a device you requested yourself/);
    await userEvent.click(within(dialog).getByRole("button", { name: "Approve device" }));
    await screen.findByTestId("device-receipt");
    const post = calls.find((c) => c.method === "POST")!;
    expect(JSON.parse(post.body!)).toEqual({ decision: "approve", expected_version: pending.version });
    expect(post.headers["idempotency-key"]).toBeTruthy();
  });

  it("requires a reason to reject and explains maker-checker refusals", async () => {
    const pending = devices.items.find((d) => d.state === "pending_approval")!;
    mockFetch({
      "GET /api/bff/society/devices": () => ({ json: devices }),
      "GET /api/bff/society/gates": () => ({ json: gates }),
      [`POST /api/bff/society/devices/${pending.id}/decision`]: () => ({ status: 422, json: { request_id: "req-mc", code: "policy_violation", message: "x", message_key: "errors.policy_violation", details: { reason: "maker_checker" } } }),
    });
    renderConsole(<DevicesPage />);
    await userEvent.click(await screen.findByRole("button", { name: `Reject device ${pending.name}` }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Reject enrolment" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox"), "Unknown hardware");
    await userEvent.click(confirm);
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("not allowed by the current rules");
    expect(alert).toHaveTextContent(/different person/);
  });

  it("read-only roles see status but no action buttons", async () => {
    mockFetch({ "GET /api/bff/society/devices": () => ({ json: devices }), "GET /api/bff/society/gates": () => ({ json: gates }) });
    renderConsole(<DevicesPage />, ["committee"]);
    await screen.findByText(devices.items[0]!.name);
    expect(screen.queryByRole("button", { name: /^Approve device/ })).toBeNull();
    expect(screen.getByText(/Approval and revocation are done by the secretary or the guard supervisor/)).toBeInTheDocument();
  });
});

describe("society settings tell the truth about the legal pack (INV-10)", () => {
  it("shows 'unapproved: binding governance is disabled' and the blockers", async () => {
    mockFetch({ "GET /api/bff/society/configuration": () => ({ json: configuration }), "GET /api/bff/v1/meta": () => ({ json: { service: "dwaar_api", version: "0.1.0", api_version: "v1", environment: "local", simulation: true } }) });
    renderConsole(<SocietySettingsPage />);
    expect(await screen.findByTestId("binding-governance")).toHaveTextContent("Unapproved: binding governance is disabled.");
    expect(screen.getByTestId("legal-pack-status")).toHaveTextContent("Unapproved");
    expect(screen.getByText("The legal pack has not been approved.")).toBeInTheDocument();
  });

  it("shows integration readiness to the secretary only", async () => {
    mockFetch({ "GET /api/bff/society/configuration": () => ({ json: configuration }), "GET /api/bff/v1/meta": () => ({ json: { service: "dwaar_api", version: "0.1.0", api_version: "v1", environment: "local", simulation: true } }) });
    const sec = renderConsole(<SocietySettingsPage />, ["secretary"]);
    expect(await screen.findByTestId("readiness")).toHaveTextContent(/Active: identity and messaging are simulated/);
    sec.unmount();
    renderConsole(<SocietySettingsPage />, ["committee"]);
    await screen.findByTestId("binding-governance");
    expect(screen.queryByTestId("readiness")).toBeNull();
    expect(screen.queryByText("Integration readiness")).toBeNull();
  });
});

describe("sign-in flow (IAM-03)", () => {
  it("asks for the OTP, then the TOTP for elevated roles, and never handles a token", async () => {
    const assign = vi.fn();
    Object.defineProperty(window, "location", { value: { assign }, writable: true });
    let sessionCalls = 0;
    const calls = mockFetch({
      "GET /api/session": () => (++sessionCalls < 2 ? { json: { authenticated: false } } : { json: { authenticated: true, stepUpRequired: true, mfa: { enrolled: true, confirmed: true, sessionVerified: false } } }),
      "POST /api/auth/otp/request": () => ({ status: 202, json: { ok: true } }),
      "GET /api/auth/dev-otp": () => ({ json: { otp: "424242", simulation: true } }),
      "POST /api/auth/otp/verify": () => ({ json: { ok: true } }),
      "POST /api/auth/mfa": () => ({ json: { session_elevated: true } }),
    });
    render(<Providers><SignInFlow /></Providers>);
    await userEvent.type(await screen.findByLabelText("Mobile number"), "+919999901001");
    await userEvent.click(screen.getByRole("button", { name: "Send code" }));
    await screen.findByText(/Local simulator \(simulation=true\)/);
    await userEvent.click(screen.getByRole("button", { name: "Fill in the simulator code" }));
    expect(screen.getByLabelText("One-time code")).toHaveValue("424242");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    const totp = await screen.findByLabelText("6-digit code");
    expect(totp).toHaveFocus();
    await userEvent.type(totp, "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/overview"));
    expect(calls.find((c) => c.url === "/api/auth/mfa")!.body).toBe(JSON.stringify({ code: "123456" }));
    for (const c of calls) expect(c.body ?? "").not.toMatch(/access_token|refresh_token/);
  });

  it("shows the mapped error for a wrong code and keeps the user on the step", async () => {
    mockFetch({
      "GET /api/session": () => ({ json: { authenticated: false } }),
      "POST /api/auth/otp/request": () => ({ status: 202, json: { ok: true } }),
      "GET /api/auth/dev-otp": () => ({ status: 404, json: { request_id: "r", code: "not_found", message: "", message_key: "errors.not_found", details: {} } }),
      "POST /api/auth/otp/verify": () => ({ status: 401, json: { request_id: "req-401", code: "unauthenticated", message: "", message_key: "errors.unauthenticated", details: {} } }),
    });
    render(<Providers><SignInFlow /></Providers>);
    await userEvent.type(await screen.findByLabelText("Mobile number"), "+919999901001");
    await userEvent.click(screen.getByRole("button", { name: "Send code" }));
    await userEvent.type(await screen.findByLabelText("One-time code"), "111111");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Please sign in to continue.");
    expect(screen.queryByText(/Local simulator/)).toBeNull(); // simulator code is hidden when the BFF says it is closed
  });
});

describe("society selector never silently changes context (PRD 6)", () => {
  const societies = [
    { id: SOCIETY, name: "Sahyadri Residency CHS (demo)", city: "Pune", roles: ["secretary"], consoleAccess: true, stepUpPending: false },
    { id: "019b76da-a800-7bbb-b000-000000000002", name: "Nandana Apartments", city: "Bengaluru", roles: ["committee"], consoleAccess: true, stepUpPending: false },
  ];
  const caps = capabilitiesFor(["secretary"]);
  const shell = () =>
    render(
      <Providers>
        <Shell person={{ displayName: "Test Person" }} simulation societies={societies} selectedSocietyId={SOCIETY} capabilities={caps} nav={navFor(caps)}>
          <p>page body</p>
        </Shell>
      </Providers>,
    );

  it("changing the dropdown alone does nothing; the switch needs a confirmation dialog and an explicit POST", async () => {
    const calls = mockFetch({ "POST /api/session/society": () => ({ json: { authenticated: true } }) });
    const assign = vi.fn();
    Object.defineProperty(window, "location", { value: { assign }, writable: true });
    shell();
    const select = screen.getByRole("combobox", { name: "Working in society" });
    await userEvent.selectOptions(select, "019b76da-a800-7bbb-b000-000000000002");
    expect(calls).toHaveLength(0);
    expect(assign).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Switch society" }));
    const dialog = await screen.findByRole("dialog", { name: "Switch to Nandana Apartments?" });
    expect(dialog).toHaveTextContent(/only data of the society you choose/);
    await userEvent.click(within(dialog).getByRole("button", { name: "Switch society" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/overview"));
    expect(JSON.parse(calls[0]!.body!)).toEqual({ society_id: "019b76da-a800-7bbb-b000-000000000002", confirm: true });
    expect(calls[0]!.headers["x-csrf-token"]).toBe("abc");
  });

  it("shows the working society, a skip link, landmarks and only permitted menu items", () => {
    shell();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveAttribute("href", "#main");
    expect(screen.getByRole("navigation", { name: "Main navigation" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveTextContent("page body");
    expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("link", { name: /finance|governance|privacy|operations/i })).toBeNull();
    expect(screen.getByText(/Local simulation/)).toBeInTheDocument();
  });
});
