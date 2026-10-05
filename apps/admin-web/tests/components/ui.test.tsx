import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { CountChart } from "@/components/ui/count-chart";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Modal } from "@/components/ui/dialog";
import { ErrorAlert } from "@/components/ui/error-alert";
import { ApiCallError } from "@/lib/api-client";
import { I18nProvider } from "@/i18n/provider";

const readBlob = (b: Blob) => new Promise<string>((res) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.readAsText(b); });
const wrap = (ui: React.ReactElement) => render(<I18nProvider>{ui}</I18nProvider>);

type Row = { id: string; name: string };
const cols: Column<Row>[] = [{ id: "n", header: "Name", cell: (r) => <button>{`open ${r.name}`}</button>, csv: (r) => r.name }];
const rows: Row[] = [{ id: "1", name: "one" }, { id: "2", name: "two" }, { id: "3", name: "three" }];

describe("DataTable (compact, keyboard-navigable, cursor pagination)", () => {
  it("moves focus between rows with the arrow keys, Home and End", async () => {
    wrap(<DataTable caption="Rows" columns={cols} rows={rows} rowKey={(r) => r.id} empty="none" />);
    const trs = screen.getAllByRole("row").slice(1);
    trs[0]!.focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(document.activeElement).toBe(trs[1]);
    await userEvent.keyboard("{ArrowDown}{ArrowDown}");
    expect(document.activeElement).toBe(trs[2]);
    await userEvent.keyboard("{ArrowUp}");
    expect(document.activeElement).toBe(trs[1]);
    await userEvent.keyboard("{Home}");
    expect(document.activeElement).toBe(trs[0]);
    await userEvent.keyboard("{End}");
    expect(document.activeElement).toBe(trs[2]);
  });

  it("has an accessible caption, column headers and a focusable scroll region", () => {
    wrap(<DataTable caption="Units" columns={cols} rows={rows} rowKey={(r) => r.id} empty="none" />);
    expect(screen.getByRole("table", { name: "Units" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Name" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Units" })).toHaveAttribute("tabindex", "0");
  });

  it("shows the empty text and disables export when there are no rows", () => {
    wrap(<DataTable caption="Units" columns={cols} rows={[]} rowKey={(r) => r.id} empty="Nothing here" csvName="x.csv" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /export/i })).toBeDisabled();
  });

  it("exports exactly the loaded rows as CSV", async () => {
    const created: Blob[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    vi.stubGlobal("URL", { ...URL, createObjectURL: (b: Blob) => (created.push(b), "blob:x"), revokeObjectURL: () => undefined });
    wrap(<DataTable caption="Units" columns={cols} rows={rows} rowKey={(r) => r.id} empty="" csvName="x.csv" />);
    await userEvent.click(screen.getByRole("button", { name: /export/i }));
    expect(await readBlob(created[0]!)).toBe("Name\r\none\r\ntwo\r\nthree\r\n");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("pages with Previous and Next", async () => {
    const onNext = vi.fn();
    const onPrev = vi.fn();
    wrap(<DataTable caption="Units" columns={cols} rows={rows} rowKey={(r) => r.id} empty="" page={{ index: 1, hasPrev: true, hasNext: true, onNext, onPrev }} />);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(onNext).toHaveBeenCalledOnce();
    expect(onPrev).toHaveBeenCalledOnce();
    expect(screen.getByText("Page 2")).toBeInTheDocument();
  });
});

describe("CountChart (charts always have numeric tables and exports)", () => {
  it("renders every number in a table; the bars are hidden from assistive tech", () => {
    const { container } = wrap(<CountChart title="By kind" labelHeader="Kind" valueHeader="Count" csvName="k.csv" data={[{ label: "Overstay", value: 3 }, { label: "Manual entry", value: 0 }]} />);
    const table = screen.getByRole("table", { name: "By kind" });
    expect(within(table).getByRole("row", { name: /Overstay\s*3/ })).toBeInTheDocument();
    expect(within(table).getByRole("row", { name: /Manual entry\s*0/ })).toBeInTheDocument();
    expect(container.querySelector('[aria-hidden="true"]')).not.toBeNull();
    expect(screen.getByRole("button", { name: /export/i })).toBeEnabled();
  });

  it("says so when there is nothing to chart and when a count is capped", () => {
    wrap(<CountChart title="By kind" labelHeader="Kind" valueHeader="Count" csvName="k.csv" data={[]} capped />);
    expect(screen.getByText("Nothing to show.")).toBeInTheDocument();
    expect(screen.getByText(/100\+/)).toBeInTheDocument();
  });
});

describe("Modal (confirmation dialogs, UX-05)", () => {
  it("is a labelled dialog that traps focus, closes on Escape and returns focus to the trigger", async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open it</button>
          <Modal open={open} onOpenChange={setOpen} title="Revoke device?" description="Scope and effect.">
            <button>Confirm now</button>
          </Modal>
        </>
      );
    }
    wrap(<Harness />);
    const trigger = screen.getByRole("button", { name: "Open it" });
    await userEvent.click(trigger);
    const dialog = await screen.findByRole("dialog", { name: "Revoke device?" });
    expect(dialog).toHaveAccessibleDescription("Scope and effect.");
    expect(dialog.contains(document.activeElement)).toBe(true);
    await userEvent.tab();
    await userEvent.tab();
    await userEvent.tab();
    expect(dialog.contains(document.activeElement)).toBe(true); // Tab never leaves the dialog
    fireEvent.keyDown(dialog, { key: "Escape" });
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await vi.waitFor(() => expect(document.activeElement).toBe(trigger));
  });
});

describe("ErrorAlert", () => {
  it("announces the mapped message and request id, not server text", () => {
    wrap(<ErrorAlert error={new ApiCallError(409, "stale_version", "req-9", {}, null)} />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("This item changed while you were looking at it");
    expect(alert).toHaveTextContent("req-9");
  });
});
