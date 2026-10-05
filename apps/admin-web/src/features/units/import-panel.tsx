"use client";
import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type ChangeEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { Modal } from "@/components/ui/dialog";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Input, Label } from "@/components/ui/input";
import { ApiCallError, newIdempotencyKey } from "@/lib/api-client";
import { downloadCsv } from "@/lib/csv";
import { useSocietyApi } from "@/lib/society-api";
import type { ImportReport } from "@/api/types";
import { useT } from "@/i18n/provider";
import type { MessageKey } from "@/i18n";

const MAX_BYTES = 1_500_000;
const TEMPLATE = "block,label,floor,carpet_area_sqft,builtup_area_sqft,undivided_interest_pct,construction_cost_paise\r\nA,101,1,675.00,810.00,0.400000,405000000\r\n";

// Error codes of the import validator (organisation/imports.py). Unknown codes fall back to the raw code.
export const IMPORT_CODES = [
  "already_exists", "block_archived", "builtup_area_below_carpet_area", "column_count", "conflict_retry", "control_characters",
  "duplicate_column", "duplicate_in_file", "empty_file", "floor_exceeds_block_floors", "invalid_integer", "invalid_integer_paise",
  "invalid_number", "malformed_csv", "missing_column", "nul_byte", "out_of_range", "too_large", "too_long", "too_many_decimals",
  "too_many_rows", "undivided_interest_total_exceeds_100", "unknown_block", "unknown_column", "unsafe_cell",
] as const;

type Loaded = { name: string; text: string };
type Run = { report: ImportReport; mode: "dry" | "real"; fileText: string; createBlocks: boolean };

async function sha(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** SOC-03: dry-run and validation report with ALL-OR-NOTHING semantics. "Import" is only offered for a file that has just
 *  passed a dry run unchanged; the server validates again and writes nothing if even one row is wrong. */
export function ImportPanel() {
  const t = useT();
  const api = useSocietyApi();
  const qc = useQueryClient();
  const [file, setFile] = useState<Loaded | null>(null);
  const [createBlocks, setCreateBlocks] = useState(false);
  const [run, setRun] = useState<Run | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const keys = useRef(new Map<string, string>());

  async function onFile(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    setRun(null);
    setError(null);
    if (!f) return setFile(null);
    if (f.size > MAX_BYTES) {
      setFile(null);
      return setError(new ApiCallError(400, "invalid_schema", null, {}, null));
    }
    setFile({ name: f.name, text: await f.text() });
  }

  async function submit(mode: "dry" | "real") {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      // the same file + options + mode reuse ONE idempotency key, so a retry after a dropped connection cannot import twice
      const k = `${mode}:${createBlocks}:${await sha(file.text)}`;
      const idem = keys.current.get(k) ?? newIdempotencyKey();
      keys.current.set(k, idem);
      const report = await api.send<ImportReport>("POST", "units:import", {
        text: file.text,
        query: { dry_run: mode === "dry", create_missing_blocks: createBlocks },
        idempotencyKey: idem,
      });
      setRun({ report, mode, fileText: file.text, createBlocks });
      if (mode === "real") {
        keys.current.delete(k);
        await qc.invalidateQueries({ queryKey: [api.societyId] });
      }
    } catch (e) {
      const rep = e instanceof ApiCallError && e.code === "policy_violation" ? (e.details.report as ImportReport | undefined) : undefined;
      if (rep) setRun({ report: rep, mode, fileText: file.text, createBlocks });
      else setError(e);
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  }

  const fresh = run?.mode === "dry" && run.report.valid && file?.text === run.fileText && createBlocks === run.createBlocks;
  const codeLabel = (code: string) => ((IMPORT_CODES as readonly string[]).includes(code) ? t(`console.import.code.${code}` as MessageKey) : code);

  return (
    <Card className="mt-6" aria-labelledby="import-title">
      <CardTitle id="import-title">{t("console.import.title")}</CardTitle>
      <p className="mb-1 text-sm text-ink-700">{t("console.import.intro")}</p>
      <p className="mb-3 text-sm font-medium text-navy-900">{t("console.import.all_or_nothing")}</p>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <Label htmlFor="import-file">{t("console.import.file")}</Label>
          <Input id="import-file" type="file" accept=".csv,text/csv" onChange={onFile} />
          <p className="mt-1 text-xs text-ink-700">{t("console.import.columns")}</p>
          <Button variant="ghost" size="sm" className="mt-1 underline" onClick={() => downloadCsv("units-template.csv", TEMPLATE)}>{t("console.import.template")}</Button>
        </div>
        <div className="flex flex-col gap-2">
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={createBlocks} onChange={(e) => setCreateBlocks(e.target.checked)} />
            {t("console.import.create_blocks")}
          </label>
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" disabled={!file || busy} onClick={() => submit("dry")}>{t("console.import.validate")}</Button>
            <Button disabled={!fresh || busy} onClick={() => setConfirm(true)}>{t("console.import.run", { count: run?.report.rows_valid ?? 0 })}</Button>
          </div>
          {file && !fresh ? <p className="text-xs text-ink-700">{t("console.import.validate_first")}</p> : null}
        </div>
      </div>
      {error ? <div className="mt-3"><ErrorAlert error={error} /></div> : null}
      {run ? (
        <div className="mt-4" data-testid="import-report">
          <Alert tone={run.report.valid ? "ok" : "danger"} live="polite">
            {run.mode === "real" && run.report.units_created > 0
              ? t("console.import.done", { count: run.report.units_created })
              : run.report.valid
                ? t("console.import.valid", { rows: run.report.rows_total, blocks: run.report.blocks_created.length })
                : t("console.import.invalid", { total: run.report.errors_total, rows: run.report.rows_total })}
          </Alert>
          {run.mode === "real" && !run.report.valid ? <p className="mt-1 text-sm font-medium">{t("console.import.nothing_written")}</p> : null}
          {run.report.blocks_created.length ? <p className="mt-1 text-sm">{t("console.import.new_blocks", { blocks: run.report.blocks_created.join(", ") })}</p> : null}
          {run.report.errors.length ? (
            <div className="mt-3">
              <DataTable
                caption={t("console.import.errors")}
                rows={run.report.errors.map((x, i) => ({ ...x, i }))}
                rowKey={(x) => String(x.i)}
                empty=""
                csvName="import-validation-report.csv"
                columns={[
                  { id: "row", header: t("console.import.col.row"), cell: (x) => (x.row === 0 ? t("console.import.whole_file") : x.row), csv: (x) => x.row, className: "text-right" },
                  { id: "field", header: t("console.import.col.field"), cell: (x) => x.field, csv: (x) => x.field },
                  { id: "code", header: t("console.import.col.problem"), cell: (x) => codeLabel(x.code), csv: (x) => x.code },
                ]}
              />
              {run.report.errors_truncated ? <p className="mt-1 text-xs text-ink-700">{t("console.import.truncated", { shown: run.report.errors.length, total: run.report.errors_total })}</p> : null}
            </div>
          ) : null}
        </div>
      ) : null}
      <Modal open={confirm} onOpenChange={setConfirm} title={t("console.import.confirm_title", { count: run?.report.rows_valid ?? 0 })} description={t("console.import.confirm_body")}>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirm(false)}>{t("common.action.cancel")}</Button>
          <Button disabled={busy} onClick={() => submit("real")}>{t("console.import.confirm_action")}</Button>
        </div>
      </Modal>
    </Card>
  );
}
