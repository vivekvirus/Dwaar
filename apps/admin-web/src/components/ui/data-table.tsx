"use client";
import { useRef, type KeyboardEvent, type ReactNode } from "react";
import { Button } from "./button";
import { cn } from "@/lib/utils";
import { downloadCsv, toCsv } from "@/lib/csv";
import { useT } from "@/i18n/provider";

export type Column<T> = {
  id: string;
  header: string;
  cell: (row: T) => ReactNode;
  /** plain value for CSV export; omit to leave the column out of the export */
  csv?: (row: T) => unknown;
  className?: string;
};

/**
 * Compact committee table (PRD 6). Keyboard: the table region is focusable for scrolling; rows take focus with ArrowUp/ArrowDown,
 * Home/End (roving tabindex); interactive cells keep their normal Tab order. Pagination is cursor based (Previous/Next).
 */
export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
  page,
  csvName,
  loading,
}: {
  caption: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  empty: string;
  page?: { index: number; hasPrev: boolean; hasNext: boolean; onPrev: () => void; onNext: () => void; fetching?: boolean };
  csvName?: string;
  loading?: boolean;
}) {
  const t = useT();
  const body = useRef<HTMLTableSectionElement>(null);

  function onKeyDown(e: KeyboardEvent<HTMLTableSectionElement>) {
    const trs = Array.from(body.current?.querySelectorAll<HTMLTableRowElement>("tr[data-row]") ?? []);
    if (!trs.length) return;
    const current = trs.findIndex((r) => r === document.activeElement || r.contains(document.activeElement));
    let next = -1;
    if (e.key === "ArrowDown") next = Math.min(trs.length - 1, current + 1);
    else if (e.key === "ArrowUp") next = Math.max(0, current - 1);
    else if (e.key === "Home" && (e.target as HTMLElement).tagName === "TR") next = 0;
    else if (e.key === "End" && (e.target as HTMLElement).tagName === "TR") next = trs.length - 1;
    if (next >= 0 && !["INPUT", "SELECT", "TEXTAREA"].includes((e.target as HTMLElement).tagName)) {
      e.preventDefault();
      trs.forEach((r, i) => r.setAttribute("tabindex", i === next ? "0" : "-1"));
      trs[next]?.focus();
    }
  }

  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <p className="text-xs text-ink-700" aria-live="polite">
          {loading ? t("common.status.loading") : t("console.table.rows_loaded", { count: rows.length })}
        </p>
        {csvName ? (
          <Button
            variant="secondary"
            size="sm"
            disabled={rows.length === 0}
            onClick={() => {
              const exportable = columns.filter((c) => c.csv);
              downloadCsv(csvName, toCsv(exportable.map((c) => c.header), rows.map((r) => exportable.map((c) => c.csv?.(r)))));
            }}
          >
            {t("console.table.export_csv")}
          </Button>
        ) : null}
      </div>
      <div className="overflow-x-auto rounded-md border border-slate-300" tabIndex={0} role="region" aria-label={caption}>
        <table className="w-full border-collapse text-left text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead className="bg-navy-50 text-xs uppercase tracking-wide text-ink-700">
            <tr>
              {columns.map((c) => (
                <th key={c.id} scope="col" className={cn("whitespace-nowrap px-2.5 py-1.5 font-semibold", c.className)}>
                  {c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody ref={body} onKeyDown={onKeyDown}>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-2.5 py-4 text-ink-700">
                  {loading ? t("common.status.loading") : empty}
                </td>
              </tr>
            ) : (
              rows.map((row, i) => (
                <tr key={rowKey(row)} data-row tabIndex={i === 0 ? 0 : -1} className="border-t border-slate-200 odd:bg-white even:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-navy-700">
                  {columns.map((c) => (
                    <td key={c.id} className={cn("px-2.5 py-1 align-top", c.className)}>
                      {c.cell(row)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {page ? (
        <nav className="mt-2 flex items-center justify-end gap-2" aria-label={t("console.table.pagination")}>
          <span className="text-xs text-ink-700">{t("console.table.page", { page: page.index + 1 })}</span>
          <Button variant="secondary" size="sm" disabled={!page.hasPrev || page.fetching} onClick={page.onPrev}>
            {t("console.table.prev")}
          </Button>
          <Button variant="secondary" size="sm" disabled={!page.hasNext || page.fetching} onClick={page.onNext}>
            {t("console.table.next")}
          </Button>
        </nav>
      ) : null}
    </div>
  );
}
