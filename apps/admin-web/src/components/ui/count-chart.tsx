"use client";
import { Button } from "./button";
import { downloadCsv, toCsv } from "@/lib/csv";
import { useT } from "@/i18n/provider";

export type CountDatum = { label: string; value: number };

/**
 * Chart WITH a numeric table and an export (PRD 6: "charts always have numeric tables and exports"). The bars are decorative
 * (aria-hidden); the table carries every number, so nothing is conveyed by the graphic alone.
 */
export function CountChart({ title, data, valueHeader, labelHeader, csvName, capped }: { title: string; data: CountDatum[]; valueHeader: string; labelHeader: string; csvName: string; capped?: boolean }) {
  const t = useT();
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <figure className="m-0">
      <figcaption className="sr-only">{title}</figcaption>
      <div aria-hidden="true" className="mb-3 space-y-1.5">
        {data.map((d) => (
          <div key={d.label} className="flex items-center gap-2 text-xs">
            <span className="w-40 shrink-0 truncate text-ink-700">{d.label}</span>
            <span className="h-3 rounded-sm bg-teal-700" style={{ width: `${(d.value / max) * 100}%`, minWidth: d.value > 0 ? 4 : 0 }} />
            <span className="font-mono text-ink-900">{d.value}</span>
          </div>
        ))}
      </div>
      <table className="w-full max-w-md border-collapse text-sm">
        <caption className="sr-only">{title}</caption>
        <thead className="bg-navy-50 text-xs text-ink-700">
          <tr>
            <th scope="col" className="px-2.5 py-1 text-left font-semibold">{labelHeader}</th>
            <th scope="col" className="px-2.5 py-1 text-right font-semibold">{valueHeader}</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.label} className="border-t border-slate-200">
              <th scope="row" className="px-2.5 py-1 text-left font-normal">{d.label}</th>
              <td className="px-2.5 py-1 text-right font-mono">{d.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {data.length === 0 ? <p className="mt-1 text-sm text-ink-700">{t("console.chart.empty")}</p> : null}
      {capped ? <p className="mt-1 text-xs text-ink-700">{t("console.chart.capped")}</p> : null}
      <div className="mt-2">
        <Button variant="secondary" size="sm" onClick={() => downloadCsv(csvName, toCsv([labelHeader, valueHeader], data.map((d) => [d.label, d.value])))}>
          {t("console.table.export_csv")}
        </Button>
      </div>
    </figure>
  );
}
