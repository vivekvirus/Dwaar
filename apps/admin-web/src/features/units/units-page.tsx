"use client";
import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, PageHeader } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Input, Label, Select } from "@/components/ui/input";
import { useSociety } from "@/components/shell/society-context";
import { useCursorPage } from "@/lib/use-cursor-page";
import { useSocietyApi } from "@/lib/society-api";
import { formatPaise } from "@/lib/utils";
import { ImportPanel } from "./import-panel";
import type { Block, Page, Unit } from "@/api/types";
import { useT } from "@/i18n/provider";

type Filters = { block_id: string; floor: string; status: string; label: string };
const EMPTY: Filters = { block_id: "", floor: "", status: "active", label: "" };

/** SOC-02: unit list with filters, cursor pagination and CSV export of the loaded rows. SOC-03: bulk import below. */
export function UnitsPage() {
  const t = useT();
  const api = useSocietyApi();
  const { can } = useSociety();
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters>(EMPTY);

  const blocks = useQuery({ queryKey: [api.societyId, "blocks"], queryFn: () => api.get<Page<Block>>("blocks", { limit: 100 }) });
  const list = useCursorPage<Unit>(api.societyId, ["units", applied], (cursor) =>
    api.get<Page<Unit>>("units", { limit: 25, cursor, block_id: applied.block_id, floor: applied.floor, status: applied.status, label: applied.label }),
  );

  const columns: Column<Unit>[] = [
    { id: "block", header: t("console.units.col.block"), cell: (u) => u.block_name, csv: (u) => u.block_name },
    { id: "label", header: t("console.units.col.label"), cell: (u) => <span className="font-medium">{u.label}</span>, csv: (u) => u.label },
    { id: "floor", header: t("console.units.col.floor"), cell: (u) => u.floor, csv: (u) => u.floor, className: "text-right" },
    { id: "carpet", header: t("console.units.col.carpet"), cell: (u) => u.carpet_area_sqft ?? "", csv: (u) => u.carpet_area_sqft, className: "text-right font-mono" },
    { id: "builtup", header: t("console.units.col.builtup"), cell: (u) => u.builtup_area_sqft ?? "", csv: (u) => u.builtup_area_sqft, className: "text-right font-mono" },
    { id: "interest", header: t("console.units.col.interest"), cell: (u) => u.undivided_interest_pct ?? "", csv: (u) => u.undivided_interest_pct, className: "text-right font-mono" },
    { id: "cost", header: t("console.units.col.cost"), cell: (u) => (u.construction_cost_paise === null ? "" : formatPaise(u.construction_cost_paise)), csv: (u) => u.construction_cost_paise, className: "text-right font-mono" },
    { id: "status", header: t("console.units.col.status"), cell: (u) => <Badge tone={u.status === "active" ? "ok" : "neutral"}>{u.status === "active" ? t("console.units.status.active") : t("console.units.status.archived")}</Badge>, csv: (u) => u.status },
  ];

  function apply(e: FormEvent) {
    e.preventDefault();
    setApplied(draft);
    list.reset();
  }

  return (
    <div>
      <PageHeader title={t("console.units.title")} description={t("console.units.description")} />
      <Card className="mb-4" aria-labelledby="unit-filters">
        <CardTitle id="unit-filters">{t("console.units.filters")}</CardTitle>
        <form onSubmit={apply} className="grid grid-cols-2 items-end gap-3 md:grid-cols-5">
          <div>
            <Label htmlFor="f-block">{t("console.units.col.block")}</Label>
            <Select id="f-block" value={draft.block_id} onChange={(e) => setDraft({ ...draft, block_id: e.target.value })}>
              <option value="">{t("console.filter.all")}</option>
              {blocks.data?.items.map((b) => (
                <option key={b.id} value={b.id}>{b.name}</option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="f-floor">{t("console.units.col.floor")}</Label>
            <Input id="f-floor" type="number" inputMode="numeric" min={0} max={300} value={draft.floor} onChange={(e) => setDraft({ ...draft, floor: e.target.value })} />
          </div>
          <div>
            <Label htmlFor="f-label">{t("console.units.col.label")}</Label>
            <Input id="f-label" maxLength={40} value={draft.label} onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
          </div>
          <div>
            <Label htmlFor="f-status">{t("console.units.col.status")}</Label>
            <Select id="f-status" value={draft.status} onChange={(e) => setDraft({ ...draft, status: e.target.value })}>
              <option value="active">{t("console.units.status.active")}</option>
              <option value="archived">{t("console.units.status.archived")}</option>
            </Select>
          </div>
          <div className="flex gap-2">
            <Button type="submit">{t("console.filter.apply")}</Button>
            <Button variant="secondary" onClick={() => { setDraft(EMPTY); setApplied(EMPTY); list.reset(); }}>{t("console.filter.clear")}</Button>
          </div>
        </form>
      </Card>
      {list.query.error ? <div className="mb-3"><ErrorAlert error={list.query.error} /></div> : null}
      <DataTable caption={t("console.units.title")} columns={columns} rows={list.rows} rowKey={(u) => u.id} empty={t("console.units.empty")} page={list.page} csvName="units.csv" loading={list.query.isLoading} />
      {can("unit.import") ? <ImportPanel /> : null}
    </div>
  );
}
