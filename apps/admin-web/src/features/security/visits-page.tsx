"use client";
import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, PageHeader } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Input, Label, Select } from "@/components/ui/input";
import { useSociety } from "@/components/shell/society-context";
import { useCursorPage } from "@/lib/use-cursor-page";
import { useSocietyApi } from "@/lib/society-api";
import { visitKindLabel, visitStateLabel } from "@/features/labels";
import { formatIst } from "@/lib/utils";
import type { ApprovalRequest, Gate, Page, Visit } from "@/api/types";
import { useT } from "@/i18n/provider";

const FULL_ROLES = ["secretary", "committee", "estate_mgr"];

/** Live visits with the exact backend state (INV-07): submitted, approved (not yet entered), entered, exited are different
 *  facts. Committee roles must state a purpose, which the server audits (IAM-04); the guard supervisor sees only the ACTIVE,
 *  masked visits of one gate. No resident identity is ever requested here (GATE-13). */
export function VisitsPage() {
  const t = useT();
  const api = useSocietyApi();
  const { roles, can } = useSociety();
  const guardView = !roles.some((r) => FULL_ROLES.includes(r));
  const gates = useQuery({ queryKey: [api.societyId, "gates", "all"], queryFn: () => api.get<{ items: Gate[] }>("gates") });

  const [draft, setDraft] = useState({ purpose: "", state: "", kind: "", gate: "" });
  const [applied, setApplied] = useState<typeof draft | null>(null);
  const ready = guardView ? !!applied?.gate : !!applied?.purpose.trim();

  const list = useCursorPage<Visit>(
    api.societyId,
    ["visits", applied],
    (cursor) => api.get<Page<Visit>>("visits", { limit: 25, cursor, purpose: guardView ? undefined : applied?.purpose, state: applied?.state, kind: applied?.kind, gate_id: applied?.gate }),
    ready,
  );

  function submit(e: FormEvent) {
    e.preventDefault();
    setApplied({ ...draft, purpose: draft.purpose.trim() });
    list.reset();
  }

  const gateName = (id: string) => gates.data?.items.find((g) => g.id === id)?.name ?? "";

  const columns: Column<Visit>[] = [
    { id: "created", header: t("console.visits.col.created"), cell: (v) => formatIst(v.created_at), csv: (v) => v.created_at },
    { id: "kind", header: t("console.visits.col.kind"), cell: (v) => visitKindLabel(t, v.kind), csv: (v) => v.kind },
    { id: "alias", header: t("console.visits.col.visitor"), cell: (v) => v.visitor_alias ?? "", csv: (v) => v.visitor_alias },
    { id: "dest", header: t("console.visits.col.destination"), cell: (v) => v.stops.map((s) => `${s.block_name}-${s.unit_label}`).join(", "), csv: (v) => v.stops.map((s) => `${s.block_name}-${s.unit_label}`).join(" ") },
    { id: "gate", header: t("console.visits.col.gate"), cell: (v) => gateName(v.gate_id), csv: (v) => gateName(v.gate_id) },
    {
      id: "state",
      header: t("console.visits.col.state"),
      cell: (v) => (
        <Badge tone={v.state === "inside" ? "info" : v.state === "authorised" ? "warn" : v.state === "requested" ? "neutral" : v.state === "exited" ? "ok" : "neutral"}>{visitStateLabel(t, v)}</Badge>
      ),
      csv: (v) => v.state,
    },
    { id: "entered", header: t("console.visits.col.entered"), cell: (v) => (v.entry_observed ? formatIst(v.entered_at) : t("console.visits.not_entered")), csv: (v) => v.entered_at },
    {
      id: "exited",
      header: t("console.visits.col.exited"),
      cell: (v) => (v.exit_basis === "reconciled_unknown" ? t("console.visits.exit_unknown") : v.exited_at ? formatIst(v.exited_at) : ""),
      csv: (v) => (v.exit_basis === "reconciled_unknown" ? "unknown" : v.exited_at),
    },
    { id: "conf", header: t("console.visits.col.confidence"), cell: (v) => (v.state === "inside" ? v.inside_confidence : ""), csv: (v) => v.inside_confidence },
  ];

  return (
    <div>
      <PageHeader title={t("console.visits.title")} description={t(guardView ? "console.visits.description_guard" : "console.visits.description")} />
      <Card className="mb-4" aria-labelledby="visit-filters">
        <CardTitle id="visit-filters">{t("console.units.filters")}</CardTitle>
        <form onSubmit={submit} className="grid grid-cols-2 items-end gap-3 md:grid-cols-5">
          {guardView ? null : (
            <div className="col-span-2">
              <Label htmlFor="v-purpose">{t("console.visits.purpose")}</Label>
              <Input id="v-purpose" required maxLength={200} value={draft.purpose} onChange={(e) => setDraft({ ...draft, purpose: e.target.value })} aria-describedby="v-purpose-hint" />
              <p id="v-purpose-hint" className="mt-0.5 text-xs text-ink-700">{t("console.visits.purpose_hint")}</p>
            </div>
          )}
          <div>
            <Label htmlFor="v-gate">{t("console.visits.col.gate")}</Label>
            <Select id="v-gate" required={guardView} value={draft.gate} onChange={(e) => setDraft({ ...draft, gate: e.target.value })}>
              <option value="">{guardView ? t("console.visits.choose_gate") : t("console.filter.all")}</option>
              {gates.data?.items.map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </Select>
          </div>
          {guardView ? null : (
            <div>
              <Label htmlFor="v-state">{t("console.visits.col.state")}</Label>
              <Select id="v-state" value={draft.state} onChange={(e) => setDraft({ ...draft, state: e.target.value })}>
                <option value="">{t("console.filter.all")}</option>
                {(["requested", "authorised", "inside", "exited", "cancelled", "expired"] as const).map((s) => (
                  <option key={s} value={s}>{visitStateLabel(t, { state: s })}</option>
                ))}
              </Select>
            </div>
          )}
          <div>
            <Label htmlFor="v-kind">{t("console.visits.col.kind")}</Label>
            <Select id="v-kind" value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })}>
              <option value="">{t("console.filter.all")}</option>
              {(["guest", "delivery", "service", "cab", "staff", "vendor"] as const).map((k) => (
                <option key={k} value={k}>{visitKindLabel(t, k)}</option>
              ))}
            </Select>
          </div>
          <div><Button type="submit">{t("console.visits.load")}</Button></div>
        </form>
      </Card>
      {!ready ? <Alert tone="info">{t(guardView ? "console.visits.choose_gate_first" : "console.visits.purpose_first")}</Alert> : null}
      {ready && list.query.error ? <div className="mb-3"><ErrorAlert error={list.query.error} /></div> : null}
      {ready ? <DataTable caption={t("console.visits.title")} columns={columns} rows={list.rows} rowKey={(v) => v.id} empty={t("console.visits.empty")} page={list.page} csvName="visits.csv" loading={list.query.isLoading} /> : null}
      {can("gate.request.read") ? <RequestsCard gates={gates.data?.items ?? []} /> : null}
    </div>
  );
}

/** Pending approval requests of one gate (guard supervisor only: the API gives committee roles no request access, by design). */
function RequestsCard({ gates }: { gates: Gate[] }) {
  const t = useT();
  const api = useSocietyApi();
  const [gate, setGate] = useState("");
  const [state, setState] = useState<ApprovalRequest["status"]>("pending");
  const list = useCursorPage<ApprovalRequest>(api.societyId, ["approval-requests", gate, state], (cursor) => api.get<Page<ApprovalRequest>>("approval-requests", { limit: 25, cursor, gate_id: gate, state }), !!gate);

  const columns: Column<ApprovalRequest>[] = [
    { id: "created", header: t("console.visits.col.created"), cell: (r) => formatIst(r.created_at), csv: (r) => r.created_at },
    { id: "unit", header: t("console.requests.col.unit"), cell: (r) => `${r.block_name}-${r.unit_label}`, csv: (r) => `${r.block_name}-${r.unit_label}` },
    { id: "visitor", header: t("console.visits.col.visitor"), cell: (r) => `${visitKindLabel(t, r.visitor.kind)}${r.visitor.alias ? `: ${r.visitor.alias}` : ""}`, csv: (r) => r.visitor.alias },
    { id: "status", header: t("console.visits.col.state"), cell: (r) => <Badge tone={r.status === "approved" ? "ok" : r.status === "pending" ? "warn" : "neutral"}>{t(`console.request_status.${r.status}`)}</Badge>, csv: (r) => r.status },
    { id: "entered", header: t("console.visits.col.entered"), cell: (r) => (r.entry_observed ? t("states.visit.entered") : t("console.visits.not_entered")), csv: (r) => r.entry_observed },
    { id: "expires", header: t("console.requests.col.expires"), cell: (r) => (r.status === "pending" ? t("console.requests.expires_in", { seconds: r.expires_in_seconds }) : ""), csv: (r) => r.expires_at },
  ];

  return (
    <Card className="mt-6" aria-labelledby="req-title">
      <CardTitle id="req-title">{t("console.requests.title")}</CardTitle>
      <p className="mb-2 text-sm text-ink-700">{t("console.requests.note")}</p>
      <div className="mb-3 grid max-w-lg grid-cols-2 gap-3">
        <div>
          <Label htmlFor="r-gate">{t("console.visits.col.gate")}</Label>
          <Select id="r-gate" value={gate} onChange={(e) => { setGate(e.target.value); list.reset(); }}>
            <option value="">{t("console.visits.choose_gate")}</option>
            {gates.map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="r-state">{t("console.visits.col.state")}</Label>
          <Select id="r-state" value={state} onChange={(e) => { setState(e.target.value as ApprovalRequest["status"]); list.reset(); }}>
            {(["pending", "approved", "denied", "expired", "cancelled"] as const).map((s) => (
              <option key={s} value={s}>{t(`console.request_status.${s}`)}</option>
            ))}
          </Select>
        </div>
      </div>
      {gate && list.query.error ? <ErrorAlert error={list.query.error} /> : null}
      {gate ? <DataTable caption={t("console.requests.title")} columns={columns} rows={list.rows} rowKey={(r) => r.id} empty={t("console.requests.empty")} page={list.page} csvName="approval-requests.csv" loading={list.query.isLoading} /> : <Alert tone="info">{t("console.visits.choose_gate_first")}</Alert>}
    </Card>
  );
}
