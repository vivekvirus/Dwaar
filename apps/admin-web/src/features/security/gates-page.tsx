"use client";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, PageHeader } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Modal } from "@/components/ui/dialog";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Input, Label } from "@/components/ui/input";
import { useSociety } from "@/components/shell/society-context";
import { useSocietyApi } from "@/lib/society-api";
import { directionLabel, gateKindLabel } from "@/features/labels";
import type { Gate, GatePolicy, Lane } from "@/api/types";
import type { Schemas } from "@/api/types";
import { useT } from "@/i18n/provider";

/** GATE-07 view / SOC-05: gates and lanes (read), and SOC-06 subset: gate policy settings with bounds shown and enforced by
 *  the server. There is no auto-allow on timeout and no setting for it (INV-03). */
export function GatesPage() {
  const t = useT();
  const api = useSocietyApi();
  const { can } = useSociety();
  const gates = useQuery({ queryKey: [api.societyId, "gates", "all"], queryFn: () => api.get<{ items: Gate[] }>("gates") });
  const lanes = useQueries({
    queries: (gates.data?.items ?? []).map((g) => ({
      queryKey: [api.societyId, "lanes", g.id],
      queryFn: () => api.get<{ items: Lane[] }>(`gates/${g.id}/lanes`),
    })),
  });
  const laneOf = (id: string) => lanes[(gates.data?.items ?? []).findIndex((g) => g.id === id)]?.data?.items ?? [];

  const columns: Column<Gate>[] = [
    { id: "name", header: t("console.gates.col.name"), cell: (g) => <span className="font-medium">{g.name}</span>, csv: (g) => g.name },
    { id: "kind", header: t("console.gates.col.kind"), cell: (g) => gateKindLabel(t, g.kind), csv: (g) => g.kind },
    { id: "status", header: t("console.gates.col.status"), cell: (g) => <Badge tone={g.status === "active" ? "ok" : "neutral"}>{g.status === "active" ? t("console.gates.status.active") : g.status}</Badge>, csv: (g) => g.status },
    {
      id: "lanes",
      header: t("console.gates.col.lanes"),
      cell: (g) => (
        <ul className="m-0 list-none p-0">
          {laneOf(g.id).map((l) => (
            <li key={l.id}>{l.label} <span className="text-ink-700">({directionLabel(t, l.direction)})</span></li>
          ))}
        </ul>
      ),
      csv: (g) => laneOf(g.id).map((l) => `${l.label} (${l.direction})`).join("; "),
    },
  ];

  return (
    <div>
      <PageHeader title={t("console.gates.title")} description={t("console.gates.description")} />
      {gates.error ? <div className="mb-3"><ErrorAlert error={gates.error} /></div> : null}
      <DataTable caption={t("console.gates.title")} columns={columns} rows={gates.data?.items ?? []} rowKey={(g) => g.id} empty={t("console.gates.empty")} csvName="gates.csv" loading={gates.isLoading} />
      <PolicyCard editable={can("gate.configure")} />
    </div>
  );
}

const OVERSTAY_KINDS = ["delivery", "cab", "service", "vendor"] as const;

function PolicyCard({ editable }: { editable: boolean }) {
  const t = useT();
  const api = useSocietyApi();
  const qc = useQueryClient();
  const policy = useQuery({ queryKey: [api.societyId, "gate-policy"], queryFn: () => api.get<GatePolicy>("gate-policy") });
  const [draft, setDraft] = useState<Record<string, string> | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const p = policy.data;

  const values = draft ?? (p ? {
    approval_expiry_seconds: String(p.approval_expiry_seconds),
    permission_validity_minutes: String(p.permission_validity_minutes),
    override_validity_minutes: String(p.override_validity_minutes),
    ...Object.fromEntries(OVERSTAY_KINDS.map((k) => [`overstay_${k}`, String(p.overstay_minutes[k] ?? "")])),
  } : {});
  const set = (k: string, v: string) => { setSaved(false); setDraft({ ...values, [k]: v }); };

  function changes(): Partial<Schemas["PolicyPut"]> {
    if (!p) return {};
    const out: Partial<Schemas["PolicyPut"]> = {};
    const num = (k: string) => Number.parseInt(values[k] ?? "", 10);
    if (num("approval_expiry_seconds") !== p.approval_expiry_seconds) out.approval_expiry_seconds = num("approval_expiry_seconds");
    if (num("permission_validity_minutes") !== p.permission_validity_minutes) out.permission_validity_minutes = num("permission_validity_minutes");
    if (num("override_validity_minutes") !== p.override_validity_minutes) out.override_validity_minutes = num("override_validity_minutes");
    const over: Record<string, number> = {};
    for (const k of OVERSTAY_KINDS) if (num(`overstay_${k}`) !== p.overstay_minutes[k]) over[k] = num(`overstay_${k}`);
    if (Object.keys(over).length) out.overstay_minutes = over;
    return out;
  }
  const diff = changes();
  const dirty = Object.keys(diff).length > 0;

  async function save() {
    if (!p) return;
    setBusy(true);
    setError(null);
    try {
      await api.send("PUT", "gate-policy", { json: { ...diff, expected_version: p.version } satisfies Schemas["PolicyPut"] });
      setDraft(null);
      setSaved(true);
      await qc.invalidateQueries({ queryKey: [api.societyId, "gate-policy"] });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  }

  const num = (id: string, label: string, hint?: string) => (
    <div key={id}>
      <Label htmlFor={`pol-${id}`}>{label}</Label>
      <Input id={`pol-${id}`} type="number" inputMode="numeric" min={1} value={values[id] ?? ""} disabled={!editable} onChange={(e) => set(id, e.target.value)} aria-describedby={hint ? `pol-${id}-hint` : undefined} />
      {hint ? <p id={`pol-${id}-hint`} className="mt-0.5 text-xs text-ink-700">{hint}</p> : null}
    </div>
  );

  return (
    <Card className="mt-6" aria-labelledby="policy-title">
      <CardTitle id="policy-title">{t("console.policy.title")}</CardTitle>
      <p className="mb-2 text-sm text-ink-700">{t("console.policy.intro")}</p>
      {policy.error ? <ErrorAlert error={policy.error} /> : null}
      {p ? (
        <>
          <Alert tone="info"><span data-testid="no-auto-allow">{t(p.auto_allow_on_timeout ? "console.policy.auto_allow_on" : "console.policy.no_auto_allow")}</span></Alert>
          <form className="mt-3 grid gap-3 md:grid-cols-3" onSubmit={(e: FormEvent) => { e.preventDefault(); if (dirty) setConfirm(true); }}>
            {num("approval_expiry_seconds", t("console.policy.approval_expiry"))}
            {num("permission_validity_minutes", t("console.policy.permission_validity"))}
            {num("override_validity_minutes", t("console.policy.override_validity"))}
            {OVERSTAY_KINDS.map((k) => num(`overstay_${k}`, t("console.policy.overstay", { kind: t(`console.visit_kind.${k}`) }), t("console.policy.bounds", { min: p.overstay_bounds[k]?.min ?? 0, max: p.overstay_bounds[k]?.max ?? 0 })))}
            <div className="flex items-end gap-2">
              {editable ? <Button type="submit" disabled={!dirty || busy}>{t("common.action.save")}</Button> : <p className="text-xs text-ink-700">{t("console.policy.read_only")}</p>}
            </div>
          </form>
          {saved ? <div className="mt-3"><Alert tone="ok" live="polite">{t("console.policy.saved")}</Alert></div> : null}
          {error ? <div className="mt-3"><ErrorAlert error={error} /></div> : null}
          <p className="mt-2 text-xs text-ink-700">{t("console.policy.versions", { version: p.version, revocation: p.revocation_version })}</p>
          <Modal open={confirm} onOpenChange={setConfirm} title={t("console.policy.confirm_title")} description={t("console.policy.confirm_body")}>
            <ul className="mb-3 list-disc pl-5 text-sm">
              {Object.entries(diff).map(([k, v]) => (
                <li key={k}>{k}: {typeof v === "object" ? JSON.stringify(v) : String(v)}</li>
              ))}
            </ul>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setConfirm(false)}>{t("common.action.cancel")}</Button>
              <Button disabled={busy} onClick={save}>{t("console.policy.confirm_action")}</Button>
            </div>
          </Modal>
        </>
      ) : null}
    </Card>
  );
}
