"use client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Modal } from "@/components/ui/dialog";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Label, Select, Textarea } from "@/components/ui/input";
import { useSociety } from "@/components/shell/society-context";
import { useSocietyApi } from "@/lib/society-api";
import { deviceKindLabel, deviceStateLabel, deviceTone } from "@/features/labels";
import { formatIst } from "@/lib/utils";
import type { Device, Gate, Schemas } from "@/api/types";
import { useT } from "@/i18n/provider";

type Action = { kind: "approve" | "reject" | "revoke"; device: Device };

/** SOC-05 subset / GATE (devices): enrolment requests wait for a DIFFERENT person's approval (maker-checker, enforced by the
 *  server). Approve, reject and revoke state their scope and effect first (UX-05) and end with an outcome receipt. */
export function DevicesPage() {
  const t = useT();
  const api = useSocietyApi();
  const qc = useQueryClient();
  const { can } = useSociety();
  const [stateFilter, setStateFilter] = useState("");
  const [action, setAction] = useState<Action | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const devices = useQuery({ queryKey: [api.societyId, "devices", stateFilter], queryFn: () => api.get<{ items: Device[] }>("devices", { state: stateFilter }) });
  const gates = useQuery({ queryKey: [api.societyId, "gates", "all"], queryFn: () => api.get<{ items: Gate[] }>("gates"), enabled: can("gate.configure.read") });
  const gateName = (id: string | null) => (id ? (gates.data?.items.find((g) => g.id === id)?.name ?? "") : t("console.devices.no_gate"));
  const decide = can("gate.device.decide");

  const minReason = action?.kind === "approve" ? 0 : 5;

  async function submit() {
    if (!action) return;
    setBusy(true);
    setError(null);
    try {
      const d = action.device;
      if (action.kind === "revoke") {
        await api.send("POST", `devices/${d.id}/revoke`, { json: { expected_version: d.version, reason } satisfies Schemas["DeviceRevoke"] });
      } else {
        await api.send("POST", `devices/${d.id}/decision`, {
          json: { decision: action.kind, expected_version: d.version, ...(reason.trim() ? { reason } : {}) } satisfies Schemas["DeviceDecision"],
        });
      }
      setReceipt(t(`console.devices.receipt.${action.kind}`, { name: d.name }));
      setAction(null);
      setReason("");
      await qc.invalidateQueries({ queryKey: [api.societyId, "devices"] });
    } catch (e) {
      setError(e);
      await qc.invalidateQueries({ queryKey: [api.societyId, "devices"] });
    } finally {
      setBusy(false);
    }
  }

  const columns: Column<Device>[] = [
    { id: "name", header: t("console.devices.col.name"), cell: (d) => <span className="font-medium">{d.name}</span>, csv: (d) => d.name },
    { id: "kind", header: t("console.devices.col.kind"), cell: (d) => deviceKindLabel(t, d.kind), csv: (d) => d.kind },
    { id: "gate", header: t("console.devices.col.gate"), cell: (d) => gateName(d.gate_id), csv: (d) => gateName(d.gate_id) },
    {
      id: "state",
      header: t("console.devices.col.state"),
      cell: (d) => (
        <span className="inline-flex flex-wrap items-center gap-1">
          <Badge tone={deviceTone(d.state)}>{deviceStateLabel(t, d.state)}</Badge>
          {d.simulation ? <Badge tone="warn">{t("console.devices.simulation")}</Badge> : null}
        </span>
      ),
      csv: (d) => d.state,
    },
    { id: "key", header: t("console.devices.col.key"), cell: (d) => <span className="font-mono text-xs">{d.key_id}</span>, csv: (d) => d.key_id },
    { id: "fw", header: t("console.devices.col.firmware"), cell: (d) => d.firmware ?? "", csv: (d) => d.firmware },
    { id: "seen", header: t("console.devices.col.last_seen"), cell: (d) => (d.last_seen_at ? formatIst(d.last_seen_at) : t("console.devices.never_seen")), csv: (d) => d.last_seen_at },
    { id: "created", header: t("console.devices.col.requested"), cell: (d) => formatIst(d.created_at), csv: (d) => d.created_at },
    {
      id: "actions",
      header: t("console.devices.col.actions"),
      cell: (d) =>
        decide && d.state === "pending_approval" ? (
          <span className="flex gap-1">
            <Button size="sm" onClick={() => { setError(null); setReason(""); setAction({ kind: "approve", device: d }); }} aria-label={t("console.devices.approve_named", { name: d.name })}>{t("console.devices.approve")}</Button>
            <Button size="sm" variant="secondary" onClick={() => { setError(null); setReason(""); setAction({ kind: "reject", device: d }); }} aria-label={t("console.devices.reject_named", { name: d.name })}>{t("console.devices.reject")}</Button>
          </span>
        ) : decide && d.state === "active" ? (
          <Button size="sm" variant="danger" onClick={() => { setError(null); setReason(""); setAction({ kind: "revoke", device: d }); }} aria-label={t("console.devices.revoke_named", { name: d.name })}>{t("console.devices.revoke")}</Button>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader title={t("console.devices.title")} description={t("console.devices.description")} />
      <div className="mb-3 max-w-xs">
        <Label htmlFor="dev-state">{t("console.devices.col.state")}</Label>
        <Select id="dev-state" value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
          <option value="">{t("console.filter.all")}</option>
          {(["pending_approval", "active", "rejected", "revoked"] as const).map((s) => (
            <option key={s} value={s}>{deviceStateLabel(t, s)}</option>
          ))}
        </Select>
      </div>
      {receipt ? <div className="mb-3"><Alert tone="ok" live="polite"><span data-testid="device-receipt">{receipt}</span></Alert></div> : null}
      {devices.error ? <div className="mb-3"><ErrorAlert error={devices.error} /></div> : null}
      {!decide ? <div className="mb-3"><Alert tone="info">{t("console.devices.read_only")}</Alert></div> : null}
      <DataTable caption={t("console.devices.title")} columns={columns} rows={devices.data?.items ?? []} rowKey={(d) => d.id} empty={t("console.devices.empty")} csvName="devices.csv" loading={devices.isLoading} />
      <Modal
        open={action !== null}
        onOpenChange={(o) => { if (!o) setAction(null); }}
        title={action ? t(`console.devices.confirm_title.${action.kind}`, { name: action.device.name }) : ""}
        description={action ? t(`console.devices.confirm_body.${action.kind}`) : ""}
      >
        {action ? (
          <div>
            <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-ink-700">{t("console.devices.col.kind")}</dt><dd>{deviceKindLabel(t, action.device.kind)}</dd>
              <dt className="text-ink-700">{t("console.devices.col.gate")}</dt><dd>{gateName(action.device.gate_id)}</dd>
              <dt className="text-ink-700">{t("console.devices.col.key")}</dt><dd className="font-mono text-xs">{action.device.key_id}</dd>
            </dl>
            <Label htmlFor="dev-reason">{minReason ? t("console.devices.reason_required") : t("console.devices.reason_optional")}</Label>
            <Textarea id="dev-reason" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />
            {error ? <div className="mt-3"><ErrorAlert error={error} /></div> : null}
            <div className="mt-3 flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setAction(null)}>{t("common.action.cancel")}</Button>
              <Button variant={action.kind === "approve" ? "primary" : "danger"} disabled={busy || reason.trim().length < minReason} onClick={submit}>
                {t(`console.devices.confirm_action.${action.kind}`)}
              </Button>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
