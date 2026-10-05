"use client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
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
import { EXCEPTION_STATE_ORDER, exceptionKindLabel, exceptionStateLabel, exceptionTone } from "@/features/labels";
import { formatIst, shortId } from "@/lib/utils";
import type { GateException, Schemas } from "@/api/types";
import { useT } from "@/i18n/provider";

type Act = { action: Schemas["ExceptionTransition"]["action"]; ex: GateException };

export function ExceptionsPage() {
  return (
    <Suspense fallback={null}>
      <Inner />
    </Suspense>
  );
}

/** GATE-07 (view and review): the exception queue with supervisor review transitions open -> supervisor_review -> resolved /
 *  escalated. State and version are compared by the server (compare-and-swap); a stale click gets a clear message. */
function Inner() {
  const t = useT();
  const api = useSocietyApi();
  const qc = useQueryClient();
  const { can, roles } = useSociety();
  const params = useSearchParams();
  const initial = params.get("state") ?? "";
  const [stateFilter, setStateFilter] = useState((EXCEPTION_STATE_ORDER as readonly string[]).includes(initial) ? initial : "");
  const [kindFilter, setKindFilter] = useState("");
  const [act, setAct] = useState<Act | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const manage = can("gate.exception.manage");

  const q = useQuery({
    queryKey: [api.societyId, "exceptions", "list", stateFilter, kindFilter],
    queryFn: () => api.get<{ items: GateException[] }>("exceptions", { state: stateFilter, kind: kindFilter, limit: 100 }),
  });

  async function submit() {
    if (!act) return;
    setBusy(true);
    setError(null);
    try {
      await api.global.send("POST", `exceptions/${act.ex.id}/transition`, {
        json: { action: act.action, expected_version: act.ex.version, ...(note.trim() ? { note } : {}) } satisfies Schemas["ExceptionTransition"],
      });
      setReceipt(t(`console.exceptions.receipt.${act.action}`, { id: shortId(act.ex.id) }));
      setAct(null);
      setNote("");
      await qc.invalidateQueries({ queryKey: [api.societyId, "exceptions"] });
    } catch (e) {
      setError(e);
      await qc.invalidateQueries({ queryKey: [api.societyId, "exceptions"] });
    } finally {
      setBusy(false);
    }
  }

  const open = (action: Act["action"], ex: GateException) => { setError(null); setNote(""); setAct({ action, ex }); };
  const canResolve = (ex: GateException) => (ex.state === "supervisor_review" || (ex.state === "escalated" && roles.includes("secretary")));

  const columns: Column<GateException>[] = [
    { id: "created", header: t("console.exceptions.col.raised"), cell: (e) => formatIst(e.created_at), csv: (e) => e.created_at },
    { id: "kind", header: t("console.exceptions.col.kind"), cell: (e) => exceptionKindLabel(t, e.kind), csv: (e) => e.kind },
    { id: "reason", header: t("console.exceptions.col.reason"), cell: (e) => <span>{e.reason}{e.raised_by_system ? <Badge className="ml-1">{t("console.exceptions.system")}</Badge> : null}</span>, csv: (e) => e.reason },
    { id: "entry", header: t("console.exceptions.col.entry"), cell: (e) => (e.entry_happened ? t("common.answer.yes") : t("common.answer.no")), csv: (e) => e.entry_happened },
    { id: "state", header: t("console.exceptions.col.state"), cell: (e) => <Badge tone={exceptionTone(e.state)}>{exceptionStateLabel(t, e.state)}</Badge>, csv: (e) => e.state },
    { id: "note", header: t("console.exceptions.col.resolution"), cell: (e) => e.resolution_note ?? "", csv: (e) => e.resolution_note },
    {
      id: "actions",
      header: t("console.exceptions.col.actions"),
      cell: (e) =>
        manage ? (
          <span className="flex flex-wrap gap-1">
            {e.state === "open" ? <Button size="sm" onClick={() => open("start_review", e)} aria-label={t("console.exceptions.start_review_named", { id: shortId(e.id) })}>{t("console.exceptions.start_review")}</Button> : null}
            {e.state === "open" || e.state === "supervisor_review" ? <Button size="sm" variant="secondary" onClick={() => open("escalate", e)} aria-label={t("console.exceptions.escalate_named", { id: shortId(e.id) })}>{t("console.exceptions.escalate")}</Button> : null}
            {canResolve(e) ? <Button size="sm" variant="secondary" onClick={() => open("resolve", e)} aria-label={t("console.exceptions.resolve_named", { id: shortId(e.id) })}>{t("console.exceptions.resolve")}</Button> : null}
          </span>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader title={t("console.exceptions.title")} description={t("console.exceptions.description")} />
      <div className="mb-3 grid max-w-lg grid-cols-2 gap-3">
        <div>
          <Label htmlFor="x-state">{t("console.exceptions.col.state")}</Label>
          <Select id="x-state" value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="">{t("console.filter.all")}</option>
            {EXCEPTION_STATE_ORDER.map((s) => (
              <option key={s} value={s}>{exceptionStateLabel(t, s)}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="x-kind">{t("console.exceptions.col.kind")}</Label>
          <Select id="x-kind" value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
            <option value="">{t("console.filter.all")}</option>
            {(["manual_entry", "emergency_entry", "unauthorised_entry", "exit_unknown", "overstay", "other"] as const).map((k) => (
              <option key={k} value={k}>{exceptionKindLabel(t, k)}</option>
            ))}
          </Select>
        </div>
      </div>
      {receipt ? <div className="mb-3"><Alert tone="ok" live="polite"><span data-testid="exception-receipt">{receipt}</span></Alert></div> : null}
      {!manage ? <div className="mb-3"><Alert tone="info">{t("console.exceptions.read_only")}</Alert></div> : null}
      {q.error ? <div className="mb-3"><ErrorAlert error={q.error} /></div> : null}
      <DataTable caption={t("console.exceptions.title")} columns={columns} rows={q.data?.items ?? []} rowKey={(e) => e.id} empty={t("console.exceptions.empty")} csvName="exceptions.csv" loading={q.isLoading} />
      {(q.data?.items.length ?? 0) >= 100 ? <p className="mt-1 text-xs text-ink-700">{t("console.exceptions.capped")}</p> : null}
      <Modal open={act !== null} onOpenChange={(o) => { if (!o) setAct(null); }} title={act ? t(`console.exceptions.confirm_title.${act.action}`) : ""} description={act ? t(`console.exceptions.confirm_body.${act.action}`) : ""}>
        {act ? (
          <div>
            <p className="mb-2 text-sm"><span className="font-medium">{exceptionKindLabel(t, act.ex.kind)}</span>: {act.ex.reason}</p>
            <Label htmlFor="x-note">{act.action === "resolve" ? t("console.exceptions.note_required") : t("console.exceptions.note_optional")}</Label>
            <Textarea id="x-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
            {error ? <div className="mt-3"><ErrorAlert error={error} /></div> : null}
            <div className="mt-3 flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setAct(null)}>{t("common.action.cancel")}</Button>
              <Button disabled={busy || (act.action === "resolve" && note.trim().length < 5)} onClick={submit}>{t(`console.exceptions.confirm_action.${act.action}`)}</Button>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
