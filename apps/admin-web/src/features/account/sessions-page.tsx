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
import { useSocietyApi } from "@/lib/society-api";
import { formatIst } from "@/lib/utils";
import type { AuthSession } from "@/api/types";
import { useT } from "@/i18n/provider";

type Target = { kind: "one"; session: AuthSession } | { kind: "others" };

/** IAM-08: the person's own session and device list, with revocation. Revoking is immediate on the server; the current session
 *  is ended with Sign out instead. */
export function SessionsPage() {
  const t = useT();
  const api = useSocietyApi();
  const qc = useQueryClient();
  const [target, setTarget] = useState<Target | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const q = useQuery({ queryKey: [api.societyId, "auth-sessions"], queryFn: () => api.global.get<{ sessions: AuthSession[] }>("auth/sessions") });
  const sessions = q.data?.sessions ?? [];
  const others = sessions.filter((s) => !s.current).length;

  async function confirm() {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      if (target.kind === "one") {
        await api.global.send("DELETE", `auth/sessions/${target.session.id}`);
        setReceipt(t("console.sessions.receipt_one", { device: target.session.device_label }));
      } else {
        const r = await api.global.send<Record<string, number>>("DELETE", "auth/sessions");
        setReceipt(t("console.sessions.receipt_others", { count: Object.values(r ?? {})[0] ?? 0 }));
      }
      setTarget(null);
      await qc.invalidateQueries({ queryKey: [api.societyId, "auth-sessions"] });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const columns: Column<AuthSession>[] = [
    { id: "device", header: t("console.sessions.col.device"), cell: (s) => <span className="font-medium">{s.device_label}</span>, csv: (s) => s.device_label },
    { id: "platform", header: t("console.sessions.col.platform"), cell: (s) => s.platform ?? "", csv: (s) => s.platform },
    { id: "created", header: t("console.sessions.col.signed_in"), cell: (s) => formatIst(s.created_at), csv: (s) => s.created_at },
    { id: "seen", header: t("console.sessions.col.last_seen"), cell: (s) => formatIst(s.last_seen_at), csv: (s) => s.last_seen_at },
    { id: "mfa", header: t("console.sessions.col.mfa"), cell: (s) => (s.mfa_verified_at ? t("console.sessions.mfa_yes") : t("console.sessions.mfa_no")), csv: (s) => s.mfa_verified_at },
    { id: "expires", header: t("console.sessions.col.expires"), cell: (s) => formatIst(s.expires_at), csv: (s) => s.expires_at },
    {
      id: "actions",
      header: t("console.sessions.col.actions"),
      cell: (s) =>
        s.current ? (
          <Badge tone="info">{t("console.sessions.current")}</Badge>
        ) : (
          <Button size="sm" variant="danger" onClick={() => { setError(null); setTarget({ kind: "one", session: s }); }} aria-label={t("console.sessions.revoke_named", { device: s.device_label })}>{t("console.sessions.revoke")}</Button>
        ),
    },
  ];

  return (
    <div>
      <PageHeader
        title={t("console.sessions.title")}
        description={t("console.sessions.description")}
        actions={<Button variant="danger" disabled={others === 0} onClick={() => { setError(null); setTarget({ kind: "others" }); }}>{t("console.sessions.revoke_others")}</Button>}
      />
      {receipt ? <div className="mb-3"><Alert tone="ok" live="polite"><span data-testid="session-receipt">{receipt}</span></Alert></div> : null}
      {q.error ? <div className="mb-3"><ErrorAlert error={q.error} /></div> : null}
      <DataTable caption={t("console.sessions.title")} columns={columns} rows={sessions} rowKey={(s) => s.id} empty={t("console.sessions.empty")} loading={q.isLoading} />
      <Modal open={target !== null} onOpenChange={(o) => { if (!o) setTarget(null); }} title={target?.kind === "others" ? t("console.sessions.confirm_others_title", { count: others }) : t("console.sessions.confirm_one_title")} description={t("console.sessions.confirm_body")}>
        {error ? <div className="mb-3"><ErrorAlert error={error} /></div> : null}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setTarget(null)}>{t("common.action.cancel")}</Button>
          <Button variant="danger" disabled={busy} onClick={confirm}>{t("console.sessions.confirm_action")}</Button>
        </div>
      </Modal>
    </div>
  );
}
