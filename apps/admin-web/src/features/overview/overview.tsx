"use client";
import Link from "next/link";
import { useQueries } from "@tanstack/react-query";
import { Alert } from "@/components/ui/alert";
import { Card, CardTitle, PageHeader } from "@/components/ui/card";
import { CountChart } from "@/components/ui/count-chart";
import { ErrorAlert } from "@/components/ui/error-alert";
import { useSociety } from "@/components/shell/society-context";
import { useSocietyApi } from "@/lib/society-api";
import { EXCEPTION_STATE_ORDER, exceptionKindLabel, exceptionStateLabel } from "@/features/labels";
import type { Device, GateException, Gate } from "@/api/types";
import { useT } from "@/i18n/provider";

const CAP = 100; // the exceptions endpoint returns at most 100 rows per call

/** PRD 6: Overview with exception counters. Counters are computed from the real exception queue; a counter that hit the 100-row
 *  page limit is labelled "100+" instead of being presented as exact. */
export function Overview() {
  const t = useT();
  const api = useSocietyApi();
  const { society, can } = useSociety();
  const showExceptions = can("gate.exception.read");
  const showDevices = can("gate.device.read");
  const showGates = can("gate.configure.read");

  const exceptionQs = useQueries({
    queries: EXCEPTION_STATE_ORDER.map((state) => ({
      queryKey: [api.societyId, "exceptions", "counter", state],
      queryFn: () => api.get<{ items: GateException[] }>("exceptions", { state, limit: CAP }),
      enabled: showExceptions,
    })),
  });
  const deviceQ = useQueries({
    queries: [
      { queryKey: [api.societyId, "devices", "all"], queryFn: () => api.get<{ items: Device[] }>("devices"), enabled: showDevices },
      { queryKey: [api.societyId, "gates", "all"], queryFn: () => api.get<{ items: Gate[] }>("gates"), enabled: showGates },
    ],
  });

  const counts = EXCEPTION_STATE_ORDER.map((state, i) => ({ state, n: exceptionQs[i]?.data?.items.length ?? null, capped: (exceptionQs[i]?.data?.items.length ?? 0) >= CAP }));
  const kindMap = new Map<string, number>();
  EXCEPTION_STATE_ORDER.forEach((state, i) => {
    if (state === "resolved") return;
    for (const e of exceptionQs[i]?.data?.items ?? []) kindMap.set(e.kind, (kindMap.get(e.kind) ?? 0) + 1);
  });
  const anyError = exceptionQs.find((q) => q.error)?.error ?? deviceQ.find((q) => q.error)?.error;
  const pendingDevices = deviceQ[0]?.data?.items.filter((d) => d.state === "pending_approval").length;
  const gates = deviceQ[1]?.data?.items;

  const tile = (id: string, label: string, value: string | number, href: string, tone: string) => (
    <li key={id}>
      <Link href={href} className={`block rounded-lg border p-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-navy-700 ${tone}`}>
        <span className="block text-xs font-medium text-ink-700">{label}</span>
        <span className="block text-2xl font-semibold text-navy-950" data-testid={`counter-${id}`}>{value}</span>
      </Link>
    </li>
  );

  return (
    <div>
      <PageHeader title={t("console.overview.title")} description={t("console.overview.description", { society: society.name })} />
      {anyError ? <div className="mb-3"><ErrorAlert error={anyError} /></div> : null}
      {!showExceptions && !showDevices ? <Alert tone="info">{t("console.overview.no_widgets")}</Alert> : null}
      {showExceptions || showDevices ? (
        <section aria-labelledby="counters" className="mb-4">
          <h2 id="counters" className="sr-only">{t("console.overview.counters")}</h2>
          <ul className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {showExceptions
              ? counts.map((c) =>
                  tile(
                    `exc-${c.state}`,
                    exceptionStateLabel(t, c.state),
                    c.n === null ? "-" : c.capped ? `${CAP}+` : c.n,
                    `/security/exceptions?state=${c.state}`,
                    c.state === "open" ? "border-rose-300 bg-danger-100" : c.state === "escalated" ? "border-amber-300 bg-warn-100" : "border-slate-300 bg-white",
                  ),
                )
              : null}
            {showDevices ? tile("dev-pending", t("console.overview.devices_pending"), pendingDevices ?? "-", "/security/devices", pendingDevices ? "border-amber-300 bg-warn-100" : "border-slate-300 bg-white") : null}
            {showGates ? tile("gates", t("console.overview.gates"), gates?.length ?? "-", "/security/gates", "border-slate-300 bg-white") : null}
          </ul>
        </section>
      ) : null}
      {showExceptions ? (
        <Card aria-labelledby="exc-chart">
          <CardTitle id="exc-chart">{t("console.overview.exceptions_by_kind")}</CardTitle>
          <p className="mb-2 text-xs text-ink-700">{t("console.overview.exceptions_by_kind_note")}</p>
          <CountChart
            title={t("console.overview.exceptions_by_kind")}
            labelHeader={t("console.exceptions.col.kind")}
            valueHeader={t("console.overview.col.unresolved")}
            csvName="exceptions-unresolved-by-kind.csv"
            capped={counts.some((c) => c.capped)}
            data={[...kindMap.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: exceptionKindLabel(t, k), value: v }))}
          />
        </Card>
      ) : null}
    </div>
  );
}
