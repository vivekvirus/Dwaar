"use client";
import { useQuery } from "@tanstack/react-query";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardTitle, PageHeader } from "@/components/ui/card";
import { ErrorAlert } from "@/components/ui/error-alert";
import { useSociety } from "@/components/shell/society-context";
import { bff } from "@/lib/api-client";
import { useSocietyApi } from "@/lib/society-api";
import type { Meta, SocietyConfiguration } from "@/api/types";
import { useT } from "@/i18n/provider";
import type { MessageKey } from "@/i18n";

const BLOCKERS = ["legal_pack_not_approved", "feature_flag_disabled"] as const;

/** SOC-01/SOC-06 view and INV-10: the legal pack is configuration; an unapproved pack means binding governance is OFF, and this
 *  page says so plainly. Integration readiness is shown only to administrators who may configure the society. */
export function SocietySettingsPage() {
  const t = useT();
  const api = useSocietyApi();
  const { can } = useSociety();
  const cfg = useQuery({ queryKey: [api.societyId, "configuration"], queryFn: () => api.get<SocietyConfiguration>("configuration") });
  const showReadiness = can("integration.readiness");
  const meta = useQuery({ queryKey: [api.societyId, "meta"], queryFn: () => bff<Meta>({ kind: "v1", path: "meta", societyId: api.societyId }), enabled: showReadiness });
  const c = cfg.data;

  const packTone = (approved: boolean) => (approved ? "ok" : "warn");

  return (
    <div>
      <PageHeader title={t("console.settings.title")} description={t("console.settings.description")} />
      {cfg.error ? <div className="mb-3"><ErrorAlert error={cfg.error} /></div> : null}
      {c ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card aria-labelledby="s-society">
            <CardTitle id="s-society">{t("console.settings.society")}</CardTitle>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-ink-700">{t("console.settings.name")}</dt><dd data-testid="settings-name">{c.name}</dd>
              <dt className="text-ink-700">{t("console.settings.city")}</dt><dd>{c.city}, {c.state}</dd>
              <dt className="text-ink-700">{t("console.settings.timezone")}</dt><dd>{c.timezone}</dd>
              <dt className="text-ink-700">{t("console.settings.status")}</dt><dd>{c.status}</dd>
              {c.legal_entity ? (
                <>
                  <dt className="text-ink-700">{t("console.settings.entity")}</dt><dd>{c.legal_entity.name}</dd>
                  <dt className="text-ink-700">{t("console.settings.registration")}</dt><dd>{c.legal_entity.registration_no ?? ""}</dd>
                  <dt className="text-ink-700">{t("console.settings.gst")}</dt><dd>{c.legal_entity.gst_registered ? t("common.answer.yes") : t("common.answer.no")}</dd>
                </>
              ) : null}
            </dl>
          </Card>

          <Card aria-labelledby="s-legal">
            <CardTitle id="s-legal">{t("console.settings.legal_pack")}</CardTitle>
            {c.legal_pack ? (
              <>
                <p className="mb-2 text-sm">{c.legal_pack.title}</p>
                <p className="mb-2 flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono text-xs">{c.legal_pack.pack_key} {c.legal_pack.version}</span>
                  <Badge tone={packTone(c.legal_pack.approved)} data-testid="legal-pack-status">{c.legal_pack.approved ? t("console.settings.pack_approved") : t("console.settings.pack_unapproved")}</Badge>
                </p>
              </>
            ) : (
              <p className="mb-2 text-sm">{t("console.settings.no_legal_pack")}</p>
            )}
            <Alert tone={c.binding_governance.enabled ? "ok" : "warn"}>
              <p className="font-medium" data-testid="binding-governance">{c.binding_governance.enabled ? t("console.settings.binding_enabled") : t("console.settings.binding_disabled")}</p>
              {c.binding_governance.blockers.length ? (
                <ul className="mt-1 list-disc pl-5">
                  {c.binding_governance.blockers.map((b) => (
                    <li key={b}>{(BLOCKERS as readonly string[]).includes(b) ? t(`console.settings.blocker.${b}` as MessageKey) : b}</li>
                  ))}
                </ul>
              ) : null}
            </Alert>
            <p className="mt-2 text-xs text-ink-700">{t("console.settings.pack_note")}</p>
          </Card>

          <Card aria-labelledby="s-tax">
            <CardTitle id="s-tax">{t("console.settings.tax_pack")}</CardTitle>
            {c.tax_pack ? (
              <p className="flex flex-wrap items-center gap-2 text-sm">
                <span>{c.tax_pack.title}</span>
                <span className="font-mono text-xs">{c.tax_pack.pack_key} {c.tax_pack.version}</span>
                <Badge tone={packTone(c.tax_pack.approved)}>{c.tax_pack.approved ? t("console.settings.pack_approved") : t("console.settings.tax_unapproved", { status: c.tax_pack.pack_status })}</Badge>
              </p>
            ) : (
              <p className="text-sm">{t("console.settings.no_tax_pack")}</p>
            )}
          </Card>

          <Card aria-labelledby="s-flags">
            <CardTitle id="s-flags">{t("console.settings.flags")}</CardTitle>
            {c.feature_flags.length ? (
              <ul className="m-0 list-none p-0 text-sm">
                {c.feature_flags.map((f) => (
                  <li key={f.flag_key} className="flex items-center justify-between border-t border-slate-200 py-1 first:border-0">
                    <span className="font-mono text-xs">{f.flag_key}</span>
                    <Badge tone={f.enabled ? "ok" : "neutral"}>{f.enabled ? t("console.settings.flag_on") : t("console.settings.flag_off")}</Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm">{t("console.settings.no_flags")}</p>
            )}
            <p className="mt-2 text-xs text-ink-700">{t("console.settings.flags_read_only")}</p>
          </Card>

          {showReadiness ? (
            <Card aria-labelledby="s-ready" className="lg:col-span-2">
              <CardTitle id="s-ready">{t("console.settings.readiness")}</CardTitle>
              <p className="mb-2 text-xs text-ink-700">{t("console.settings.readiness_admins_only")}</p>
              {meta.error ? <ErrorAlert error={meta.error} /> : null}
              {meta.data ? (
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm" data-testid="readiness">
                  <dt className="text-ink-700">{t("console.settings.runtime")}</dt><dd>{t("console.settings.runtime_value", { environment: meta.data.environment, api: meta.data.api_version })}</dd>
                  <dt className="text-ink-700">{t("console.settings.simulators")}</dt>
                  <dd>{meta.data.simulation ? t("console.settings.simulators_active") : t("console.settings.simulators_inactive")}</dd>
                  <dt className="text-ink-700">{t("console.settings.live_providers")}</dt><dd>{t("console.settings.live_providers_unknown")}</dd>
                </dl>
              ) : null}
            </Card>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
