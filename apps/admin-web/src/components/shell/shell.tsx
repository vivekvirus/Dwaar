"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Modal } from "@/components/ui/dialog";
import { Select, Label } from "@/components/ui/input";
import { SocietyContext } from "./society-context";
import { authCall } from "@/lib/api-client";
import type { Capability, NavItem } from "@/lib/access";
import { SUPPORTED_LOCALES, type Locale } from "@/i18n";
import { useI18n, useT } from "@/i18n/provider";
import type { SessionSociety } from "@/server/session";

export type ShellProps = {
  person: { displayName: string };
  simulation: boolean;
  societies: SessionSociety[];
  selectedSocietyId: string;
  capabilities: Capability[];
  nav: NavItem[];
  children: ReactNode;
};

const SWITCH_FLAG = "dwaar.admin.switched";

export function Shell({ person, simulation, societies, selectedSocietyId, capabilities, nav, children }: ShellProps) {
  const t = useT();
  const { locale, setLocale } = useI18n();
  const pathname = usePathname();
  const society = societies.find((s) => s.id === selectedSocietyId)!;
  const usable = societies.filter((s) => s.consoleAccess);
  const ctx = useMemo(
    () => ({ societyId: selectedSocietyId, society, roles: society.roles, capabilities, can: (c: Capability) => capabilities.includes(c) }),
    [selectedSocietyId, society, capabilities],
  );
  const groups = useMemo(() => {
    const out: { key: NavItem["groupKey"]; items: NavItem[] }[] = [];
    for (const item of nav) {
      const g = out.find((x) => x.key === item.groupKey);
      if (g) g.items.push(item);
      else out.push({ key: item.groupKey, items: [item] });
    }
    return out;
  }, [nav]);

  // The "you are now working in ..." banner survives the full reload that follows an explicit switch.
  const [switchedTo, setSwitchedTo] = useState<string | null>(null);
  useEffect(() => {
    try {
      const v = window.sessionStorage.getItem(SWITCH_FLAG);
      if (v) {
        setSwitchedTo(v);
        window.sessionStorage.removeItem(SWITCH_FLAG);
      }
    } catch {
      /* storage unavailable: the header still names the society */
    }
  }, []);

  async function signOut() {
    try {
      await authCall("/api/auth/logout");
    } finally {
      window.location.assign("/signin");
    }
  }

  return (
    <SocietyContext.Provider value={ctx}>
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 focus:text-navy-900">
        {t("console.shell.skip")}
      </a>
      <div className="flex min-h-screen flex-col lg:flex-row">
        <aside className="bg-navy-950 text-white lg:w-60 lg:shrink-0">
          <div className="px-4 py-3 text-lg font-semibold">{t("common.app.name")} <span className="text-sm font-normal text-slate-200">{t("console.shell.console")}</span></div>
          <nav aria-label={t("console.shell.primary_nav")} className="px-2 pb-3">
            {groups.map((g) => (
              <div key={g.key} className="mb-2">
                <h2 className="px-2 pb-0.5 pt-2 text-xs font-semibold uppercase tracking-wide text-slate-300">{t(g.key)}</h2>
                <ul className="space-y-0.5">
                  {g.items.map((n) => {
                    const active = pathname === n.href || pathname.startsWith(`${n.href}/`);
                    return (
                      <li key={n.id}>
                        <Link href={n.href} aria-current={active ? "page" : undefined} className={`block rounded px-2 py-1.5 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-white ${active ? "bg-teal-700 text-white" : "text-slate-100 hover:bg-navy-800"}`}>
                          {t(n.labelKey)}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </nav>
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-300 bg-white px-4 py-2">
            <SocietySwitcher societies={usable} selectedId={selectedSocietyId} />
            <div className="flex flex-wrap items-center gap-3 text-sm">
              {simulation ? <span className="rounded bg-warn-100 px-1.5 py-0.5 text-xs font-medium text-warn-800">{t("console.shell.simulation")}</span> : null}
              <div>
                <Label htmlFor="lang" className="sr-only">{t("common.language.label")}</Label>
                <Select id="lang" value={locale} onChange={(e) => setLocale(e.target.value as Locale)} className="min-h-8 w-auto py-0.5">
                  {SUPPORTED_LOCALES.map((l) => (
                    <option key={l} value={l}>{t(`common.language.${l}` as const)}</option>
                  ))}
                </Select>
              </div>
              <Link href="/account/sessions" className="rounded px-1 text-navy-800 underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-navy-700">{person.displayName}</Link>
              <Button variant="secondary" size="sm" onClick={signOut}>{t("common.action.sign_out")}</Button>
            </div>
          </header>
          {switchedTo ? (
            <div className="px-4 pt-3">
              <Alert tone="ok" live="polite">
                <div className="flex items-center justify-between gap-2">
                  <span data-testid="switch-banner">{t("console.society.switched_banner", { society: switchedTo })}</span>
                  <Button variant="ghost" size="sm" onClick={() => setSwitchedTo(null)}>{t("common.action.close")}</Button>
                </div>
              </Alert>
            </div>
          ) : null}
          <main id="main" tabIndex={-1} className="min-w-0 flex-1 p-4 focus:outline-none">
            {children}
          </main>
        </div>
      </div>
    </SocietyContext.Provider>
  );
}

function SocietySwitcher({ societies, selectedId }: { societies: SessionSociety[]; selectedId: string }) {
  const t = useT();
  const qc = useQueryClient();
  const current = societies.find((s) => s.id === selectedId);
  const [target, setTarget] = useState(selectedId);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const targetSociety = societies.find((s) => s.id === target);

  async function confirmSwitch() {
    setBusy(true);
    setError(null);
    try {
      await authCall("/api/session/society", { json: { society_id: target, confirm: true } });
      qc.clear(); // nothing cached for the previous society may survive the switch
      try {
        window.sessionStorage.setItem(SWITCH_FLAG, targetSociety?.name ?? "");
      } catch {
        /* ignore */
      }
      window.location.assign("/overview");
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-end gap-2" data-testid="society-selector">
      <div>
        <p className="text-xs font-medium text-ink-700" id="society-label">{t("console.society.working_in")}</p>
        {societies.length > 1 ? (
          <Select aria-labelledby="society-label" value={target} onChange={(e) => setTarget(e.target.value)} className="min-w-56">
            {societies.map((s) => (
              <option key={s.id} value={s.id}>{s.name}{s.id === selectedId ? ` (${t("console.society.current")})` : ""}</option>
            ))}
          </Select>
        ) : (
          <p className="text-sm font-semibold text-navy-900" aria-labelledby="society-label" data-testid="society-name">{current?.name}</p>
        )}
      </div>
      {societies.length > 1 ? (
        <Button ref={trigger} variant="secondary" size="sm" disabled={target === selectedId} onClick={() => setOpen(true)}>
          {t("console.society.switch")}
        </Button>
      ) : null}
      <Modal open={open} onOpenChange={setOpen} title={t("console.society.confirm_title", { society: targetSociety?.name ?? "" })} description={t("console.society.confirm_body")}>
        {error ? <div className="mb-3"><ErrorAlert error={error} /></div> : null}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setOpen(false)}>{t("common.action.cancel")}</Button>
          <Button onClick={confirmSwitch} disabled={busy}>{t("console.society.confirm_action")}</Button>
        </div>
      </Modal>
    </div>
  );
}
