import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { SocietyContext } from "@/components/shell/society-context";
import { capabilitiesFor, type Capability } from "@/lib/access";
import { I18nProvider } from "@/i18n/provider";

export const SOCIETY = "019b76da-a800-713c-a879-90fe5f48356e";

export function renderConsole(ui: ReactElement, roles: string[] = ["secretary"], societyId = SOCIETY, existing?: QueryClient) {
  const client = existing ?? new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  const caps = capabilitiesFor(roles);
  const value = {
    societyId,
    society: { id: societyId, name: "Sahyadri Residency CHS (demo)", city: "Pune", roles, consoleAccess: true, stepUpPending: false },
    roles,
    capabilities: caps,
    can: (c: Capability) => caps.includes(c),
  };
  const utils = render(
    <QueryClientProvider client={client}>
      <I18nProvider>
        <SocietyContext.Provider value={value}>{ui}</SocietyContext.Provider>
      </I18nProvider>
    </QueryClientProvider>,
  );
  return { ...utils, client };
}

export type FetchCall = { url: string; method: string; headers: Record<string, string>; body: string | undefined };

/** Replaces global fetch with route handlers keyed "METHOD /path-without-query". */
export function mockFetch(routes: Record<string, (c: FetchCall) => { status?: number; json?: unknown }>) {
  const calls: FetchCall[] = [];
  const impl = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const call: FetchCall = { url, method: (init?.method ?? "GET").toUpperCase(), headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>)), body: init?.body as string | undefined };
    calls.push(call);
    const key = `${call.method} ${url.split("?")[0]}`;
    const h = routes[key];
    if (!h) return new Response(JSON.stringify({ request_id: "r", code: "not_found", message: "", message_key: "errors.not_found", details: {} }), { status: 404 });
    const out = h(call);
    return new Response(out.status === 204 ? null : JSON.stringify(out.json ?? {}), { status: out.status ?? 200, headers: { "content-type": "application/json" } });
  };
  globalThis.fetch = impl as typeof fetch;
  return calls;
}
