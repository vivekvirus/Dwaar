// App-wide state: session, /v1/me, language, the ACTIVE household context. REQ: INV-01, UX-08, PRD 6.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { Platform } from "react-native";
import { API_BASE_URL } from "../config";
import { ApiClient } from "../api/client";
import { createApi, type Api } from "../api/endpoints";
import { SessionManager } from "../auth/session";
import { createTokenStore, type TokenStore } from "../auth/tokenStore";
import {
  deriveContexts,
  resolveContext,
  sameContext,
  type HouseholdContext,
} from "../domain/household";
import type { Me } from "../domain/types";
import { DEFAULT_LOCALE, createT, isLocale, type Locale, type TFn } from "../i18n";
import { NoopNotificationAdapter, type NotificationAdapter } from "../notifications/adapter";
import { DataCache } from "./resource";
import {
  asyncPrefs,
  deviceId,
  loadLocale,
  loadStoredContext,
  storeContext,
  storeLocale,
  type PrefsStore,
} from "./prefs";

export type AuthStatus = "booting" | "signedOut" | "signedIn";

export interface ContextLabel {
  society: string;
  unit: string;
}

export interface AppServices {
  api: Api;
  session: SessionManager;
  prefs: PrefsStore;
  notifications: NotificationAdapter;
}

export interface AppState {
  status: AuthStatus;
  sessionEnded: boolean;
  me: Me | null;
  simulation: boolean;
  locale: Locale;
  t: TFn;
  contexts: HouseholdContext[];
  labels: Record<string, ContextLabel>;
  active: HouseholdContext | null;
  /** set when a household must be chosen; `stale` = the previous choice is gone */
  choice: { stale: boolean } | null;
  loadingMe: boolean;
  services: AppServices;
  cache: DataCache;
  signInWithOtp(phone: string, code: string): Promise<void>;
  signOut(): Promise<void>;
  selectContext(ctx: HouseholdContext): Promise<void>;
  requestChoice(): void;
  setLocale(locale: Locale): Promise<"saved" | "local_only">;
  reloadMe(): Promise<void>;
}

const Ctx = createContext<AppState | null>(null);

export const contextKey = (c: HouseholdContext) => `${c.societyId}:${c.unitId}:${c.role}`;

export function createServices(overrides: Partial<AppServices> & { store?: TokenStore } = {}): AppServices {
  const session = overrides.session ?? new SessionManager(overrides.store ?? createTokenStore(), API_BASE_URL);
  const client = new ApiClient({ baseUrl: API_BASE_URL, session });
  return {
    session,
    api: overrides.api ?? createApi(client),
    prefs: overrides.prefs ?? asyncPrefs,
    notifications: overrides.notifications ?? new NoopNotificationAdapter(),
  };
}

export function AppProvider({ services, children }: { services: AppServices; children: React.ReactNode }) {
  const { api, session, prefs } = services;
  const [status, setStatus] = useState<AuthStatus>("booting");
  const [sessionEnded, setSessionEnded] = useState(false);
  const [me, setMe] = useState<Me | null>(null);
  const [simulation, setSimulation] = useState(false);
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);
  const [contexts, setContexts] = useState<HouseholdContext[]>([]);
  const [labels, setLabels] = useState<Record<string, ContextLabel>>({});
  const [active, setActive] = useState<HouseholdContext | null>(null);
  const [choice, setChoice] = useState<{ stale: boolean } | null>(null);
  const [loadingMe, setLoadingMe] = useState(false);
  const cache = useRef(new DataCache()).current;
  const t = useMemo(() => createT(locale), [locale]);

  const resetSignedOut = useCallback(() => {
    setMe(null);
    setContexts([]);
    setLabels({});
    setActive(null);
    setChoice(null);
    cache.clear();
  }, [cache]);

  const resolveLabels = useCallback(
    async (list: HouseholdContext[]) => {
      const societies = new Map<string, string>();
      const next: Record<string, ContextLabel> = {};
      await Promise.all(
        list.map(async (c) => {
          const [soc, unit] = await Promise.allSettled([
            societies.has(c.societyId) ? Promise.resolve(societies.get(c.societyId)!) : api.society(c.societyId).then((s) => s.name),
            api.unit(c.societyId, c.unitId).then((u) => u.label),
          ]);
          if (soc.status === "fulfilled") societies.set(c.societyId, soc.value);
          next[contextKey(c)] = {
            society: soc.status === "fulfilled" ? soc.value : "-",
            unit: unit.status === "fulfilled" ? unit.value : "-",
          };
        }),
      );
      setLabels((prev) => ({ ...prev, ...next }));
    },
    [api],
  );

  const applyMe = useCallback(
    async (m: Me) => {
      setMe(m);
      const serverLang = m.person.preferred_language;
      const stored = await loadLocale(prefs);
      const chosen = isLocale(serverLang) ? serverLang : isLocale(stored) ? stored : DEFAULT_LOCALE;
      setLocaleState(chosen);
      const offered = deriveContexts(m);
      setContexts(offered);
      const storedCtx = await loadStoredContext(prefs, m.person.id);
      const res = resolveContext(offered, storedCtx);
      if (res.kind === "active") {
        setActive((prev) => (sameContext(prev, res.context) ? prev : res.context));
        setChoice(null);
        if (!res.chosenByUser) await storeContext(prefs, m.person.id, res.context);
      } else {
        setActive(null);
        setChoice(res.kind === "choose" ? { stale: res.stale } : null);
        if (res.kind === "choose" && res.stale) await storeContext(prefs, m.person.id, null);
      }
      void resolveLabels(offered);
    },
    [prefs, resolveLabels],
  );

  const reloadMe = useCallback(async () => {
    setLoadingMe(true);
    try {
      await applyMe(await api.me());
    } finally {
      setLoadingMe(false);
    }
  }, [api, applyMe]);

  // boot: restore tokens, then ask the server who we are
  useEffect(() => {
    let alive = true;
    (async () => {
      const m = await api.meta().catch(() => null);
      if (alive && m) setSimulation(m.simulation);
      const has = await session.restore();
      if (!alive) return;
      if (!has) return setStatus("signedOut");
      try {
        setLoadingMe(true);
        await applyMe(await api.me());
        if (alive) setStatus("signedIn");
      } catch {
        // offline or expired: 401 already cleared the session via the client; otherwise stay signed out and let the person retry
        if (alive) setStatus(session.signedIn ? "signedIn" : "signedOut");
      } finally {
        if (alive) setLoadingMe(false);
      }
    })();
    const off = session.subscribe((e) => {
      if (e === "expired") {
        resetSignedOut();
        setSessionEnded(true);
        setStatus("signedOut");
      }
    });
    return () => {
      alive = false;
      off();
    };
  }, [api, session, applyMe, resetSignedOut]);

  const signInWithOtp = useCallback(
    async (phone: string, code: string) => {
      const id = await deviceId(prefs);
      const pair = await api.otpVerify(phone, code, {
        device_id: id,
        label: Platform.OS === "web" ? "Dwaar resident app (web)" : `Dwaar resident app (${Platform.OS})`,
        platform: Platform.OS,
      });
      await session.signedInWith(pair);
      setSimulation(pair.simulation);
      setSessionEnded(false);
      await applyMe(await api.me());
      setStatus("signedIn");
    },
    [api, session, prefs, applyMe],
  );

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* best effort: the local tokens are wiped either way */
    }
    await session.clear("signed_out");
    resetSignedOut();
    setSessionEnded(false);
    setStatus("signedOut");
  }, [api, session, resetSignedOut]);

  const selectContext = useCallback(
    async (ctx: HouseholdContext) => {
      // only an explicit choice among the contexts the server offers; anything else is refused (fail closed)
      if (!contexts.some((c) => sameContext(c, ctx))) return;
      if (me) await storeContext(prefs, me.person.id, ctx);
      if (!sameContext(active, ctx)) cache.clear();
      setActive(ctx);
      setChoice(null);
    },
    [contexts, me, prefs, active, cache],
  );

  const requestChoice = useCallback(() => {
    setActive(null);
    setChoice({ stale: false });
    cache.clear();
  }, [cache]);

  const setLocale = useCallback(
    async (next: Locale): Promise<"saved" | "local_only"> => {
      setLocaleState(next);
      await storeLocale(prefs, next);
      try {
        await api.updateProfile({ preferred_language: next });
        return "saved";
      } catch {
        return "local_only";
      }
    },
    [api, prefs],
  );

  const value: AppState = {
    status,
    sessionEnded,
    me,
    simulation,
    locale,
    t,
    contexts,
    labels,
    active,
    choice,
    loadingMe,
    services,
    cache,
    signInWithOtp,
    signOut,
    selectContext,
    requestChoice,
    setLocale,
    reloadMe,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp outside AppProvider");
  return v;
}
