"use client";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { DEFAULT_LOCALE, SUPPORTED_LOCALES, makeT, type Locale, type TFn } from "./index";

type Ctx = { locale: Locale; setLocale: (l: Locale) => void; t: TFn };
const I18nContext = createContext<Ctx>({ locale: DEFAULT_LOCALE, setLocale: () => undefined, t: makeT(DEFAULT_LOCALE) });

const STORAGE_KEY = "dwaar.admin.locale";

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(STORAGE_KEY);
      if (saved && (SUPPORTED_LOCALES as readonly string[]).includes(saved)) setLocaleState(saved as Locale);
    } catch {
      /* storage unavailable: keep default */
    }
  }, []);
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);
  const value = useMemo<Ctx>(
    () => ({
      locale,
      t: makeT(locale),
      setLocale: (l) => {
        setLocaleState(l);
        try {
          window.localStorage.setItem(STORAGE_KEY, l);
        } catch {
          /* ignore */
        }
      },
    }),
    [locale],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const useI18n = () => useContext(I18nContext);
export const useT = () => useContext(I18nContext).t;
