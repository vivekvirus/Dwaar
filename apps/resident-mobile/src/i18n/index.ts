// REQ: UX-03, UX-08. All visible copy comes from @dwaar/i18n (shared keys) or the app-local "app." catalog (appStrings.ts).
import {
  DEFAULT_LOCALE,
  SUPPORTED_LOCALES,
  interpolate,
  isLocale,
  translate,
  type I18nKey,
  type KeyParams,
  type Locale,
} from "@dwaar/i18n";
import { APP_CATALOGS, type AppKey } from "./appStrings";

export { DEFAULT_LOCALE, SUPPORTED_LOCALES, isLocale };
export type { Locale, AppKey, I18nKey };

export type TKey = I18nKey | AppKey;
type SharedParams<K extends I18nKey> = KeyParams[K] extends undefined ? Record<string, never> | undefined : KeyParams[K];

export type TFn = {
  <K extends I18nKey>(key: K, params?: SharedParams<K>): string;
  (key: AppKey, params?: Record<string, string | number>): string;
  /** a key only known as the union (e.g. from domain/status): params are checked at the call site that picked the key */
  (key: TKey, params?: Record<string, string | number>): string;
};

export function isAppKey(key: string): key is AppKey {
  return key.startsWith("app.");
}

export function createT(locale: Locale): TFn {
  const fn = (key: string, params?: Record<string, string | number>): string => {
    if (isAppKey(key)) {
      const template = APP_CATALOGS[locale][key] ?? APP_CATALOGS[DEFAULT_LOCALE][key] ?? key;
      return interpolate(template, params);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return translate(locale, key as I18nKey, params as any);
  };
  return fn as TFn;
}

/** Locale of the numbers/dates: always Latin digits so unit numbers and times stay in one script (UX-03). */
const INTL_TAG: Record<Locale, string> = { en: "en-IN-u-nu-latn", hi: "hi-IN-u-nu-latn", mr: "mr-IN-u-nu-latn" };

export function formatDateTime(iso: string | null | undefined, locale: Locale): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat(INTL_TAG[locale], {
    timeZone: "Asia/Kolkata",
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  }).format(d);
}

export function formatTime(iso: string | null | undefined, locale: Locale): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat(INTL_TAG[locale], {
    timeZone: "Asia/Kolkata",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  }).format(d);
}
