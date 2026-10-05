// REQ: UX-08, INV-11. All user-visible copy goes through t(); no hard-coded strings in UI code.
import { CATALOGS } from "./catalogs";
import type { I18nKey, KeyParams } from "./keys";

export { ALL_KEYS, NAMESPACES } from "./keys";
export type { I18nKey, KeyParams, Namespace } from "./keys";

export const SUPPORTED_LOCALES = ["en", "hi", "mr"] as const; // kn joins at M2
export type Locale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (SUPPORTED_LOCALES as readonly string[]).includes(value);
}

/** Map e.g. "hi-IN" or "MR_in" to a supported locale; unknown input falls back to English. */
export function resolveLocale(input: string | null | undefined): Locale {
  const base = (input ?? "").toLowerCase().split(/[-_]/)[0];
  return isLocale(base) ? base : DEFAULT_LOCALE;
}

type ParamsArg<K extends I18nKey> = KeyParams[K] extends undefined
  ? [params?: undefined]
  : [params: KeyParams[K]];

/** Raw lookup in one locale (no fallback). */
export function lookup(locale: Locale, key: string): string | undefined {
  const dot = key.indexOf(".");
  if (dot < 0) return undefined;
  const value = CATALOGS[locale]?.[key.slice(0, dot)]?.[key.slice(dot + 1)];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, name: string) => {
    const v = params[name];
    return v === undefined ? m : String(v);
  });
}

/**
 * Translate a key. Falls back locale -> English -> the key itself (never throws, never empty).
 * Unit numbers are passed through verbatim so they stay in one script across languages (UX-03).
 */
export function translate<K extends I18nKey>(locale: Locale, key: K, ...args: ParamsArg<K>): string {
  const template = lookup(locale, key) ?? lookup(DEFAULT_LOCALE, key) ?? key;
  return interpolate(template, args[0] as Record<string, string | number> | undefined);
}

export type Translator = <K extends I18nKey>(key: K, ...args: ParamsArg<K>) => string;

export function createTranslator(locale: Locale): Translator {
  return (key, ...args) => translate(locale, key, ...args);
}

/** Default English translator. */
export const t: Translator = createTranslator(DEFAULT_LOCALE);
