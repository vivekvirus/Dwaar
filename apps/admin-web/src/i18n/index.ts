// REQ: UX-08, INV-11. Shared copy comes from @dwaar/i18n (errors, states, common); console-only copy lives in ./console.*.json
// under the "console." prefix. hi/mr console catalogs do not exist yet: they fall back to English (reported, not hidden).
import { DEFAULT_LOCALE, SUPPORTED_LOCALES, interpolate, lookup, type I18nKey, type Locale } from "@dwaar/i18n";
import en from "./console.en.json";

export { DEFAULT_LOCALE, SUPPORTED_LOCALES };
export type { Locale };

export type ConsoleKey = `console.${keyof typeof en & string}`;
export type MessageKey = ConsoleKey | I18nKey;
export type Params = Record<string, string | number>;

const CONSOLE: Record<string, Record<string, string>> = { en };

export function consoleKeys(): string[] {
  return Object.keys(en).map((k) => `console.${k}`);
}

export function message(locale: Locale, key: MessageKey, params?: Params): string {
  if (key.startsWith("console.")) {
    const k = key.slice("console.".length);
    const template = CONSOLE[locale]?.[k] ?? CONSOLE[DEFAULT_LOCALE]?.[k] ?? key;
    return interpolate(template, params);
  }
  // @dwaar/i18n falls back locale -> English -> key
  return lookup(locale, key) === undefined && lookup(DEFAULT_LOCALE, key) === undefined
    ? key
    : interpolate(lookup(locale, key) ?? (lookup(DEFAULT_LOCALE, key) as string), params);
}

export type TFn = (key: MessageKey, params?: Params) => string;
export const makeT = (locale: Locale): TFn => (key, params) => message(locale, key, params);
