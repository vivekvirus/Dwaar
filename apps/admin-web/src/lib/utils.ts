import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));

/** Money is integer paise (INV-02); format only for display. */
export function formatPaise(paise: number | null | undefined): string {
  if (paise === null || paise === undefined) return "";
  const rupees = Math.trunc(paise / 100);
  const frac = Math.abs(paise % 100).toString().padStart(2, "0");
  return `${rupees.toLocaleString("en-IN")}.${frac}`;
}

/** Stored UTC, presented Asia/Kolkata (Brief section 3). */
export function formatIst(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", dateStyle: "medium", timeStyle: "short", hour12: false }).format(d);
}

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(-8) : "";
}
