import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const tones = {
  info: "border-navy-700 bg-navy-50 text-navy-950",
  warn: "border-amber-600 bg-warn-100 text-warn-800",
  danger: "border-rose-700 bg-danger-100 text-danger-700",
  ok: "border-green-700 bg-ok-100 text-ok-800",
} as const;

/** role=alert for errors (announced at once), role=status for polite updates. */
export function Alert({ tone = "info", children, live, className }: { tone?: keyof typeof tones; children: ReactNode; live?: "assertive" | "polite"; className?: string }) {
  const role = live === "assertive" || (live === undefined && tone === "danger") ? "alert" : live === "polite" ? "status" : undefined;
  return (
    <div role={role} className={cn("rounded-md border-l-4 px-3 py-2 text-sm", tones[tone], className)}>
      {children}
    </div>
  );
}
