import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// State is always carried by TEXT as well as colour (UX-02/WCAG 1.4.1).
const badge = cva("inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset", {
  variants: {
    tone: {
      neutral: "bg-slate-100 text-ink-900 ring-slate-300",
      ok: "bg-ok-100 text-ok-800 ring-green-300",
      warn: "bg-warn-100 text-warn-800 ring-amber-300",
      danger: "bg-danger-100 text-danger-700 ring-rose-300",
      info: "bg-navy-100 text-navy-800 ring-blue-200",
    },
  },
  defaultVariants: { tone: "neutral" },
});

export function Badge({ className, tone, ...p }: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) {
  return <span className={cn(badge({ tone }), className)} {...p} />;
}
