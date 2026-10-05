import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Card({ className, ...p }: HTMLAttributes<HTMLElement>) {
  return <section className={cn("rounded-lg border border-slate-300 bg-white p-4 shadow-sm", className)} {...p} />;
}

export function CardTitle({ children, id, className }: { children: ReactNode; id?: string; className?: string }) {
  return (
    <h2 id={id} className={cn("mb-2 text-base font-semibold text-navy-900", className)}>
      {children}
    </h2>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-navy-950">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-ink-700">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}
