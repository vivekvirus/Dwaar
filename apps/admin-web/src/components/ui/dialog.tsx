"use client";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { useRef, type ReactNode } from "react";
import { useT } from "@/i18n/provider";

/** Confirmation dialog (UX-05): scope, effect and required approval are stated BEFORE the action; focus is trapped and returns
 *  to the trigger on close (Radix). */
export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  children: ReactNode;
}) {
  const t = useT();
  // Radix only restores focus to a <Dialog.Trigger>; these dialogs are opened from table buttons, so we remember the opener.
  const opener = useRef<HTMLElement | null>(null);
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-slate-900/50" />
        <DialogPrimitive.Content
          onOpenAutoFocus={() => {
            opener.current = document.activeElement as HTMLElement | null;
          }}
          onCloseAutoFocus={(e) => {
            e.preventDefault();
            if (opener.current && document.contains(opener.current)) opener.current.focus();
          }}
          className="fixed left-1/2 top-1/2 z-50 max-h-[90vh] w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg bg-white p-5 shadow-xl focus:outline-none">
          <DialogPrimitive.Title className="text-lg font-semibold text-navy-950">{title}</DialogPrimitive.Title>
          <DialogPrimitive.Description className="mt-1 text-sm text-ink-700">{description}</DialogPrimitive.Description>
          <div className="mt-4">{children}</div>
          <DialogPrimitive.Close className="absolute right-3 top-3 rounded px-2 py-1 text-sm text-ink-700 hover:bg-slate-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-navy-700" aria-label={t("common.action.close")}>
            <span aria-hidden="true">x</span>
          </DialogPrimitive.Close>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
