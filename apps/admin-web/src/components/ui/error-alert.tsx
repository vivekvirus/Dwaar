"use client";
import { Alert } from "./alert";
import { mapError } from "@/lib/errors";
import { useT } from "@/i18n/provider";

/** Renders ANY thrown value through the PRD 12.2 code -> i18n mapping. Request id is shown for support; message text is not. */
export function ErrorAlert({ error }: { error: unknown }) {
  const t = useT();
  if (!error) return null;
  const m = mapError(error);
  return (
    <Alert tone="danger">
      <p>{t(m.key, m.params)}</p>
      {m.reasonKey ? <p className="mt-0.5">{t(m.reasonKey)}</p> : null}
      {m.requestId && m.key !== "errors.unknown" ? <p className="mt-0.5 text-xs">{t("errors.request_id.label", { request_id: m.requestId })}</p> : null}
    </Alert>
  );
}
