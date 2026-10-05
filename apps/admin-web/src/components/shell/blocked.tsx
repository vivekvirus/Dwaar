"use client";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { ErrorAlert } from "@/components/ui/error-alert";
import { authCall } from "@/lib/api-client";
import { useT } from "@/i18n/provider";
import type { SessionSociety } from "@/server/session";

export function SignOutButton() {
  const t = useT();
  return (
    <Button
      variant="secondary"
      onClick={async () => {
        try {
          await authCall("/api/auth/logout");
        } finally {
          window.location.assign("/signin");
        }
      }}
    >
      {t("common.action.sign_out")}
    </Button>
  );
}

/** Signed in, but no role of this person is a committee-console role (guards, residents, ...). Says nothing about why. */
export function NoConsoleAccess() {
  const t = useT();
  return (
    <main id="main" className="mx-auto max-w-xl p-6">
      <Card aria-labelledby="no-access">
        <CardTitle id="no-access">{t("console.no_access.title")}</CardTitle>
        <p className="mb-4 text-sm text-ink-700">{t("console.no_access.body")}</p>
        <SignOutButton />
      </Card>
    </main>
  );
}

export function Forbidden() {
  const t = useT();
  return (
    <div className="max-w-xl">
      <Alert tone="danger">
        <p className="font-medium">{t("console.forbidden.title")}</p>
        <p>{t("errors.not_authorised")}</p>
      </Alert>
    </div>
  );
}

/** More than one society: the person chooses explicitly; nothing is preselected on their behalf. */
export function SocietyPicker({ societies, personName }: { societies: SessionSociety[]; personName: string }) {
  const t = useT();
  const [choice, setChoice] = useState<string>("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  return (
    <main id="main" className="mx-auto max-w-xl p-6">
      <Card aria-labelledby="pick-title">
        <CardTitle id="pick-title">{t("console.society.pick_title")}</CardTitle>
        <p className="mb-3 text-sm text-ink-700">{t("console.society.pick_body", { name: personName })}</p>
        {error ? <div className="mb-3"><ErrorAlert error={error} /></div> : null}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              await authCall("/api/session/society", { json: { society_id: choice, confirm: true } });
              window.location.assign("/overview");
            } catch (err) {
              setError(err);
              setBusy(false);
            }
          }}
        >
          <fieldset className="mb-3 space-y-1.5">
            <legend className="sr-only">{t("console.society.pick_title")}</legend>
            {societies.filter((s) => s.consoleAccess).map((s) => (
              <label key={s.id} className="flex cursor-pointer items-center gap-2 rounded border border-slate-300 px-3 py-2 text-sm has-[:checked]:border-navy-700 has-[:checked]:bg-navy-50">
                <input type="radio" name="society" value={s.id} checked={choice === s.id} onChange={() => setChoice(s.id)} />
                <span>
                  <span className="font-medium">{s.name}</span>
                  <span className="ml-2 text-xs text-ink-700">{s.roles.join(", ")}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <div className="flex gap-2">
            <Button type="submit" disabled={!choice || busy}>{t("console.society.pick_action")}</Button>
            <SignOutButton />
          </div>
        </form>
      </Card>
    </main>
  );
}
