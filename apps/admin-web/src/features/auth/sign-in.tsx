"use client";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { ErrorAlert } from "@/components/ui/error-alert";
import { Input, Label } from "@/components/ui/input";
import { authCall } from "@/lib/api-client";
import { useT } from "@/i18n/provider";
import type { SessionView } from "@/server/session";

type Step = "phone" | "otp" | "enrol" | "totp";

/** IAM-03: phone OTP, then (for elevated roles) the TOTP step-up. The browser never sees an access or refresh token. */
export function SignInFlow() {
  const t = useT();
  const [step, setStep] = useState<Step>("phone");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [simOtp, setSimOtp] = useState<string | null>(null);
  const [enrol, setEnrol] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const input = useRef<HTMLInputElement>(null);

  // Resume the TOTP step after a redirect from a console page, or skip sign-in when a full session already exists.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await authCall<SessionView>("/api/session", { method: "GET" });
        if (cancelled || !s.authenticated) return;
        if (!s.stepUpRequired) window.location.assign("/overview");
        else setStep(s.mfa.enrolled && s.mfa.confirmed ? "totp" : "enrol");
      } catch {
        /* stay on the phone step */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    input.current?.focus();
  }, [step, enrol]);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const requestOtp = (e: FormEvent) => {
    e.preventDefault();
    return run(async () => {
      await authCall("/api/auth/otp/request", { json: { phone } });
      setCode("");
      setStep("otp");
      try {
        const d = await authCall<{ otp: string }>(`/api/auth/dev-otp?phone=${encodeURIComponent(phone)}`, { method: "GET" });
        setSimOtp(d.otp);
      } catch {
        setSimOtp(null); // closed outside the labelled local simulator
      }
    });
  };

  const verifyOtp = (e: FormEvent) => {
    e.preventDefault();
    return run(async () => {
      await authCall("/api/auth/otp/verify", { json: { phone, code } });
      const s = await authCall<SessionView>("/api/session", { method: "GET" });
      if (s.authenticated && s.stepUpRequired) {
        setCode("");
        setStep(s.mfa.enrolled && s.mfa.confirmed ? "totp" : "enrol");
        return;
      }
      window.location.assign("/overview");
    });
  };

  const verifyTotp = (e: FormEvent) => {
    e.preventDefault();
    return run(async () => {
      await authCall(step === "enrol" ? "/api/auth/mfa/confirm" : "/api/auth/mfa", { json: { code } });
      window.location.assign("/overview");
    });
  };

  const startEnrol = () =>
    run(async () => {
      setEnrol(await authCall<{ secret: string; otpauth_uri: string }>("/api/auth/mfa/enrol", { json: {} }));
    });

  return (
    <main id="main" className="mx-auto mt-10 max-w-md p-4">
      <Card aria-labelledby="signin-title">
        <h1 id="signin-title" ref={heading} tabIndex={-1} className="mb-1 text-xl font-semibold text-navy-950">
          {t("console.signin.title")}
        </h1>
        <p className="mb-3 text-sm text-ink-700">{t("console.signin.intro")}</p>
        {error ? (
          <div className="mb-3">
            <ErrorAlert error={error} />
          </div>
        ) : null}

        {step === "phone" ? (
          <form onSubmit={requestOtp} className="space-y-3">
            <div>
              <Label htmlFor="phone">{t("console.signin.phone")}</Label>
              <Input id="phone" ref={input} name="phone" type="tel" autoComplete="tel" inputMode="tel" required value={phone} onChange={(e) => setPhone(e.target.value)} aria-describedby="phone-hint" />
              <p id="phone-hint" className="mt-1 text-xs text-ink-700">{t("console.signin.phone_hint")}</p>
            </div>
            <Button type="submit" disabled={busy || !phone}>{t("console.signin.send_code")}</Button>
          </form>
        ) : null}

        {step === "otp" ? (
          <form onSubmit={verifyOtp} className="space-y-3">
            <CardTitle>{t("console.signin.otp_title")}</CardTitle>
            <div>
              <Label htmlFor="otp">{t("console.signin.otp")}</Label>
              <Input id="otp" ref={input} name="otp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{4,8}" required value={code} onChange={(e) => setCode(e.target.value)} />
            </div>
            {simOtp ? (
              <Alert tone="warn" live="polite">
                <p>{t("console.signin.simulator_note")}</p>
                <Button variant="secondary" size="sm" className="mt-1" onClick={() => setCode(simOtp)}>{t("console.signin.simulator_fill")}</Button>
              </Alert>
            ) : null}
            <div className="flex gap-2">
              <Button type="submit" disabled={busy || !code}>{t("console.signin.verify")}</Button>
              <Button variant="secondary" onClick={() => setStep("phone")}>{t("common.action.back")}</Button>
            </div>
          </form>
        ) : null}

        {step === "totp" || step === "enrol" ? (
          <form onSubmit={verifyTotp} className="space-y-3">
            <CardTitle>{t("console.signin.totp_title")}</CardTitle>
            <p className="text-sm text-ink-700">{t("console.signin.totp_intro")}</p>
            {step === "enrol" && !enrol ? (
              <div>
                <Alert tone="warn">{t("console.signin.enrol_needed")}</Alert>
                <Button className="mt-2" onClick={startEnrol} disabled={busy}>{t("console.signin.enrol_start")}</Button>
              </div>
            ) : null}
            {step === "enrol" && enrol ? (
              <div className="rounded border border-slate-300 p-2 text-sm">
                <p>{t("console.signin.enrol_secret")}</p>
                <p className="mt-1 break-all font-mono text-xs" data-testid="totp-secret">{enrol.secret}</p>
              </div>
            ) : null}
            {step === "totp" || enrol ? (
              <div>
                <Label htmlFor="totp">{t("console.signin.totp")}</Label>
                <Input id="totp" ref={input} name="totp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={(e) => setCode(e.target.value)} />
              </div>
            ) : null}
            {step === "totp" || enrol ? <Button type="submit" disabled={busy || code.length !== 6}>{t("console.signin.verify")}</Button> : null}
          </form>
        ) : null}
      </Card>
    </main>
  );
}
