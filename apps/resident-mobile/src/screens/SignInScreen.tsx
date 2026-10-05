// REQ: IAM-14 (OTP sign-in), PRD 6. The simulator is labelled (SimulatorBanner in the root layout + the helper button).
import React, { useEffect, useState } from "react";
import { View } from "react-native";
import { ApiError, errorMessage, isApiError } from "../api/errors";
import { useApp } from "../state/AppProvider";
import { AppText, Banner, Button, Field, Heading, Screen } from "../ui/components";
import { space } from "../ui/tokens";

export function normalisePhone(raw: string): string {
  const compact = raw.replace(/[\s()-]/g, "");
  return compact;
}

export function SignInScreen() {
  const { t, services, signInWithOtp, simulation, sessionEnded } = useApp();
  const [step, setStep] = useState<"phone" | "code">("phone");
  const [phone, setPhone] = useState("+91");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  useEffect(() => setError(null), [step]);

  const sendCode = async () => {
    setBusy(true);
    setError(null);
    try {
      await services.api.otpRequest(normalisePhone(phone));
      setInfo(t("app.signin.code_sent"));
      setStep("code");
    } catch (e) {
      setError(errorMessage(e, t));
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    setBusy(true);
    setError(null);
    try {
      await signInWithOtp(normalisePhone(phone), code.trim());
    } catch (e) {
      // wrong or expired code, unknown number: one message that says nothing about membership
      const generic = isApiError(e) && [400, 401, 404].includes((e as ApiError).status);
      setError(generic ? t("app.signin.failed") : errorMessage(e, t));
    } finally {
      setBusy(false);
    }
  };

  const fillFromSimulator = async () => {
    try {
      const d = await services.api.devOtp(normalisePhone(phone));
      setCode(d.otp);
    } catch (e) {
      setError(errorMessage(e, t));
    }
  };

  return (
    <Screen testID="screen-sign-in">
      <Heading>{t("app.signin.title")}</Heading>
      {sessionEnded ? <Banner tone="warning" alert>{t("app.state.session_ended")}</Banner> : null}
      {step === "phone" ? (
        <View>
          <Field
            testID="input-phone"
            label={t("app.signin.phone")}
            hint={t("app.signin.phone_hint")}
            value={phone}
            onChangeText={setPhone}
            keyboardType="phone-pad"
            autoComplete="tel"
            textContentType="telephoneNumber"
            autoCapitalize="none"
          />
          {error ? <Banner tone="danger" alert>{error}</Banner> : null}
          <Button testID="btn-send-code" label={t("app.signin.send_code")} onPress={sendCode} busy={busy} disabled={normalisePhone(phone).length < 8} />
        </View>
      ) : (
        <View>
          {info ? <Banner tone="info">{info}</Banner> : null}
          <AppText muted style={{ marginBottom: space.md }}>{normalisePhone(phone)}</AppText>
          <Field
            testID="input-code"
            label={t("app.signin.code")}
            value={code}
            onChangeText={(v) => setCode(v.replace(/\D/g, "").slice(0, 6))}
            keyboardType="number-pad"
            autoComplete="one-time-code"
            textContentType="oneTimeCode"
            maxLength={6}
          />
          {error ? <Banner tone="danger" alert>{error}</Banner> : null}
          {simulation ? (
            <View style={{ marginBottom: space.md }}>
              <Button testID="btn-sim-code" variant="secondary" glyph="⚠" label={`${t("app.simulator.label")}: ${t("app.signin.use_simulator_code")}`} onPress={fillFromSimulator} />
            </View>
          ) : null}
          <Button testID="btn-verify" label={t("app.signin.verify")} onPress={verify} busy={busy} disabled={code.length !== 6} />
          <View style={{ height: space.md }} />
          <Button variant="secondary" label={t("app.signin.change_number")} onPress={() => { setCode(""); setStep("phone"); }} />
        </View>
      )}
    </Screen>
  );
}
