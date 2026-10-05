// REQ: UX-06 (preferences persist server-side across reinstall: preferred_language via PATCH /v1/me/profile), UX-03 (language
// en/hi/mr), INV-05 (no ad/tracking SDKs: stated and true by construction), PRD 6 Profile and Privacy.
import React, { useState } from "react";
import { View } from "react-native";
import { contextKey, useApp } from "../state/AppProvider";
import { SUPPORTED_LOCALES, type Locale } from "../i18n";
import { useNav } from "../hooks/useNav";
import { AppText, Banner, Button, Card, Choice, Heading, Row, Screen } from "../ui/components";
import { space } from "../ui/tokens";

export function ProfileScreen() {
  const { t, me, locale, setLocale, active, labels, requestChoice, contexts, signOut, services } = useApp();
  const nav = useNav();
  const [langResult, setLangResult] = useState<"saved" | "local_only" | null>(null);
  const l = active ? labels[contextKey(active)] : undefined;

  const pick = async (next: Locale) => {
    setLangResult(null);
    setLangResult(await setLocale(next));
  };

  return (
    <Screen testID="screen-profile">
      <Heading>{t("app.profile.title")}</Heading>
      {me?.person.display_name ? <Card><Row label={t("app.profile.name")} value={me.person.display_name} /></Card> : null}

      <Heading level={2}>{t("common.language.label")}</Heading>
      <View accessibilityRole="radiogroup" style={{ gap: space.sm, marginBottom: space.sm }}>
        {SUPPORTED_LOCALES.map((code) => (
          <Choice key={code} testID={`lang-${code}`} label={t(`common.language.${code}` as const)} selected={locale === code} onPress={() => void pick(code)} />
        ))}
      </View>
      <AppText variant="small" muted style={{ marginBottom: space.sm }}>{t("app.profile.language_help")}</AppText>
      {langResult === "saved" ? <Banner tone="success" testID="lang-saved">{t("app.profile.language_saved")}</Banner> : null}
      {langResult === "local_only" ? <Banner tone="warning" alert testID="lang-local">{t("app.profile.language_local")}</Banner> : null}

      <Heading level={2}>{t("app.profile.home")}</Heading>
      <Card testID="profile-home">
        {l && active ? <Row label={t("common.unit.label", { unit: l.unit })} value={`${l.society} · ${t(`app.role.${active.role}` as const)}`} /> : null}
        {contexts.length > 1 ? (
          <Button testID="btn-change-home" label={t("app.context.change")} variant="secondary" onPress={() => { requestChoice(); nav.replace("/choose-unit"); }} />
        ) : null}
      </Card>

      <Heading level={2}>{t("app.profile.privacy_title")}</Heading>
      <Card testID="privacy-card">
        <AppText style={{ marginBottom: space.sm }}>{t("app.profile.privacy_1")}</AppText>
        <AppText style={{ marginBottom: space.sm }}>{t("app.profile.privacy_2")}</AppText>
        <AppText style={{ marginBottom: space.sm }}>{t("app.profile.privacy_3")}</AppText>
        {services.notifications.available ? null : <AppText testID="alerts-note" variant="small" muted>{t("app.profile.alerts")}</AppText>}
      </Card>

      <Button testID="btn-sign-out" label={t("common.action.sign_out")} variant="secondary" onPress={() => void signOut()} />
    </Screen>
  );
}
