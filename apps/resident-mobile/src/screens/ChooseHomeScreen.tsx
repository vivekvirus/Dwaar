// REQ: INV-01 / PRD 6: the selector never silently changes context. Only contexts the server offers are listed.
import React from "react";
import { View } from "react-native";
import { contextKey, useApp } from "../state/AppProvider";
import { useNav } from "../hooks/useNav";
import { AppText, Banner, Button, Heading, Screen } from "../ui/components";
import { space } from "../ui/tokens";

export function ChooseHomeScreen() {
  const { t, contexts, labels, active, choice, selectContext, signOut, loadingMe } = useApp();
  const nav = useNav();
  if (contexts.length === 0 && !loadingMe) {
    return (
      <Screen testID="screen-no-household">
        <Heading>{t("app.context.none_title")}</Heading>
        <Banner tone="warning" alert>{t("app.context.none_body")}</Banner>
        <Button label={t("common.action.sign_out")} variant="secondary" onPress={() => void signOut()} />
      </Screen>
    );
  }
  return (
    <Screen testID="screen-choose-home">
      <Heading>{t("app.context.title")}</Heading>
      {choice?.stale ? <Banner tone="warning" alert>{t("app.context.stale")}</Banner> : null}
      <AppText muted style={{ marginBottom: space.lg }}>{t("app.context.intro")}</AppText>
      {contexts.map((c) => {
        const l = labels[contextKey(c)];
        const isCurrent = !!active && contextKey(active) === contextKey(c);
        const role = t(`app.role.${c.role}` as const);
        const label = l ? t("app.context.choose", { society: l.society, unit: l.unit, role }) : t("app.context.loading_names");
        return (
          <View key={contextKey(c)} style={{ marginBottom: space.md }}>
            <Button
              testID={`ctx-${c.unitId}`}
              label={isCurrent ? `${label} - ${t("app.context.current")}` : label}
              variant={isCurrent ? "primary" : "secondary"}
              disabled={!l}
              onPress={async () => {
                await selectContext(c);
                nav.go("/");
              }}
            />
          </View>
        );
      })}
    </Screen>
  );
}
