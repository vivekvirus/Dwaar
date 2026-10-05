import React from "react";
import { Redirect, Stack } from "expo-router";
import { View } from "react-native";
import { useApp } from "../../src/state/AppProvider";
import { ActiveContextHeader } from "../../src/ui/chrome";
import { Loading } from "../../src/ui/components";
import { colors } from "../../src/ui/tokens";

export default function AppLayout() {
  const { status, active, choice, t, loadingMe } = useApp();
  if (status === "booting" || (status === "signedIn" && loadingMe && !active && !choice)) return <Loading label={t("app.boot.loading")} />;
  if (status === "signedOut") return <Redirect href="/sign-in" />;
  if (!active || choice) return <Redirect href="/choose-unit" />;
  return (
    <View style={{ flex: 1 }}>
      <ActiveContextHeader />
      <Stack
        // no platform header: its back link is 30 dp wide; screens above the tabs render their own 48 dp BackBar
        screenOptions={{ headerShown: false, contentStyle: { backgroundColor: colors.bg } }}
      >
        <Stack.Screen name="(tabs)" />
        <Stack.Screen name="approval/[id]" />
        <Stack.Screen name="invite/new" />
        <Stack.Screen name="invite/[id]" />
      </Stack>
    </View>
  );
}
