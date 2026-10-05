import React from "react";
import { Redirect } from "expo-router";
import { useApp } from "../src/state/AppProvider";
import { Loading } from "../src/ui/components";
import { ChooseHomeScreen } from "../src/screens/ChooseHomeScreen";

export default function ChooseUnitRoute() {
  const { status, t, active, choice } = useApp();
  if (status === "booting") return <Loading label={t("app.boot.loading")} />;
  if (status === "signedOut") return <Redirect href="/sign-in" />;
  if (active && !choice) return <Redirect href="/" />;
  return <ChooseHomeScreen />;
}
