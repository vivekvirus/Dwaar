import React from "react";
import { Redirect } from "expo-router";
import { useApp } from "../src/state/AppProvider";
import { Loading } from "../src/ui/components";
import { SignInScreen } from "../src/screens/SignInScreen";

export default function SignInRoute() {
  const { status, t } = useApp();
  if (status === "booting") return <Loading label={t("app.boot.loading")} />;
  if (status === "signedIn") return <Redirect href="/" />;
  return <SignInScreen />;
}
