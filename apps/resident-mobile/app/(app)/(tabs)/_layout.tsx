import React from "react";
import { Slot, usePathname, useRouter } from "expo-router";
import { View } from "react-native";
import { useApp } from "../../../src/state/AppProvider";
import { TabBar } from "../../../src/ui/chrome";

const ROUTES: Record<string, string> = { index: "/", visitors: "/visitors", profile: "/profile" };

function activeTab(pathname: string): string {
  if (pathname.startsWith("/visitors")) return "visitors";
  if (pathname.startsWith("/profile")) return "profile";
  return "index";
}

/**
 * Bottom navigation around a <Slot/>: only the CURRENT tab is mounted. (The stock Tabs navigator keeps visited tabs mounted
 * and focusable behind aria-hidden, which axe reports as aria-hidden-focus, and they keep polling in the background.)
 */
export default function TabsLayout() {
  const { t } = useApp();
  const router = useRouter();
  const pathname = usePathname();
  // Only released modules are tabs. Dues, Help and Community have no backend yet and are not shown at all.
  const specs = [
    { name: "index", label: t("app.nav.home"), glyph: "⌂" },
    { name: "visitors", label: t("app.nav.visitors"), glyph: "☰" },
    { name: "profile", label: t("app.nav.profile"), glyph: "☺" },
  ];
  return (
    <View style={{ flex: 1 }}>
      <View style={{ flex: 1 }}>
        <Slot />
      </View>
      <TabBar
        tabs={specs}
        navLabel={t("app.nav.label")}
        activeName={activeTab(pathname)}
        onSelect={(name) => router.replace((ROUTES[name] ?? "/") as never)}
      />
    </View>
  );
}
