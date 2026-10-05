// Shared chrome: simulator banner (INV: simulators are labelled), active-household header (UX/PRD 6: active unit visible),
// bottom navigation (only released modules: no empty items).
import React from "react";
import { Pressable, Text, View } from "react-native";
import { useApp, contextKey } from "../state/AppProvider";
import { AppText } from "./components";
import { colors, MIN_TARGET, space, type } from "./tokens";

export function SimulatorBanner() {
  const { simulation, t } = useApp();
  if (!simulation) return null;
  return (
    <View
      testID="simulator-banner"
      accessible
      accessibilityRole="alert"
      accessibilityLabel={`${t("app.simulator.label")}. ${t("app.simulator.body")}`}
      style={{ backgroundColor: colors.simulatorBg, paddingVertical: space.sm, paddingHorizontal: space.lg, flexDirection: "row", flexWrap: "wrap" }}
    >
      <Text style={[type.label, { color: colors.simulatorText, marginRight: space.sm }]}>{"⚠ "}{t("app.simulator.label")}</Text>
      <Text style={[type.small, { color: colors.simulatorText, flexShrink: 1 }]}>{t("app.simulator.body")}</Text>
    </View>
  );
}

export function ActiveContextHeader() {
  const { active, labels, t } = useApp();
  if (!active) return null;
  const l = labels[contextKey(active)];
  return (
    <View
      testID="active-context"
      accessible
      accessibilityLabel={t("app.context.active", { society: l?.society ?? "-", unit: l?.unit ?? "-" })}
      style={{ backgroundColor: colors.navy, paddingVertical: space.md, paddingHorizontal: space.lg }}
    >
      <Text style={[type.label, { color: colors.onNavy }]}>{t("common.app.name")}</Text>
      <Text style={[type.small, { color: colors.onNavy }]}>
        {l ? `${l.society} · ${t("common.unit.label", { unit: l.unit })}` : t("resident.state.loading")}
      </Text>
    </View>
  );
}

export interface TabSpec {
  name: string;
  label: string;
  glyph: string;
}

/** Bottom tab bar. Always shows text, selected tab marked by state + underline + bold (not colour alone), targets >= 56 dp. */
export function TabBar({ tabs, activeName, onSelect, navLabel }: { tabs: TabSpec[]; activeName: string; onSelect: (name: string) => void; navLabel: string }) {
  return (
    <View
      accessibilityRole="tablist"
      accessibilityLabel={navLabel}
      style={{ flexDirection: "row", backgroundColor: colors.surface, borderTopWidth: 2, borderTopColor: colors.navy }}
    >
      {tabs.map((tab) => {
        const selected = tab.name === activeName;
        return (
          <Pressable
            key={tab.name}
            testID={`tab-${tab.name}`}
            accessibilityRole="tab"
            accessibilityLabel={tab.label}
            accessibilityState={{ selected }}
            onPress={() => onSelect(tab.name)}
            style={{
              flex: 1,
              minHeight: MIN_TARGET + 8,
              alignItems: "center",
              justifyContent: "center",
              paddingVertical: space.sm,
              paddingHorizontal: space.xs,
              borderTopWidth: selected ? 4 : 0,
              borderTopColor: colors.teal,
              backgroundColor: selected ? colors.tealSoft : colors.surface,
            }}
          >
            <Text accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={{ fontSize: 20, color: colors.navy }}>
              {tab.glyph}
            </Text>
            <AppText variant="small" style={{ fontWeight: selected ? "700" : "400", textAlign: "center", color: colors.navy }}>
              {tab.label}
            </AppText>
          </Pressable>
        );
      })}
    </View>
  );
}

/** Back control for screens above the tabs. Replaces the platform header link, which is 30 dp wide and named after the route. */
export function BackBar({ onBack }: { onBack: () => void }) {
  const { t } = useApp();
  return (
    <Pressable
      testID="btn-back"
      accessibilityRole="button"
      accessibilityLabel={t("common.action.back")}
      onPress={onBack}
      style={{ minHeight: MIN_TARGET, minWidth: MIN_TARGET, flexDirection: "row", alignItems: "center", alignSelf: "flex-start", paddingRight: space.lg, marginBottom: space.sm }}
    >
      <Text accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={{ fontSize: 24, color: colors.navy, marginRight: space.sm }}>
        {"←"}
      </Text>
      <AppText variant="label" style={{ color: colors.navy }}>{t("common.action.back")}</AppText>
    </Pressable>
  );
}
