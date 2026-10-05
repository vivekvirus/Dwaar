import React, { useMemo } from "react";
import { Slot } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { AppProvider, createServices } from "../src/state/AppProvider";
import { SimulatorBanner } from "../src/ui/chrome";
import { View } from "react-native";
import { colors } from "../src/ui/tokens";

export default function RootLayout() {
  const services = useMemo(() => createServices(), []);
  return (
    <SafeAreaProvider>
      <AppProvider services={services}>
        <StatusBar style="dark" />
        <View style={{ flex: 1, backgroundColor: colors.bg }}>
          <SimulatorBanner />
          <Slot />
        </View>
      </AppProvider>
    </SafeAreaProvider>
  );
}
