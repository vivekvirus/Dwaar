// REQ: UX-02/UX-03, PRD 6 acceptance. Every control: role + label + state, >= 48 dp, text wraps (no fixed heights, no
// truncation), state is carried by words/glyphs as well as colour. No avatars, no promotions.
import React from "react";
import {
  ActivityIndicator,
  Pressable,
  RefreshControl,
  ScrollView,
  Text,
  TextInput,
  View,
  type StyleProp,
  type TextInputProps,
  type TextStyle,
  type ViewStyle,
} from "react-native";
import { colors, MIN_TARGET, radius, space, type } from "./tokens";
import type { Tone } from "../domain/status";

export function AppText({
  variant = "body",
  muted,
  style,
  children,
  ...rest
}: {
  variant?: "body" | "small" | "title" | "heading" | "label";
  muted?: boolean;
  style?: StyleProp<TextStyle>;
  children: React.ReactNode;
} & Omit<React.ComponentProps<typeof Text>, "style">) {
  return (
    <Text {...rest} style={[type[variant], { color: muted ? colors.textMuted : colors.text, flexShrink: 1 }, style]}>
      {children}
    </Text>
  );
}

export function Heading({ children, level = 1 }: { children: React.ReactNode; level?: 1 | 2 }) {
  return (
    <AppText variant={level === 1 ? "title" : "heading"} accessibilityRole="header" style={{ marginBottom: space.sm }}>
      {children}
    </AppText>
  );
}

type ButtonVariant = "primary" | "secondary" | "danger";
const buttonColors: Record<ButtonVariant, { bg: string; fg: string; border: string }> = {
  primary: { bg: colors.navy, fg: colors.onNavy, border: colors.navy },
  secondary: { bg: colors.surface, fg: colors.navy, border: colors.navy },
  danger: { bg: colors.surface, fg: colors.danger, border: colors.danger },
};

export function Button({
  label,
  onPress,
  variant = "primary",
  disabled,
  busy,
  hint,
  glyph,
  testID,
  style,
  accessibilityLabel,
}: {
  label: string;
  accessibilityLabel?: string;
  onPress: () => void;
  variant?: ButtonVariant;
  disabled?: boolean;
  busy?: boolean;
  hint?: string;
  glyph?: string;
  testID?: string;
  style?: StyleProp<ViewStyle>;
}) {
  const c = buttonColors[variant];
  const inactive = disabled || busy;
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? label}
      accessibilityHint={hint}
      accessibilityState={{ disabled: !!inactive, busy: !!busy }}
      disabled={inactive}
      onPress={onPress}
      style={({ pressed }) => [
        {
          minHeight: MIN_TARGET + 4,
          minWidth: MIN_TARGET,
          paddingVertical: space.md,
          paddingHorizontal: space.lg,
          borderRadius: radius.md,
          borderWidth: 2,
          borderColor: c.border,
          backgroundColor: c.bg,
          flexDirection: "row",
          alignItems: "center",
          justifyContent: "center",
          opacity: inactive ? 0.55 : pressed ? 0.85 : 1,
        },
        style,
      ]}
    >
      {busy ? <ActivityIndicator color={c.fg} style={{ marginRight: space.sm }} /> : null}
      {glyph ? (
        <Text accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={{ color: c.fg, fontSize: 18, marginRight: space.sm }}>
          {glyph}
        </Text>
      ) : null}
      <Text style={[type.label, { color: c.fg, textAlign: "center", flexShrink: 1 }]}>{label}</Text>
    </Pressable>
  );
}

/** One option of a single-choice group. Selected state = border + check glyph + accessibility state (not colour alone). */
export function Choice({
  label,
  selected,
  onPress,
  testID,
}: {
  label: string;
  selected: boolean;
  onPress: () => void;
  testID?: string;
}) {
  return (
    <Pressable
      testID={testID}
      accessibilityRole="radio"
      accessibilityLabel={label}
      accessibilityState={{ selected, checked: selected }}
      onPress={onPress}
      style={{
        minHeight: MIN_TARGET,
        paddingHorizontal: space.lg,
        paddingVertical: space.sm,
        borderRadius: radius.md,
        borderWidth: selected ? 3 : 1,
        borderColor: selected ? colors.navy : colors.border,
        backgroundColor: selected ? colors.tealSoft : colors.surface,
        flexDirection: "row",
        alignItems: "center",
      }}
    >
      <Text accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={{ color: colors.navy, fontSize: 18, marginRight: space.sm }}>
        {selected ? "◉" : "○"}
      </Text>
      <Text style={[type.label, { color: colors.text, flexShrink: 1 }]}>{label}</Text>
    </Pressable>
  );
}

export function Field({
  label,
  hint,
  error,
  testID,
  ...input
}: { label: string; hint?: string; error?: string | null; testID?: string } & Omit<TextInputProps, "style">) {
  return (
    <View style={{ marginBottom: space.lg }}>
      <AppText variant="label" style={{ marginBottom: space.xs }}>
        {label}
      </AppText>
      <TextInput
        testID={testID}
        accessibilityLabel={label}
        accessibilityHint={hint}
        placeholderTextColor={colors.textMuted}
        {...input}
        style={{
          minHeight: MIN_TARGET + 4,
          borderWidth: 2,
          borderColor: error ? colors.danger : colors.border,
          borderRadius: radius.md,
          paddingHorizontal: space.md,
          paddingVertical: space.sm,
          backgroundColor: colors.surface,
          color: colors.text,
          fontSize: 18,
        }}
      />
      {hint ? (
        <AppText variant="small" muted style={{ marginTop: space.xs }}>
          {hint}
        </AppText>
      ) : null}
      {error ? (
        <AppText variant="small" accessibilityRole="alert" style={{ marginTop: space.xs, color: colors.danger }}>
          {"✕ "}
          {error}
        </AppText>
      ) : null}
    </View>
  );
}

const toneColors: Record<Tone, { bg: string; fg: string; border: string }> = {
  neutral: { bg: colors.surface, fg: colors.text, border: colors.border },
  info: { bg: colors.infoBg, fg: colors.info, border: colors.info },
  success: { bg: colors.successBg, fg: colors.success, border: colors.success },
  warning: { bg: colors.warningBg, fg: colors.warning, border: colors.warning },
  danger: { bg: colors.dangerBg, fg: colors.danger, border: colors.danger },
};

const toneGlyph: Record<Tone, string> = { neutral: "ℹ", info: "ℹ", success: "✓", warning: "!", danger: "✕" };

export function Banner({
  tone = "info",
  children,
  alert,
  testID,
  title,
}: {
  tone?: Tone;
  children: React.ReactNode;
  alert?: boolean;
  testID?: string;
  title?: string;
}) {
  const c = toneColors[tone];
  return (
    <View
      testID={testID}
      accessibilityRole={alert ? "alert" : undefined}
      accessible
      style={{
        flexDirection: "row",
        padding: space.md,
        borderRadius: radius.md,
        borderWidth: 2,
        borderColor: c.border,
        backgroundColor: c.bg,
        marginBottom: space.md,
      }}
    >
      <Text accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={{ color: c.fg, fontSize: 18, fontWeight: "700", marginRight: space.sm }}>
        {toneGlyph[tone]}
      </Text>
      <View style={{ flex: 1 }}>
        {title ? (
          <AppText variant="label" style={{ color: c.fg }}>
            {title}
          </AppText>
        ) : null}
        {typeof children === "string" ? <AppText style={{ color: colors.text }}>{children}</AppText> : children}
      </View>
    </View>
  );
}

export function StatusPill({ label, glyph, tone, testID }: { label: string; glyph: string; tone: Tone; testID?: string }) {
  const c = toneColors[tone];
  return (
    <View
      testID={testID}
      accessible
      accessibilityLabel={label}
      style={{
        flexDirection: "row",
        alignItems: "center",
        alignSelf: "flex-start",
        paddingVertical: space.xs + 2,
        paddingHorizontal: space.md,
        borderRadius: 999,
        borderWidth: 2,
        borderColor: c.border,
        backgroundColor: c.bg,
      }}
    >
      <Text accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={{ color: c.fg, fontWeight: "700", marginRight: space.xs }}>
        {glyph}
      </Text>
      <Text style={[type.label, { color: c.fg, flexShrink: 1 }]}>{label}</Text>
    </View>
  );
}

export function Card({ children, testID, style, accessibilityLabel }: { children: React.ReactNode; testID?: string; style?: StyleProp<ViewStyle>; accessibilityLabel?: string }) {
  return (
    <View
      testID={testID}
      accessibilityLabel={accessibilityLabel}
      style={[
        {
          backgroundColor: colors.surface,
          borderRadius: radius.lg,
          borderWidth: 1,
          borderColor: colors.border,
          padding: space.lg,
          marginBottom: space.md,
        },
        style,
      ]}
    >
      {children}
    </View>
  );
}

export function Row({ label, value, testID }: { label: string; value: string; testID?: string }) {
  return (
    <View testID={testID} accessible accessibilityLabel={`${label}: ${value}`} style={{ marginBottom: space.sm }}>
      <AppText variant="small" muted>
        {label}
      </AppText>
      <AppText variant="label">{value}</AppText>
    </View>
  );
}

export function Screen({
  children,
  refreshing,
  onRefresh,
  refreshLabel,
  testID,
}: {
  children: React.ReactNode;
  refreshing?: boolean;
  onRefresh?: () => void;
  refreshLabel?: string;
  testID?: string;
}) {
  return (
    <ScrollView
      testID={testID}
      style={{ flex: 1, backgroundColor: colors.bg }}
      contentContainerStyle={{ padding: space.lg, paddingBottom: space.xxl * 2 }}
      keyboardShouldPersistTaps="handled"
      refreshControl={onRefresh ? <RefreshControl refreshing={!!refreshing} onRefresh={onRefresh} accessibilityLabel={refreshLabel} /> : undefined}
    >
      {children}
    </ScrollView>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <View accessibilityRole="progressbar" accessibilityLabel={label} accessible style={{ padding: space.xl, alignItems: "center" }}>
      <ActivityIndicator color={colors.navy} size="large" />
      <AppText muted style={{ marginTop: space.md }}>
        {label}
      </AppText>
    </View>
  );
}
