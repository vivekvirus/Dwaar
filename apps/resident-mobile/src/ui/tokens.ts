// REQ: UX-02, UX-03 (PRD 6): sober navy/teal, high contrast, touch targets >= 48 dp. Every foreground/background pair
// below is checked for >= 4.5:1 by __tests__/contrast.test.ts. No promotional colours, no avatars.
export const colors = {
  navy: "#0B2545",
  navySoft: "#13315C",
  teal: "#0B6E6E",
  tealSoft: "#E3F2F2",
  bg: "#F5F7FA",
  surface: "#FFFFFF",
  text: "#14213D",
  textMuted: "#475569",
  border: "#64748B",
  onNavy: "#FFFFFF",
  info: "#0B4A8F",
  infoBg: "#E6F0FB",
  success: "#0B6B3A",
  successBg: "#E6F5EC",
  warning: "#7A4300",
  warningBg: "#FFF3DC",
  danger: "#A4161A",
  dangerBg: "#FDE9E9",
  simulatorBg: "#FFE08A",
  simulatorText: "#3B2A00",
} as const;

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 } as const;

/** Minimum interactive target (dp). PRD 6 acceptance: >= 48. */
export const MIN_TARGET = 48;

export const type = {
  body: { fontSize: 16, lineHeight: 26 },
  small: { fontSize: 14, lineHeight: 22 },
  title: { fontSize: 22, lineHeight: 32, fontWeight: "700" as const },
  heading: { fontSize: 18, lineHeight: 28, fontWeight: "700" as const },
  label: { fontSize: 16, lineHeight: 24, fontWeight: "600" as const },
};

export const radius = { md: 10, lg: 14 } as const;
