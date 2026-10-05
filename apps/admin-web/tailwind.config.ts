import type { Config } from "tailwindcss";

// Design tokens: sober navy and teal, high-contrast neutrals, restrained animation, compact committee density (PRD 6).
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: { 950: "#0b1b33", 900: "#10264a", 800: "#183663", 700: "#1f4580", 100: "#e3ebf7", 50: "#f1f5fb" },
        teal: { 800: "#0b5f63", 700: "#0f766e", 600: "#0d8a80", 100: "#d5f0ec", 50: "#eef9f7" },
        ink: { 900: "#0f172a", 700: "#334155", 600: "#475569" },
        danger: { 700: "#9f1239", 100: "#ffe4e9" },
        warn: { 800: "#854d0e", 100: "#fef3c7" },
        ok: { 800: "#166534", 100: "#dcfce7" },
      },
      fontSize: { xs: ["0.8125rem", "1.125rem"], sm: ["0.875rem", "1.25rem"] },
      transitionDuration: { DEFAULT: "120ms" },
    },
  },
  plugins: [],
};
export default config;
