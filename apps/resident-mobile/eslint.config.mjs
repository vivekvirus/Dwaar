// Flat config. The react-native-a11y rules are enforced as errors (PRD 6: accessibility acceptance); the plugin predates
// flat config, so its rules are registered by hand.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const a11y = require("eslint-plugin-react-native-a11y");

const a11yRules = Object.fromEntries(
  Object.keys(a11y.rules)
    // has-valid-accessibility-ignores-invert-colors only concerns images (none are used); the rest apply to every component
    .map((name) => [`react-native-a11y/${name}`, "error"]),
);

export default tseslint.config(
  { ignores: ["dist/**", "e2e/.tmp/**", ".expo/**", "node_modules/**", "src/api/generated/**", "e2e/**/*.mjs", "scripts/**", "coverage/**", "babel.config.js", "jest.config.js", "expo-env.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks, "react-native-a11y": a11y },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...a11yRules,
      // hints are for controls whose effect is not obvious from the label; requiring one on every labelled element is noise
      "react-native-a11y/has-accessibility-hint": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      // INV-05 / UX-03: no hard-coded copy and no font-scaling opt-outs
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='allowFontScaling'][value.expression.value=false]", message: "Text must scale (PRD 6: 200% text)." },
        { selector: "JSXAttribute[name.name='maxFontSizeMultiplier']", message: "Do not cap font scaling (PRD 6: 200% text)." },
      ],
    },
  },
  {
    files: ["__tests__/**/*.{ts,tsx}", "jest.setup.ts"],
    rules: { "@typescript-eslint/no-explicit-any": "off", "@typescript-eslint/no-require-imports": "off" },
  },
);
