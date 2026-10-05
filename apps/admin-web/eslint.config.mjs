import { FlatCompat } from "@eslint/eslintrc";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });

const config = [
  { ignores: [".next/**", "node_modules/**", "src/api/schema.d.ts", "e2e/report/**", "test-results/**", "next-env.d.ts"] },
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXText[value=/[A-Za-z]{3,}/]",
          message: "No hard-coded UI copy: use the i18n catalogs (UX-08).",
        },
      ],
    },
  },
  { files: ["tests/**", "e2e/**", "**/*.test.tsx", "**/*.test.ts"], rules: { "no-restricted-syntax": "off" } },
];

export default config;
