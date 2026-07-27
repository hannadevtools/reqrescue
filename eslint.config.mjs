import eslint from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

const eslintConfig = defineConfig([
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  globalIgnores([
    ".next/**",
    "dist/**",
    "outputs/**",
    "out/**",
    "build/**",
    "work/**",
    ".tools/**",
    "next-env.d.ts",
  ]),
  {
    files: ["app/**/*.{ts,tsx}", "worker/**/*.ts"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.serviceworker,
      },
    },
  },
  {
    files: [
      "scripts/**/*.{js,mjs}",
      "tests/**/*.{js,mjs,ts,tsx}",
      "playwright.config.ts",
    ],
    languageOptions: {
      globals: globals.node,
    },
  },
]);

export default eslintConfig;
