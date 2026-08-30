// Copyright 2026 CyberGuard AI
// Licensed under the Apache License, Version 2.0.
//
// Flat ESLint config: TypeScript + React Hooks rules for the whole workspace.
// Complements `tsc --noEmit`; catches dead code and unsafe patterns tsc allows.

import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "docs/**", "*.config.js"] },

  // Browser-side React code
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/server/**"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "no-restricted-globals": [
        "error",
        { name: "escape", message: "Deprecated. Use encodeURIComponent." },
        { name: "unescape", message: "Deprecated. Use decodeURIComponent." },
      ],
    },
  },

  // Server-side code (Node globals, no React)
  {
    files: ["server.ts", "src/server/**/*.ts", "test/**/*.ts"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.node,
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
);
