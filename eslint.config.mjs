import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", ".routecairn-*/**", "reports/**", "apps/dashboard-ui/dist/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx,mjs}"],
    languageOptions: { parserOptions: { ecmaVersion: 2024, sourceType: "module" } },
    rules: {
      "no-control-regex": "off",
      "no-useless-escape": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      "@typescript-eslint/ban-ts-comment": "off",
      "no-extra-boolean-cast": "off",
      "prefer-const": "off",
      "eqeqeq": ["error", "always"],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-template-curly-in-string": "error"
    }
  },
  {
    files: ["**/*.mjs"],
    languageOptions: {
      globals: {
        Buffer: "readonly",
        console: "readonly",
        process: "readonly",
        structuredClone: "readonly",
        TextEncoder: "readonly"
      }
    },
    rules: { "@typescript-eslint/no-require-imports": "off" }
  }
);
