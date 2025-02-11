import pluginJs from "@eslint/js";
import stylisticTs from "@stylistic/eslint-plugin-ts";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import pluginReact from "eslint-plugin-react";
import globals from "globals";
import tseslint from "typescript-eslint";

/** @type {import('eslint').Linter.Config[]} */
export default [
  { files: ["**/*.{js,mjs,cjs,ts,jsx,tsx}"] },
  { languageOptions: { globals: { ...globals.browser, ...globals.node } } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  pluginReact.configs.flat.recommended,
  eslintPluginPrettierRecommended,
  {
    plugins: {
      "@stylistic/ts": stylisticTs
    }
  },
  {
    rules: {
      "prettier/prettier": "error",
      "no-console": [
        1,
        {
          allow: ["error", "info", "warn"]
        }
      ],
      "comma-dangle": ["error", "never"],
      "no-trailing-spaces": "error",
      "react/display-name": 0,
      "@stylistic/ts/semi": "error",
      "@typescript-eslint/camelcase": 0,
      "@typescript-eslint/interface-name-prefix": 0,
      "@typescript-eslint/prefer-interface": 0,
      "@typescript-eslint/no-explicit-any": 0,
      "@typescript-eslint/no-use-before-define": 0,
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          vars: "all",
          args: "after-used",
          caughtErrors: "none",
          ignoreRestSiblings: false,
          reportUsedIgnorePattern: false,
          varsIgnorePattern: "^_"
        }
      ]
    }
  },
  {
    settings: {
      react: {
        version: "detect"
      }
    }
  }
];
