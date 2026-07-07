/// <reference types="vitest/config" />
import { defineConfig } from "vite"
import { configDefaults } from "vitest/config"

export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "e2e/*", "examples/**/*", "examples/**/*.test.*"],
    coverage: {
      reporter: ["text", "json-summary", "lcov"],
      include: ["src/**/*"],
      exclude: [
        // Barrel re-exports — no executable logic
        "src/client/index.ts",
        "src/server/index.ts",
        "src/testing/index.ts",
        // Type-only files — no runtime statements
        "src/types/authorize.ts",
        "src/types/dpop.ts",
        "src/types/mcd.ts",
        "src/types/passwordless-db.ts",
        // Test infrastructure — not product code
        "src/test/mocks.ts",
      ],
      ignoreEmptyLines: true,
    },
  },
})
