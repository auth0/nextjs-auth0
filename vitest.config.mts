/// <reference types="vitest/config" />
import { defineConfig } from "vite"
import { configDefaults } from "vitest/config"

export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "e2e/*"],
    coverage: {
      include: ["src/**/*"],
    },
  },
})
