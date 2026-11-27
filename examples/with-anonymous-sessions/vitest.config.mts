/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    environment: "jsdom",
    // Give jsdom a concrete origin so the SDK hook's relative fetch resolves to
    // http://localhost:3000/... (matches the MSW handlers in the hook tests).
    environmentOptions: { jsdom: { url: "http://localhost:3000" } },
    globals: true,
    setupFiles: ["./tests/setup.ts"],
    // Playwright specs live under tests/e2e and must NOT be collected by vitest
    // (they import @playwright/test, which is not a vitest runtime).
    exclude: ["**/node_modules/**", "**/tests/e2e/**"],
    // The live suite toggles the global MSW server off in beforeAll (real HTTP
    // must reach the network). Pin per-file isolation so that toggle can never
    // leak MSW-off state into another test file. Do not relax these without
    // moving the live suite's MSW lifecycle to per-test hooks.
    pool: "threads",
    isolate: true,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./"),
    },
    // The local SDK (file:../..), swr, and the example each pull react from a
    // different pnpm store. Force one instance so the SDK hook renders cleanly.
    dedupe: ["react", "react-dom", "swr"],
  },
});
