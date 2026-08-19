import { defineConfig, devices } from "@playwright/test";

/**
 * Offline mock-backed Playwright harness for anonymous-sessions example.
 *
 * Runs against E2E_ANON_MOCK=1 server on port 3001. All tokens synthetic,
 * deterministic, no tenant needed. The app still requires AUTH0_DOMAIN/CLIENT_ID/
 * SECRET/AUTH0_SECRET/APP_BASE_URL in .env.local to construct Auth0Client, but
 * next dev loads it automatically — no custom parser needed here.
 */
export default defineConfig({
  testDir: "./tests/e2e/offline",
  timeout: 30_000,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://localhost:3001",
    trace: "off"
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ],
  webServer: {
    command: "E2E_ANON_MOCK=1 next dev --turbo -p 3001",
    port: 3001,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  }
});
