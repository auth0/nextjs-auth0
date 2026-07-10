import dotenv from "dotenv"
import path from "path"
import { fileURLToPath } from "url"
import { defineConfig, devices } from "@playwright/test"

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// Load .env.local — passkey tests read PASSKEY_* vars directly from here.
dotenv.config({ path: path.resolve(__dirname, "e2e/test-app/.env.local"), override: false })

// Passkey tests require the app to run as a production build (not dev/Turbopack).
// The dev server's Turbopack HMR WebSocket uses wss:// which nginx doesn't proxy,
// preventing React hydration. `pnpm build && pnpm start` avoids this entirely.
//
// To pre-start the server manually before running these tests:
//   cd e2e/test-app && AUTH0_DOMAIN=piyushkumar.acmetest.org \
//     APP_BASE_URL=https://piyushkumar.acmetest.org \
//     pnpm build && pnpm start
//
// Playwright will reuse the running server (reuseExistingServer: true).

const baseURL = process.env.PASSKEY_APP_BASE_URL || "https://piyushkumar.acmetest.org"

export default defineConfig({
  testDir: "./e2e/features/passkey",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 1 : undefined,
  outputDir: "./e2e/test-results-passkey",
  reporter: [["html", { outputFolder: "./e2e/playwright-report-passkey" }]],
  use: {
    baseURL,
    trace: "on",
    ignoreHTTPSErrors: true,
    storageState: { cookies: [], origins: [] },
  },

  projects: [
    {
      name: "passkey",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  // Server must be started manually with passkey credentials before running tests.
  // See comment above. Playwright reuses it via reuseExistingServer.
  webServer: {
    command: `cd e2e/test-app && AUTH0_DOMAIN=${process.env.PASSKEY_AUTH0_DOMAIN} APP_BASE_URL=${process.env.PASSKEY_APP_BASE_URL} pnpm build && AUTH0_DOMAIN=${process.env.PASSKEY_AUTH0_DOMAIN} APP_BASE_URL=${process.env.PASSKEY_APP_BASE_URL} pnpm start`,
    url: "http://localhost:3000",
    timeout: 300 * 1000,
    reuseExistingServer: !process.env.CI,
  },

  timeout: 40 * 1000,
  expect: {
    timeout: 5 * 1000,
  },
})
