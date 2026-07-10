import dotenv from "dotenv"
import path from "path"
import { fileURLToPath } from "url"
import { defineConfig, devices } from "@playwright/test"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
dotenv.config({ path: path.resolve(__dirname, "e2e/test-app/.env.local"), override: false })

// Use process.env.PORT by default and fallback to port 3000
const PORT = process.env.PORT || 3000

const baseURL = process.env.APP_BASE_URL || `http://localhost:${PORT}`

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 1 : undefined,
  outputDir: "./e2e/test-results",
  reporter: [["html", { outputFolder: "./e2e/playwright-report" }]],
  use: {
    baseURL,
    trace: "on",
  },

  projects: [
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    {
      name: "chromium",
      testIgnore: [/.*passwordless.*\.spec\.ts/, /.*passkey.*\.spec\.ts/],
      use: {
        ...devices["Desktop Chrome"],
        storageState: "e2e/.auth/user.json",
      },
      dependencies: ["setup"],
    },
    // Passwordless tests establish their own session via OTP — no pre-auth needed.
    {
      name: "passwordless",
      testMatch: /.*passwordless.*\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        storageState: { cookies: [], origins: [] },
      },
    },
  ],

  webServer: {
    command: "cd e2e/test-app && pnpm i && pnpm run dev",
    url: "http://localhost:3000",
    timeout: 120 * 1000,
    reuseExistingServer: !process.env.CI,
  },

  timeout: 40 * 1000,
  expect: {
    timeout: 5 * 1000,
  },
})
