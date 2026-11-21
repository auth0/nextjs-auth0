import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, devices } from "@playwright/test";

// Load .env.local into process.env so gated specs (L9b/L10) can detect tenant
// creds. Next loads it for the webServer process; this makes it visible to the
// test runner process too. In CI (no .env.local) the gated specs skip.
const envPath = join(__dirname, ".env.local");
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, "utf8").split("\n")) {
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)\s*$/);
    if (m && !(m[1] in process.env)) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  }
}

/**
 * Isolated Playwright harness for the anonymous-sessions example.
 *
 * Kept separate from the SDK root `e2e/` harness (which drives `e2e/test-app`
 * and has no anonymous-session support). Browser tests here:
 *   - sec1-strip.spec.ts   L9a/L9c: creds-free SEC-1 checks (CI-safe); L9b: gated live (needs tenant)
 *   - link-callback.spec.ts L10: gated live login->callback link (needs creds)
 *
 * The dev server is started with `next dev` and reads `.env.local` for the
 * tenant config. L9 only needs AUTH0_DOMAIN to be set so the authorize URL
 * host is well-formed; it never performs a real login.
 */
export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://localhost:3000",
    // Traces capture network + env and this harness loads real tenant creds
    // (incl. AUTH0_CLIENT_SECRET) for the gated live specs. Keep traces OFF so
    // no secret can end up in an uploaded test-results/ artifact.
    trace: "off"
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ],
  webServer: {
    command: "next dev --turbo -p 3000",
    port: 3000,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  }
});
