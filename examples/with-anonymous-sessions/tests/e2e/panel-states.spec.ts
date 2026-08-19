import { expect, test } from "@playwright/test";

/**
 * L11-L12 — Client hook UI state coverage (creds-free, route-intercept).
 *
 * Exercises the AnonymousSessionPanel's client-side UI states (error banner,
 * logout flow) via Playwright route interception (`page.route(...)`). These
 * tests run unconditionally (no live tenant required) by mocking the
 * `useAnonymousSession()` hook's fetch to `/auth/anonymous-session`.
 *
 * The panel is rendered at `/demo`, which also performs a SERVER-side
 * getAnonymousSession() render. In a mocked run, the SSR block will show
 * "No anonymous session found (server-side read)" — this is expected. Target
 * the CLIENT panel specifically using `.error-banner` / `.session-panel`
 * class selectors or role/text scoped to the client panel.
 *
 * These tests complement the live-gated spec (tests/e2e/link-callback.spec.ts)
 * by providing deterministic coverage of UI states that cannot be triggered
 * reliably in a live-tenant run.
 */

test.describe("L11-L12 — Client hook UI states", () => {
  test("L12 — hook error renders the error banner", async ({ page }) => {
    // Intercept the GET `/auth/anonymous-session` the hook makes and return an
    // error response. Ensure we only fulfill the GET (the hook), not unrelated
    // requests.
    await page.route("**/auth/anonymous-session", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({
            code: "internal_error",
            message: "Failed to load anonymous session"
          })
        });
      } else {
        route.continue();
      }
    });

    await page.goto("/demo");

    // Assert the error banner is visible and contains the error text.
    const errorBanner = page.locator(".error-banner");
    await expect(errorBanner).toBeVisible();
    await expect(errorBanner).toContainText("Error:");
    await expect(errorBanner).toContainText("Failed to load anonymous session");
  });

  test("L11 — logout clears client session and returns home", async ({
    page
  }) => {
    // Intercept GET `/auth/anonymous-session` to return a synthetic session so
    // the panel renders the Logout button.
    await page.route("**/auth/anonymous-session", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            id: "anon@synthetic-e2e",
            accessToken:
              "ANONYMOUS_SESSION_synthetic_fake_token_value_12345678",
            expiresAt: 4102444800,
            metadata: { cart_id: "e2e" }
          })
        });
      } else {
        route.continue();
      }
    });

    // Intercept POST `/auth/anonymous-session/logout` to complete the logout.
    await page.route("**/auth/anonymous-session/logout", (route) => {
      if (route.request().method() === "POST") {
        route.fulfill({
          status: 204
        });
      } else {
        route.continue();
      }
    });

    await page.goto("/demo");

    // Assert the client session panel shows the synthetic session ID.
    const sessionPanel = page.locator(".session-panel");
    await expect(sessionPanel).toBeVisible();
    await expect(sessionPanel).toContainText("anon@synthetic-e2e");

    // Click the Logout button.
    const logoutButton = page.getByRole("button", { name: "Logout" });
    await logoutButton.click();

    // Assert navigation ends at home `/`.
    await page.waitForURL(/\/$/);
    expect(new URL(page.url()).pathname).toBe("/");
  });
});
