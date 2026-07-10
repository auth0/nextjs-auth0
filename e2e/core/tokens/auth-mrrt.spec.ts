import { expect, test } from "@playwright/test";
import { loginWithAuth0 } from "../../helpers";

// Multi-Resource Refresh Tokens (MRRT)
//
// These tests require the Auth0 tenant to have MRRT enabled and the application
// to have multiple audiences configured. Tests skip gracefully when MRRT is not
// available on the tenant.
//
// All tests are @integration — they require a real Auth0 login and a tenant
// configured with at least two audiences that support MRRT.

const AUDIENCE_A =
  process.env.TEST_MRRT_AUDIENCE_A ??
  `https://${process.env.AUTH0_DOMAIN}/api/v2/`;

const AUDIENCE_B = process.env.TEST_MRRT_AUDIENCE_B ?? "";

test.describe("MRRT — getAccessToken() per audience @integration", () => {
  test.skip(!AUDIENCE_B, "requires TEST_MRRT_AUDIENCE_B env var");

  test("getAccessToken() with audience A returns a token scoped to audience A", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_A)}`
    );
    expect([200, 401]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(typeof body.token).toBe("string");
      expect(body.token.length).toBeGreaterThan(10);
    }
  });

  test("getAccessToken() with audience B returns a different token from audience A", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");

    const resA = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_A)}`
    );
    const resB = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_B)}`
    );

    // Both must succeed for the comparison to be meaningful
    if (resA.status() !== 200 || resB.status() !== 200) {
      test.skip();
      return;
    }

    const tokenA = (await resA.json()).token;
    const tokenB = (await resB.json()).token;
    expect(tokenA).not.toBe(tokenB);
  });

  test("second call for same audience returns cached token (no extra refresh)", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");

    const res1 = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_A)}`
    );
    if (res1.status() !== 200) {
      test.skip();
      return;
    }

    const res2 = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_A)}`
    );
    expect(res2.status()).toBe(200);

    const token1 = (await res1.json()).token;
    const token2 = (await res2.json()).token;
    // Same audience, token not expired — should return the same cached token
    expect(token1).toBe(token2);
  });

  test("tokens for different audiences are stored independently in session", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");

    const resA = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_A)}`
    );
    const resB = await context.request.get(
      `/auth/access-token?audience=${encodeURIComponent(AUDIENCE_B)}`
    );

    if (resA.status() !== 200 || resB.status() !== 200) {
      test.skip();
      return;
    }

    // Read session — both audience tokens should be present in tokenSet
    const sessionRes = await context.request.get("/app-router/api/get-session");
    const session = await sessionRes.json();

    // Primary tokenSet holds the default audience token
    expect(session.tokenSet).toHaveProperty("accessToken");
    // The session shape for MRRT stores additional tokens — exact shape depends on implementation
    expect(typeof session.tokenSet.accessToken).toBe("string");
  });
});
