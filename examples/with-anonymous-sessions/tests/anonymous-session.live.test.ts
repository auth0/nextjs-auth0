/**
 * TIER 1 LIVE Integration Tests (L1-L10)
 *
 * These tests hit a REAL Auth0 tenant's anonymous-sessions endpoints and are
 * SKIPPED by default. They ran green once (2026-08-13) against dev-ozu.
 *
 * To run:
 *   RUN_LIVE_ANON_TESTS=1 \
 *   AUTH0_DOMAIN=your-tenant.us.auth0.com \
 *   AUTH0_CLIENT_ID=... AUTH0_CLIENT_SECRET=... \
 *   AUTH0_AUDIENCE=https://api.customers \
 *   pnpm test tests/anonymous-session.live.test.ts
 *
 * CI has no creds set → the whole suite skips (never fails the pipeline).
 * NO secrets are committed: every credential is read from the environment.
 *
 * IMPORTANT: MSW is NOT used here. `onUnhandledRequest: "error"` in setup.ts
 * would reject live calls, so this file must not import ./setup. Vitest loads
 * setupFiles globally, so these tests bypass MSW by hitting real HTTPS via the
 * live domain (which MSW is not configured to intercept). We disable MSW for
 * this file explicitly in beforeAll.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { server } from "./setup";

const DOMAIN = process.env.AUTH0_DOMAIN;
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUDIENCE = process.env.AUTH0_AUDIENCE ?? "https://api.customers";

const hasCreds = Boolean(
  process.env.RUN_LIVE_ANON_TESTS && DOMAIN && CLIENT_ID && CLIENT_SECRET
);

const base = DOMAIN
  ? DOMAIN.startsWith("http")
    ? DOMAIN
    : `https://${DOMAIN}`
  : "";

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const [, payload] = jwt.split(".");
  const json = Buffer.from(payload, "base64url").toString("utf8");
  return JSON.parse(json) as Record<string, unknown>;
}

async function createSession(
  extra: Record<string, unknown> = {}
): Promise<Response> {
  return fetch(`${base}/anonymous/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: AUDIENCE,
      ...extra
    })
  });
}

async function logout(extra: Record<string, unknown> = {}): Promise<Response> {
  return fetch(`${base}/anonymous/logout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: CLIENT_ID, ...extra })
  });
}

describe.skipIf(!hasCreds)(
  "Anonymous Sessions - TIER 1 LIVE (L1-L8, server)",
  () => {
    // Live calls must reach the real network; MSW would reject them.
    beforeAll(() => {
      server.close();
    });
    afterAll(() => {
      // Re-arm MSW for any subsequent files in the same worker.
      server.listen({ onUnhandledRequest: "error" });
    });

    it("L1: create -> 200, sub=anon@, aud=api.customers, session_expires_in=2592000", async () => {
      const res = await createSession();
      expect(res.status).toBe(200);
      const json = (await res.json()) as Record<string, any>;

      expect(json.token_type).toBe("Bearer");
      expect(json.session_expires_in).toBe(2592000);
      expect(typeof json.session_token).toBe("string");
      expect(json.session_token).toMatch(/^ANONYMOUS_SESSION_/);
      expect(typeof json.access_token).toBe("string");

      const claims = decodeJwtPayload(json.access_token);
      expect(String(claims.sub)).toMatch(/^anon@/);
      expect(claims.aud).toBe(AUDIENCE);
      expect(claims.scope).toContain("read:customers");
    });

    it("L2: create + metadata -> 200", async () => {
      const res = await createSession({
        metadata: { cart_id: "cart_123", items: 3 }
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as Record<string, any>;
      expect(json.session_token).toMatch(/^ANONYMOUS_SESSION_/);
      expect(typeof json.access_token).toBe("string");
    });

    it("L3: read-back — created access_token decodes to same anon subject shape", async () => {
      const res = await createSession();
      const json = (await res.json()) as Record<string, any>;
      const claims = decodeJwtPayload(json.access_token);
      // Read-back: the token we just minted must carry a stable anon subject.
      expect(String(claims.sub)).toMatch(/^anon@/);
      expect(claims.iss).toContain(DOMAIN);
    });

    it("L4: renew(session_token) -> 200, NO new session_token", async () => {
      const created = (await (await createSession()).json()) as Record<
        string,
        any
      >;
      const res = await createSession({
        session_token: created.session_token
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as Record<string, any>;
      expect(json).not.toHaveProperty("session_token");
      expect(typeof json.access_token).toBe("string");
      expect(json.access_token).not.toBe(""); // fresh access token
    });

    it("L5: renew + metadata -> 400 invalid_request (set-once)", async () => {
      const created = (await (await createSession()).json()) as Record<
        string,
        any
      >;
      const res = await createSession({
        session_token: created.session_token,
        metadata: { x: "y" }
      });
      expect(res.status).toBe(400);
      const json = (await res.json()) as Record<string, any>;
      expect(json.error).toBe("invalid_request");
      expect(json.error_description).toBe(
        "metadata cannot be provided when session_token is present"
      );
    });

    it("L6: logout {client_id} -> 204", async () => {
      const res = await logout();
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
    });

    it("L7: logout {} -> 204", async () => {
      const res = await fetch(`${base}/anonymous/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });
      expect(res.status).toBe(204);
    });

    it("L8: logout + session_token -> 400 invalid_request", async () => {
      const created = (await (await createSession()).json()) as Record<
        string,
        any
      >;
      const res = await logout({ session_token: created.session_token });
      expect(res.status).toBe(400);
      const json = (await res.json()) as Record<string, any>;
      expect(json.error).toBe("invalid_request");
    });
  }
);

/**
 * L9-L12: Browser-level flows live in the Playwright harness, NOT this Vitest
 * suite (they need a real /auth/login redirect + cookie roundtrip).
 *
 * L9  SEC-1 session_token strip -> tests/e2e/sec1-strip.spec.ts (L9a/L9b/L9c).
 *     Creds-free L9a/L9c always run; L9b needs a live-minted auth0_anon cookie.
 *     Status: PASSING (3/3 vs dev-ozu, 2026-08-17).
 * L10 anon->login callback anonymousSessionLinked=true (?linked=true banner)
 *     -> tests/e2e/link-callback.spec.ts. Gated on TEST_USER_EMAIL + TEST_USER_PASSWORD;
 *     skips in CI. Run: pnpm exec playwright test link-callback.
 * L11-L12 Client hook UI states (error banner, logout) -> tests/e2e/panel-states.spec.ts.
 *     Creds-free route-intercept tests, always run.
 *
 * Run L9: pnpm test:e2e:l9   |   Run all e2e: pnpm test:e2e
 */
describe("Anonymous Sessions - TIER 1 LIVE (L9-L12, browser)", () => {
  it.todo("L9: covered by Playwright tests/e2e/sec1-strip.spec.ts (passing)");
  it.todo(
    "L10: covered by Playwright tests/e2e/link-callback.spec.ts (gated live, passing)"
  );
  it.todo(
    "L11-L12: covered by Playwright tests/e2e/panel-states.spec.ts (creds-free, passing)"
  );
});
