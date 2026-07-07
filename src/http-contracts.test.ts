import { NextRequest } from "next/server.js";
import { describe, expect, it, vi } from "vitest";

import { MfaRequiredError } from "./errors/index.js";
import { AuthClient } from "./server/auth-client.js";
import { decrypt, encrypt } from "./server/cookies.js";
import { StatefulSessionStore } from "./server/session/stateful-session-store.js";
import { StatelessSessionStore } from "./server/session/stateless-session-store.js";
import { TransactionStore } from "./server/transaction-store.js";
import { getDefaultRoutes } from "./test/defaults.js";
import { generateSecret } from "./test/utils.js";
import { encryptMfaToken } from "./utils/mfa-utils.js";

const DOMAIN = "test.auth0.com";
const CLIENT_ID = "client_id";
const CLIENT_SECRET = "client_secret";
const APP_BASE_URL = "https://example.com";

function makeDiscoveryResponse(extra: Record<string, unknown> = {}) {
  return new Response(
    JSON.stringify({
      issuer: `https://${DOMAIN}/`,
      authorization_endpoint: `https://${DOMAIN}/authorize`,
      token_endpoint: `https://${DOMAIN}/oauth/token`,
      end_session_endpoint: `https://${DOMAIN}/v2/logout`,
      jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      ...extra
    })
  );
}

async function makeAuthClient(
  secret: string,
  extra: Record<string, unknown> = {}
) {
  return new AuthClient({
    transactionStore: new TransactionStore({ secret }),
    sessionStore: new StatelessSessionStore({ secret }),
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    secret,
    appBaseUrl: APP_BASE_URL,
    routes: getDefaultRoutes(),
    fetch: () => Promise.resolve(makeDiscoveryResponse()),
    ...extra
  });
}

async function makeSessionCookie(secret: string) {
  const session = {
    user: { sub: "user_123", email: "user@example.com" },
    tokenSet: {
      accessToken: "at_123",
      idToken: "idt_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    },
    internal: { sid: "session-sid", createdAt: Math.floor(Date.now() / 1000) }
  };
  const expiry = Math.floor(Date.now() / 1000) + 3600;
  return encrypt(session, secret, expiry);
}

describe("HTTP status codes — profile endpoint", () => {
  it("returns 401 when no session exists (default behavior)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const req = new NextRequest(new URL("/auth/profile", APP_BASE_URL), {
      method: "GET"
    });
    const res = await authClient.handleProfile(req);

    expect(res.status).toBe(401);
  });

  it("returns 204 when no session exists and noContentProfileResponseWhenUnauthenticated is true", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, {
      noContentProfileResponseWhenUnauthenticated: true
    });

    const req = new NextRequest(new URL("/auth/profile", APP_BASE_URL), {
      method: "GET"
    });
    const res = await authClient.handleProfile(req);

    expect(res.status).toBe(204);
  });

  it("returns 200 with user data when session exists", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const sessionCookie = await makeSessionCookie(secret);
    const headers = new Headers({ cookie: `__session=${sessionCookie}` });
    const req = new NextRequest(new URL("/auth/profile", APP_BASE_URL), {
      method: "GET",
      headers
    });

    const res = await authClient.handleProfile(req);
    expect(res.status).toBe(200);
  });
});

describe("HTTP status codes — backchannel logout endpoint", () => {
  it("returns 204 on successful backchannel logout", async () => {
    const secret = await generateSecret(32);

    const dataStore = {
      get: async () => null,
      set: async () => {},
      delete: async () => {},
      deleteByLogoutToken: async () => {}
    };

    const sessionStore = new StatefulSessionStore({
      secret,
      store: dataStore as any
    });

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore,
      domain: DOMAIN,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () => Promise.resolve(makeDiscoveryResponse())
    });

    vi.spyOn(authClient as any, "verifyLogoutToken").mockResolvedValue([
      null,
      {
        sub: "user_123",
        sid: "session-sid",
        iss: `https://${DOMAIN}/`,
        aud: CLIENT_ID
      }
    ]);

    const req = new NextRequest(
      new URL("/auth/backchannel-logout", APP_BASE_URL),
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          logout_token: "header.payload.sig.enc.tag"
        })
      }
    );

    const res = await authClient.handleBackChannelLogout(req);
    expect(res.status).toBe(204);
  });
});

describe("HTTP status codes — redirect is 302 not 301", () => {
  it("handleLogin redirect is 307 (temporary, not permanent)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const req = new NextRequest(new URL("/auth/login", APP_BASE_URL), {
      method: "GET"
    });
    const res = await authClient.handleLogin(req);

    expect(res.status).not.toBe(301);
    expect([302, 307, 308]).toContain(res.status);
    expect(res.headers.get("location")).toContain(`${DOMAIN}/authorize`);
  });

  it("handleLogout redirect is not 301 (permanent redirect is never acceptable)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const sessionCookie = await makeSessionCookie(secret);
    const headers = new Headers({ cookie: `__session=${sessionCookie}` });
    const req = new NextRequest(new URL("/auth/logout", APP_BASE_URL), {
      method: "GET",
      headers
    });

    const res = await authClient.handleLogout(req);

    expect(res.status).not.toBe(301);
    expect(res.headers.get("location")).toBeDefined();
  });
});

describe("Cache-Control headers on auth responses", () => {
  it("profile endpoint sets Cache-Control to private, no-cache, no-store, must-revalidate, max-age=0", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const sessionCookie = await makeSessionCookie(secret);
    const headers = new Headers({ cookie: `__session=${sessionCookie}` });
    const req = new NextRequest(new URL("/auth/profile", APP_BASE_URL), {
      method: "GET",
      headers
    });

    const res = await authClient.handleProfile(req);

    expect(res.headers.get("Cache-Control")).toBe(
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
  });
});

describe("Logout parameter format", () => {
  it("federated param is set as empty string (not 'true')", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const req = new NextRequest(
      new URL("/auth/logout?federated", APP_BASE_URL),
      { method: "GET" }
    );
    const res = await authClient.handleLogout(req);

    const location = res.headers.get("location");
    expect(location).toBeDefined();

    const url = new URL(location!);
    expect(url.searchParams.has("federated")).toBe(true);
    expect(url.searchParams.get("federated")).toBe("");
  });

  it("logout_hint is sourced from session.internal.sid", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, { logoutStrategy: "oidc" });

    const sessionCookie = await makeSessionCookie(secret);
    const headers = new Headers({ cookie: `__session=${sessionCookie}` });
    const req = new NextRequest(new URL("/auth/logout", APP_BASE_URL), {
      method: "GET",
      headers
    });

    const res = await authClient.handleLogout(req);

    const location = res.headers.get("location");
    expect(location).toBeDefined();

    const url = new URL(location!);
    expect(url.searchParams.get("logout_hint")).toBe("session-sid");
  });
});

describe("MFA error response body shape (S2-18)", () => {
  it("MfaRequiredError.toJSON() returns {error, error_description, mfa_token} snake_case", () => {
    const err = new MfaRequiredError(
      "MFA required",
      "encrypted_tok_123",
      undefined,
      undefined
    );
    const json = err.toJSON();

    expect(Object.keys(json)).toEqual(
      expect.arrayContaining(["error", "error_description", "mfa_token"])
    );
    expect(json.error).toBe("mfa_required");
    expect(json.error_description).toBe("MFA required");
    expect(json.mfa_token).toBe("encrypted_tok_123");
  });

  it("MfaRequiredError.toJSON() does NOT include camelCase keys", () => {
    const err = new MfaRequiredError(
      "MFA required",
      "tok",
      undefined,
      undefined
    );
    const json = err.toJSON() as Record<string, unknown>;

    expect(json).not.toHaveProperty("mfaToken");
    expect(json).not.toHaveProperty("errorDescription");
  });

  it("403 response body from handleAccessToken matches MfaRequiredError shape", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    vi.spyOn(authClient as any, "getTokenSet").mockResolvedValue([
      new MfaRequiredError(
        "step-up required",
        "encrypted_mfa_tok",
        undefined,
        undefined
      ),
      null
    ]);

    const sessionCookie = await makeSessionCookie(secret);
    const headers = new Headers({ cookie: `__session=${sessionCookie}` });
    const req = new NextRequest(new URL("/auth/access-token", APP_BASE_URL), {
      method: "GET",
      headers
    });

    const res = await authClient.handleAccessToken(req);
    expect(res.status).toBe(403);

    const body = await res.json();
    expect(body).toHaveProperty("error", "mfa_required");
    expect(body).toHaveProperty("error_description");
    expect(body).toHaveProperty("mfa_token");
  });
});

describe("MFA token JWE structure (S2-19)", () => {
  it("encryptMfaToken produces a valid JWE (5-segment compact serialization)", async () => {
    const secret = await generateSecret(32);
    const jwe = await encryptMfaToken(
      "raw_mfa_tok",
      "https://api.example.com",
      "openid",
      undefined,
      secret,
      300
    );

    expect(jwe.split(".")).toHaveLength(5);
  });

  it("encrypted MFA token payload contains mfaToken, audience, scope, createdAt", async () => {
    const secret = await generateSecret(32);
    const jwe = await encryptMfaToken(
      "raw_mfa_tok",
      "https://api.example.com",
      "openid profile",
      undefined,
      secret,
      300
    );

    const decrypted = await decrypt<{
      mfaToken: string;
      audience: string;
      scope: string;
      createdAt: number;
    }>(jwe, secret);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.payload.mfaToken).toBe("raw_mfa_tok");
    expect(decrypted!.payload.audience).toBe("https://api.example.com");
    expect(decrypted!.payload.scope).toBe("openid profile");
    expect(typeof decrypted!.payload.createdAt).toBe("number");
  });

  it("encrypted MFA token has a TTL (exp claim is set)", async () => {
    const secret = await generateSecret(32);
    const before = Math.floor(Date.now() / 1000);
    const jwe = await encryptMfaToken(
      "tok",
      "",
      "openid",
      undefined,
      secret,
      300
    );

    const decrypted = await decrypt<Record<string, unknown>>(jwe, secret);
    expect(decrypted).not.toBeNull();
    const exp = decrypted!.payload.exp as number;
    expect(exp).toBeGreaterThan(before + 299);
    expect(exp).toBeLessThan(before + 301 + 2);
  });
});
