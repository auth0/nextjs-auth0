import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import { describe, expect, it, vi } from "vitest";

import { AuthClient } from "./server/auth-client.js";
import { decrypt, encrypt } from "./server/cookies.js";
import { LEGACY_COOKIE_NAME } from "./server/session/normalize-session.js";
import { StatefulSessionStore } from "./server/session/stateful-session-store.js";
import { StatelessSessionStore } from "./server/session/stateless-session-store.js";
import { TransactionStore } from "./server/transaction-store.js";
import { DEFAULT_ID_TOKEN_CLAIMS } from "./server/user.js";
import { getDefaultRoutes } from "./test/defaults.js";
import { generateSecret } from "./test/utils.js";
import { RESPONSE_TYPES } from "./types/index.js";
import {
  DEFAULT_DPOP_CLOCK_SKEW,
  DEFAULT_DPOP_CLOCK_TOLERANCE,
  DEFAULT_MFA_CONTEXT_TTL_SECONDS,
  DEFAULT_RETRY_DELAY,
  DEFAULT_RETRY_JITTER,
  DEFAULT_SCOPES,
  MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE
} from "./utils/constants.js";

describe("SDK constants — utils/constants.ts", () => {
  it("DEFAULT_SCOPES equals 'openid profile email offline_access'", () => {
    expect(DEFAULT_SCOPES).toBe("openid profile email offline_access");
  });

  it("DEFAULT_DPOP_CLOCK_SKEW equals 0", () => {
    expect(DEFAULT_DPOP_CLOCK_SKEW).toBe(0);
  });

  it("DEFAULT_DPOP_CLOCK_TOLERANCE equals 30", () => {
    expect(DEFAULT_DPOP_CLOCK_TOLERANCE).toBe(30);
  });

  it("MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE equals 300", () => {
    expect(MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE).toBe(300);
  });

  it("DEFAULT_RETRY_DELAY equals 100", () => {
    expect(DEFAULT_RETRY_DELAY).toBe(100);
  });

  it("DEFAULT_RETRY_JITTER equals true", () => {
    expect(DEFAULT_RETRY_JITTER).toBe(true);
  });

  it("DEFAULT_MFA_CONTEXT_TTL_SECONDS equals 300", () => {
    expect(DEFAULT_MFA_CONTEXT_TTL_SECONDS).toBe(300);
  });
});

describe("Cookie encryption — server/cookies.ts", () => {
  const secret = "a-32-byte-secret-for-testing-use";

  it("JWT clock tolerance of 15 seconds allows decryption of JWE expired 14 seconds ago", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expiration = now - 14;
    const jwe = await encrypt({ sub: "user_test" }, secret, expiration);
    const result = await decrypt(jwe, secret);

    expect(result).not.toBeNull();
    expect(result?.payload.sub).toBe("user_test");
  });

  it("JWT clock tolerance of 15 seconds rejects JWE expired 16 seconds ago", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expiration = now - 16;
    const jwe = await encrypt({ sub: "user_test" }, secret, expiration);
    const result = await decrypt(jwe, secret);

    expect(result).toBeNull();
  });
});

describe("Session cookie name defaults", () => {
  it("StatelessSessionStore has sessionCookieName default '__session'", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });
    expect(store.sessionCookieName).toBe("__session");
  });

  it("StatefulSessionStore has sessionCookieName default '__session'", async () => {
    const secret = await generateSecret(32);
    const mockStore = {
      get: async () => null,
      set: async () => {}
    };
    const store = new StatefulSessionStore({
      secret,
      store: mockStore as any
    });
    expect(store.sessionCookieName).toBe("__session");
  });
});

describe("Session TTL defaults", () => {
  it("AbstractSessionStore rolling defaults to true", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });
    expect((store as any).rolling).toBe(true);
  });

  it("AbstractSessionStore absoluteDuration defaults to 259200 (3 days)", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });
    expect((store as any).absoluteDuration).toBe(60 * 60 * 24 * 3);
  });

  it("AbstractSessionStore inactivityDuration defaults to 86400 (1 day)", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });
    expect((store as any).inactivityDuration).toBe(60 * 60 * 24 * 1);
  });
});

describe("Session cookie security defaults", () => {
  it("Session cookie has httpOnly: true, sameSite: 'lax', path: '/', secure: false", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });
    const config = (store as any).cookieConfig;

    expect(config.httpOnly).toBe(true);
    expect(config.sameSite).toBe("lax");
    expect(config.path).toBe("/");
    expect(config.secure).toBe(false);
  });
});

describe("Connection token sets cookie format", () => {
  it("StatelessSessionStore connectionTokenSetsCookieName equals '__FC'", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });
    expect(store.connectionTokenSetsCookieName).toBe("__FC");
  });

  it("Connection token sets use underscore separator format '__FC_${index}'", async () => {
    const secret = await generateSecret(32);
    const mockSessionData = {
      user: { sub: "user_123", email: "user@example.com" },
      tokenSet: { accessToken: "at_123" },
      internal: { createdAt: Math.floor(Date.now() / 1000) },
      connectionTokenSets: [{ payload: { access_token: "conn_at_0" } }]
    };

    const store = new StatelessSessionStore({ secret });
    const reqCookies = new RequestCookies(new Headers());
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);

    await store.set(reqCookies, resCookies, mockSessionData as any);

    const setCookieHeaders = headers.getSetCookie();
    const connectionTokenCookie = setCookieHeaders.find((c) =>
      c.includes("__FC_0")
    );

    expect(connectionTokenCookie).toBeDefined();
  });
});

describe("Legacy cookie name (v3 migration)", () => {
  it("LEGACY_COOKIE_NAME equals 'appSession'", () => {
    expect(LEGACY_COOKIE_NAME).toBe("appSession");
  });

  it("StatelessSessionStore reads __session before appSession (fallback order)", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });

    const session = {
      user: { sub: "from_session" },
      tokenSet: { accessToken: "at_from_session" },
      internal: { createdAt: Math.floor(Date.now() / 1000) }
    };
    const legacySession = {
      user: { sub: "from_app_session" },
      tokenSet: { accessToken: "at_from_app_session" },
      internal: { createdAt: Math.floor(Date.now() / 1000) }
    };

    const expiry = Math.floor(Date.now() / 1000) + 3600;
    const sessionJwe = await encrypt(session, secret, expiry);
    const legacyJwe = await encrypt(legacySession, secret, expiry);

    // Both cookies present — __session wins
    const headers = new Headers({
      cookie: `__session=${sessionJwe}; appSession=${legacyJwe}`
    });
    const reqCookies = new RequestCookies(headers);
    const result = await store.get(reqCookies);

    expect(result?.user.sub).toBe("from_session");
  });

  it("StatelessSessionStore falls back to appSession when __session is absent", async () => {
    const secret = await generateSecret(32);
    const store = new StatelessSessionStore({ secret });

    const legacySession = {
      user: { sub: "from_app_session" },
      tokenSet: { accessToken: "at_from_app_session" },
      internal: { createdAt: Math.floor(Date.now() / 1000) }
    };

    const expiry = Math.floor(Date.now() / 1000) + 3600;
    const legacyJwe = await encrypt(legacySession, secret, expiry);

    const headers = new Headers({ cookie: `appSession=${legacyJwe}` });
    const reqCookies = new RequestCookies(headers);
    const result = await store.get(reqCookies);

    expect(result?.user.sub).toBe("from_app_session");
  });
});

describe("Transaction store defaults", () => {
  it("TransactionStore cookiePrefix defaults to '__txn_'", async () => {
    const secret = await generateSecret(32);
    const store = new TransactionStore({ secret });
    expect(store.getCookiePrefix()).toBe("__txn_");
  });

  it("TransactionStore enableParallelTransactions defaults to true", async () => {
    const secret = await generateSecret(32);
    const store = new TransactionStore({ secret });
    expect((store as any).enableParallelTransactions).toBe(true);
  });

  it("TransactionStore cookie has httpOnly: true, sameSite: 'lax', path: '/', secure: false", async () => {
    const secret = await generateSecret(32);
    const store = new TransactionStore({ secret });
    const config = (store as any).cookieOptions;

    expect(config.httpOnly).toBe(true);
    expect(config.sameSite).toBe("lax");
    expect(config.path).toBe("/");
    expect(config.secure).toBe(false);
  });

  it("TransactionStore cookie maxAge defaults to 3600 (1 hour)", async () => {
    const secret = await generateSecret(32);
    const store = new TransactionStore({ secret });
    const config = (store as any).cookieOptions;

    expect(config.maxAge).toBe(3600);
  });
});

describe("DEFAULT_ID_TOKEN_CLAIMS", () => {
  it("DEFAULT_ID_TOKEN_CLAIMS has exact array in exact order", () => {
    expect(DEFAULT_ID_TOKEN_CLAIMS).toEqual([
      "sub",
      "name",
      "nickname",
      "given_name",
      "family_name",
      "picture",
      "email",
      "email_verified",
      "org_id",
      "act"
    ]);
  });
});

describe("Logout defaults — auth-client.ts", () => {
  it("AuthClient logoutStrategy defaults to 'auto'", async () => {
    const secret = await generateSecret(32);
    const mockFetch = () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            issuer: "https://test.auth0.com",
            authorization_endpoint: "https://test.auth0.com/authorize",
            token_endpoint: "https://test.auth0.com/oauth/token",
            jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"]
          })
        )
      );

    const mockSessionStore = new StatelessSessionStore({ secret });
    const mockTransactionStore = new TransactionStore({ secret });

    const authClient = new AuthClient({
      domain: "test.auth0.com",
      clientId: "test_client_id",
      clientSecret: "test_secret",
      secret,
      sessionStore: mockSessionStore,
      transactionStore: mockTransactionStore,
      routes: getDefaultRoutes(),
      fetch: mockFetch as any
    });

    expect((authClient as any).logoutStrategy).toBe("auto");
  });

  it("AuthClient includeIdTokenHintInOIDCLogoutUrl defaults to true", async () => {
    const secret = await generateSecret(32);
    const mockFetch = () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            issuer: "https://test.auth0.com",
            authorization_endpoint: "https://test.auth0.com/authorize",
            token_endpoint: "https://test.auth0.com/oauth/token",
            jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"]
          })
        )
      );

    const mockSessionStore = new StatelessSessionStore({ secret });
    const mockTransactionStore = new TransactionStore({ secret });

    const authClient = new AuthClient({
      domain: "test.auth0.com",
      clientId: "test_client_id",
      clientSecret: "test_secret",
      secret,
      sessionStore: mockSessionStore,
      transactionStore: mockTransactionStore,
      routes: getDefaultRoutes(),
      fetch: mockFetch as any
    });

    expect((authClient as any).includeIdTokenHintInOIDCLogoutUrl).toBe(true);
  });
});

describe("RESPONSE_TYPES enum values", () => {
  it("RESPONSE_TYPES.CODE equals 'code'", () => {
    expect(RESPONSE_TYPES.CODE).toBe("code");
  });

  it("RESPONSE_TYPES.CONNECT_CODE equals 'connect_code'", () => {
    expect(RESPONSE_TYPES.CONNECT_CODE).toBe("connect_code");
  });
});

describe("Stateful session ID format", () => {
  it("Session ID is 32 lowercase hex characters (16 bytes)", async () => {
    const secret = await generateSecret(32);
    const mockStore = {
      get: async () => null,
      set: async () => {},
      delete: async () => {}
    };
    const store = new StatefulSessionStore({
      secret,
      store: mockStore as any
    });

    const mockSessionData = {
      user: { sub: "user_123", email: "user@example.com" },
      tokenSet: { accessToken: "at_123" },
      internal: { createdAt: Math.floor(Date.now() / 1000) }
    };

    const reqCookies = new RequestCookies(new Headers());
    const headers = new Headers();
    const resCookies = new ResponseCookies(headers);

    await store.set(reqCookies, resCookies, mockSessionData as any, true);

    const cookieValue = reqCookies.get("__session")?.value;
    expect(cookieValue).toBeDefined();

    if (cookieValue) {
      const decrypted = await decrypt<{ id: string }>(cookieValue, secret);
      expect(decrypted).not.toBeNull();
      expect(decrypted!.payload.id).toMatch(/^[0-9a-f]{32}$/);
    }
  });

  it("Stateful session cookie contains envelope with id property", async () => {
    const secret = await generateSecret(32);
    const mockStore = {
      get: async () => null,
      set: async () => {},
      delete: async () => {}
    };
    const store = new StatefulSessionStore({
      secret,
      store: mockStore as any
    });

    const mockSessionData = {
      user: { sub: "user_123", email: "user@example.com" },
      tokenSet: { accessToken: "at_123" },
      internal: { createdAt: Math.floor(Date.now() / 1000) }
    };

    const reqCookies = new RequestCookies(new Headers());
    const resCookies = new ResponseCookies(new Headers());

    await store.set(reqCookies, resCookies, mockSessionData as any, true);

    const cookieValue = reqCookies.get("__session")?.value;
    expect(cookieValue).toBeDefined();

    if (cookieValue) {
      const decrypted = await decrypt<{ id: string }>(cookieValue, secret);
      expect(decrypted).not.toBeNull();
      expect(typeof decrypted?.payload.id).toBe("string");
      expect(decrypted!.payload.id).toMatch(/^[0-9a-f]{32}$/);
    }
  });
});

describe("INTERNAL_AUTHORIZE_PARAMS restriction", () => {
  it("User-provided state and nonce are overridden by SDK-generated values", async () => {
    const secret = await generateSecret(32);
    const mockFetch = vi.fn(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            issuer: "https://test.auth0.com",
            authorization_endpoint: "https://test.auth0.com/authorize",
            token_endpoint: "https://test.auth0.com/oauth/token",
            jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"]
          })
        )
      )
    );

    const mockSessionStore = new StatelessSessionStore({ secret });
    const mockTransactionStore = new TransactionStore({ secret });

    const authClient = new AuthClient({
      domain: "test.auth0.com",
      clientId: "test_client_id",
      clientSecret: "test_secret",
      secret,
      appBaseUrl: "https://example.com",
      sessionStore: mockSessionStore,
      transactionStore: mockTransactionStore,
      routes: getDefaultRoutes(),
      fetch: mockFetch as any
    });

    const result = await authClient.startInteractiveLogin({
      authorizationParameters: {
        state: "user_state_should_be_ignored",
        nonce: "user_nonce_should_be_ignored"
      }
    });

    const redirectUrl = result.headers.get("location");
    expect(redirectUrl).toBeDefined();

    if (redirectUrl) {
      const url = new URL(redirectUrl);
      const state = url.searchParams.get("state");
      const nonce = url.searchParams.get("nonce");

      expect(state).not.toBe("user_state_should_be_ignored");
      expect(nonce).not.toBe("user_nonce_should_be_ignored");
      expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });
});
