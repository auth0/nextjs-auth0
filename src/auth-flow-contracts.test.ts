import { NextRequest } from "next/server.js";
import { describe, expect, it, vi } from "vitest";

import { AuthClient } from "./server/auth-client.js";
import { StatelessSessionStore } from "./server/session/stateless-session-store.js";
import { TransactionStore } from "./server/transaction-store.js";
import { getDefaultRoutes } from "./test/defaults.js";
import { generateSecret } from "./test/utils.js";
import { RESPONSE_TYPES } from "./types/index.js";

const DOMAIN = "test.auth0.com";
const APP_BASE_URL = "https://example.com";

function makeDiscoveryResponse(extra: Record<string, unknown> = {}) {
  return new Response(
    JSON.stringify({
      issuer: `https://${DOMAIN}/`,
      authorization_endpoint: `https://${DOMAIN}/authorize`,
      token_endpoint: `https://${DOMAIN}/oauth/token`,
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
    clientId: "client_id",
    clientSecret: "client_secret",
    secret,
    appBaseUrl: APP_BASE_URL,
    routes: getDefaultRoutes(),
    fetch: () => Promise.resolve(makeDiscoveryResponse()),
    ...extra
  });
}

describe("INTERNAL_AUTHORIZE_PARAMS — always overridden by SDK", () => {
  it("user-provided 'state' in authorizationParameters is overridden by SDK-generated state", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const res = await authClient.startInteractiveLogin({
      authorizationParameters: { state: "user_supplied_state" }
    });

    const location = res.headers.get("location")!;
    const url = new URL(location);
    expect(url.searchParams.get("state")).not.toBe("user_supplied_state");
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  it("user-provided 'nonce' in authorizationParameters is overridden by SDK-generated nonce", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const res = await authClient.startInteractiveLogin({
      authorizationParameters: { nonce: "user_supplied_nonce" }
    });

    const location = res.headers.get("location")!;
    const url = new URL(location);
    expect(url.searchParams.get("nonce")).not.toBe("user_supplied_nonce");
    expect(url.searchParams.get("nonce")).toBeTruthy();
  });

  it("user-provided 'code_challenge' is overridden (SDK always generates PKCE)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const res = await authClient.startInteractiveLogin({
      authorizationParameters: { code_challenge: "user_supplied_challenge" }
    });

    const location = res.headers.get("location")!;
    const url = new URL(location);
    expect(url.searchParams.get("code_challenge")).not.toBe(
      "user_supplied_challenge"
    );
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
  });

  it("user-provided 'redirect_uri' is overridden (SDK always controls the callback URL)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const res = await authClient.startInteractiveLogin({
      authorizationParameters: { redirect_uri: "https://attacker.com/callback" }
    });

    const location = res.headers.get("location")!;
    const url = new URL(location);
    expect(url.searchParams.get("redirect_uri")).not.toBe(
      "https://attacker.com/callback"
    );
    expect(url.searchParams.get("redirect_uri")).toContain("/auth/callback");
  });

  it("user-provided 'response_type' is overridden to 'code' (SDK always uses authorization code flow)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret);

    const res = await authClient.startInteractiveLogin({
      authorizationParameters: { response_type: "token" }
    });

    const location = res.headers.get("location")!;
    const url = new URL(location);
    expect(url.searchParams.get("response_type")).toBe("code");
  });
});

describe("Connect account response type", () => {
  it("RESPONSE_TYPES.CONNECT_CODE is a distinct value from RESPONSE_TYPES.CODE", () => {
    expect(RESPONSE_TYPES.CONNECT_CODE).not.toBe(RESPONSE_TYPES.CODE);
    expect(RESPONSE_TYPES.CONNECT_CODE).toBe("connect_code");
    expect(RESPONSE_TYPES.CODE).toBe("code");
  });

  it("connectAccount transaction state uses RESPONSE_TYPES.CONNECT_CODE (not CODE)", async () => {
    const secret = await generateSecret(32);

    let capturedResponseType: string | null = null;
    const originalTransactionStore = new TransactionStore({ secret });
    vi.spyOn(originalTransactionStore, "save").mockImplementation(
      async (_cookies, state) => {
        capturedResponseType = (state as any).responseType ?? null;
      }
    );

    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes("connected-accounts/connect")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              auth_session: "session_abc",
              connect_uri: "https://test.auth0.com/authorize",
              connect_params: { ticket: "ticket_123" }
            })
          )
        );
      }
      return Promise.resolve(makeDiscoveryResponse());
    });

    const authClient = new AuthClient({
      transactionStore: originalTransactionStore,
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: mockFetch
    });

    await authClient.connectAccount({
      connection: "google-oauth2",
      tokenSet: { accessToken: "at_for_connect", expiresAt: 0 }
    });

    expect(capturedResponseType).toBe(RESPONSE_TYPES.CONNECT_CODE);
  });
});

describe("PAR: no silent fallback when endpoint missing", () => {
  it("returns an error (not a redirect) when pushedAuthorizationRequests=true and server has no PAR endpoint", async () => {
    const secret = await generateSecret(32);

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () =>
        Promise.resolve(
          makeDiscoveryResponse({
            // Explicitly omit pushed_authorization_request_endpoint
          })
        ),
      pushedAuthorizationRequests: true
    });

    const req = new NextRequest(new URL("/auth/login", APP_BASE_URL), {
      method: "GET"
    });
    const res = await authClient.handleLogin(req);

    expect([302, 307]).not.toContain(res.status);
    expect(res.status).toBe(500);
  });

  it("succeeds normally when pushedAuthorizationRequests=false (no PAR endpoint required)", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, {
      pushedAuthorizationRequests: false
    });

    const req = new NextRequest(new URL("/auth/login", APP_BASE_URL), {
      method: "GET"
    });
    const res = await authClient.handleLogin(req);

    expect([302, 307]).toContain(res.status);
    expect(res.headers.get("location")).toContain(`${DOMAIN}/authorize`);
  });
});
