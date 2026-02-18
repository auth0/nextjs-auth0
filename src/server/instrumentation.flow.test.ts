import { NextRequest } from "next/server.js";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type { SessionData } from "../types/index.js";
import type {
  InstrumentationEvent,
  InstrumentationLogger
} from "../types/instrumentation.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "test-user-id",
  sid: "test-session-id",
  idToken: "test-id-token",
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token"
};

// Mock authorization server metadata
const authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}/`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"]
};

const handlers = [
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(authorizationServerMetadata);
  })
];

const server = setupServer(...handlers);

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

async function createSessionCookie(
  session: SessionData,
  secret: string
): Promise<string> {
  const maxAge = 60 * 60;
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  return await encrypt(session, secret, expiration);
}

function createTestSetup(logger: InstrumentationLogger) {
  let secret: string;
  let transactionStore: TransactionStore;
  let sessionStore: StatelessSessionStore;

  const setup = async () => {
    secret = await generateSecret(32);
    transactionStore = new TransactionStore({ secret });
    sessionStore = new StatelessSessionStore({ secret });
    return {
      secret,
      authClient: new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        routes: getDefaultRoutes(),
        logger
      }),
      transactionStore,
      sessionStore
    };
  };

  return setup;
}

describe("Instrumentation Flow Tests", () => {
  let events: InstrumentationEvent[];
  let logger: InstrumentationLogger;
  let setup: ReturnType<typeof createTestSetup>;

  beforeEach(() => {
    events = [];
    logger = (event) => events.push(event);
    setup = createTestSetup(logger);
  });

  // FT-1: Login flow emits auth:login:start and auth:login:redirect
  describe("FT-1: Login flow", () => {
    it("emits auth:login:start and auth:login:redirect", async () => {
      const { authClient } = await setup();

      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });

      await authClient.handler(req);

      const loginStart = events.find((e) => e.event === "auth:login:start");
      expect(loginStart).toBeDefined();
      expect(loginStart!.level).toBe("info");
      expect(loginStart!.data.domain).toBe(DEFAULT.domain);

      const loginRedirect = events.find(
        (e) => e.event === "auth:login:redirect"
      );
      expect(loginRedirect).toBeDefined();
      expect(loginRedirect!.level).toBe("info");
      expect(loginRedirect!.data.authorizationUrl).toBeDefined();
      // Must not contain query params (PII protection)
      expect(
        (loginRedirect!.data.authorizationUrl as string).includes("?")
      ).toBe(false);
    });
  });

  // FT-2: Logout flow emits auth:logout:start, session:delete, auth:logout:complete
  describe("FT-2: Logout flow", () => {
    it("emits logout events with session", async () => {
      const { authClient, secret } = await setup();

      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          idToken: DEFAULT.idToken,
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          scope: "openid profile email",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const cookieValue = await createSessionCookie(session, secret);
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/logout`, {
        method: "GET",
        headers: {
          cookie: `__session=${cookieValue}`
        }
      });

      await authClient.handler(req);

      const logoutStart = events.find((e) => e.event === "auth:logout:start");
      expect(logoutStart).toBeDefined();
      expect(logoutStart!.data.hasSession).toBe(true);
      expect(logoutStart!.data.strategy).toBeDefined();

      const sessionDelete = events.find((e) => e.event === "session:delete");
      expect(sessionDelete).toBeDefined();
      expect(sessionDelete!.data.reason).toBe("logout");

      const logoutComplete = events.find(
        (e) => e.event === "auth:logout:complete"
      );
      expect(logoutComplete).toBeDefined();
    });
  });

  // FT-3: Discovery cache hit
  describe("FT-3: Discovery caching", () => {
    it("emits discovery:start on first call, discovery:cache-hit on second", async () => {
      const { authClient } = await setup();

      // First request triggers discovery
      const req1 = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });
      await authClient.handler(req1);

      const discoveryStart = events.find((e) => e.event === "discovery:start");
      expect(discoveryStart).toBeDefined();

      const discoveryComplete = events.find(
        (e) => e.event === "discovery:complete"
      );
      expect(discoveryComplete).toBeDefined();
      expect(discoveryComplete!.durationMs).toBeTypeOf("number");

      // Clear events for second request
      events.length = 0;

      // Second login request should hit cache
      const req2 = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });
      await authClient.handler(req2);

      const cacheHit = events.find((e) => e.event === "discovery:cache-hit");
      expect(cacheHit).toBeDefined();
    });
  });

  // FT-4: Discovery failure emits error
  describe("FT-4: Discovery failure", () => {
    it("emits error event on discovery failure", async () => {
      // Override discovery to fail
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => {
            return new HttpResponse(null, { status: 500 });
          }
        )
      );

      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/logout`, {
        method: "GET"
      });

      await authClient.handler(req);

      const errorEvent = events.find(
        (e) => e.event === "error" && e.data.operation === "discovery"
      );
      expect(errorEvent).toBeDefined();
      expect(errorEvent!.level).toBe("error");
      expect(errorEvent!.durationMs).toBeTypeOf("number");
    });
  });

  // FT-5: Callback with missing state emits error
  describe("FT-5: Callback error handling", () => {
    it("emits error on callback with missing state", async () => {
      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/callback`, {
        method: "GET"
      });

      await authClient.handler(req);

      const callbackStart = events.find(
        (e) => e.event === "auth:callback:start"
      );
      expect(callbackStart).toBeDefined();
      expect(callbackStart!.data.hasState).toBe(false);

      const errorEvent = events.find(
        (e) => e.event === "error" && e.data.operation === "callback"
      );
      expect(errorEvent).toBeDefined();
      expect(errorEvent!.level).toBe("error");
      expect(errorEvent!.data.errorType).toBe("MissingStateError");
    });
  });

  // FT-6: getTokenSet emits debug events
  describe("FT-6: getTokenSet instrumentation", () => {
    it("emits token:get:start", async () => {
      const { authClient } = await setup();

      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          scope: "openid profile email",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      await authClient.getTokenSet(session);

      const tokenGetStart = events.find((e) => e.event === "token:get:start");
      expect(tokenGetStart).toBeDefined();
      expect(tokenGetStart!.level).toBe("debug");
    });
  });

  // FT-7: Backchannel logout emits events
  describe("FT-7: Backchannel logout", () => {
    it("emits auth:backchannel-logout:start", async () => {
      const { authClient } = await setup();

      // Backchannel logout requires a session store with deleteByLogoutToken
      // Without it, it returns 500 but should still emit start
      const req = new NextRequest(
        `${DEFAULT.appBaseUrl}/auth/backchannel-logout`,
        {
          method: "POST",
          body: "logout_token=test-token"
        }
      );

      await authClient.handler(req);

      const bclStart = events.find(
        (e) => e.event === "auth:backchannel-logout:start"
      );
      expect(bclStart).toBeDefined();
      expect(bclStart!.level).toBe("info");
    });
  });

  // FT-8: Profile endpoint (no instrumentation expected, just ensure no crash)
  describe("FT-8: Profile endpoint", () => {
    it("handles profile request without crash when logger present", async () => {
      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/profile`, {
        method: "GET"
      });

      const res = await authClient.handler(req);
      expect(res.status).toBe(401);
    });
  });

  // FT-9: Access token endpoint with no session
  describe("FT-9: Access token endpoint", () => {
    it("handles access-token request without crash when logger present", async () => {
      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/access-token`, {
        method: "GET"
      });

      const res = await authClient.handler(req);
      expect(res.status).toBe(401);
    });
  });

  // FT-15: session:touch emits on rolling session pass-through
  describe("FT-15: Session touch", () => {
    it("emits session:touch at debug level on non-auth routes with active session", async () => {
      const { authClient, secret } = await setup();

      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          scope: "openid profile email",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const cookieValue = await createSessionCookie(session, secret);
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/some/page`, {
        method: "GET",
        headers: { cookie: `__session=${cookieValue}` }
      });

      await authClient.handler(req);

      const touchEvent = events.find((e) => e.event === "session:touch");
      expect(touchEvent).toBeDefined();
      expect(touchEvent!.level).toBe("debug");
    });

    it("does not emit session:touch when no session exists", async () => {
      const { authClient } = await setup();

      const req = new NextRequest(`${DEFAULT.appBaseUrl}/some/page`, {
        method: "GET"
      });

      await authClient.handler(req);

      const touchEvent = events.find((e) => e.event === "session:touch");
      expect(touchEvent).toBeUndefined();
    });
  });

  // FT-10: Logout fallback warning emits event + suppresses console.warn
  describe("FT-10: Logout fallback warning", () => {
    it("emits auth:logout:fallback when RP-initiated logout not available", async () => {
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => {
            const { end_session_endpoint: _, ...metadataWithout } =
              authorizationServerMetadata;
            return HttpResponse.json(metadataWithout);
          }
        )
      );

      const consoleWarnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/logout`, {
        method: "GET"
      });

      await authClient.handler(req);

      const fallbackEvent = events.find(
        (e) => e.event === "auth:logout:fallback"
      );
      expect(fallbackEvent).toBeDefined();
      expect(fallbackEvent!.level).toBe("warn");

      // console.warn should be suppressed when logger is present
      const warnCalls = consoleWarnSpy.mock.calls.map((c) => c[0]);
      const hasRpLogoutWarn = warnCalls.some(
        (msg) => typeof msg === "string" && msg.includes("RP-initiated logout")
      );
      expect(hasRpLogoutWarn).toBe(false);

      consoleWarnSpy.mockRestore();
    });
  });

  // FT-11: Discovery console.error suppressed when logger present
  describe("FT-11: Discovery error console suppression", () => {
    it("suppresses console.error when logger is present", async () => {
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => {
            return new HttpResponse(null, { status: 500 });
          }
        )
      );

      const consoleErrorSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/logout`, {
        method: "GET"
      });

      await authClient.handler(req);

      // console.error should be suppressed when logger present
      const errorCalls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const hasDiscoveryError = errorCalls.some(
        (msg) => typeof msg === "string" && msg.includes("discovery request")
      );
      expect(hasDiscoveryError).toBe(false);

      // Logger should have the error
      const errorEvent = events.find(
        (e) => e.event === "error" && e.data.operation === "discovery"
      );
      expect(errorEvent).toBeDefined();

      consoleErrorSpy.mockRestore();
    });
  });

  // FT-12: Event ordering - login flow events are in order
  describe("FT-12: Event ordering", () => {
    it("login events appear in correct order", async () => {
      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });

      await authClient.handler(req);

      const eventNames = events.map((e) => e.event);
      const loginStartIdx = eventNames.indexOf("auth:login:start");
      const loginRedirectIdx = eventNames.indexOf("auth:login:redirect");

      expect(loginStartIdx).toBeGreaterThanOrEqual(0);
      expect(loginRedirectIdx).toBeGreaterThanOrEqual(0);
      expect(loginStartIdx).toBeLessThan(loginRedirectIdx);
    });
  });

  // FT-13: Timestamp format
  describe("FT-13: Timestamp format", () => {
    it("all events have valid ISO 8601 timestamps", async () => {
      const { authClient } = await setup();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });

      await authClient.handler(req);

      for (const event of events) {
        expect(event.timestamp).toMatch(
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/
        );
      }
    });
  });

  // FT-14: Multiple flows don't cross-contaminate
  describe("FT-14: No cross-contamination between flows", () => {
    it("events from separate flows are independent", async () => {
      const { authClient, secret } = await setup();

      // Login flow
      const loginReq = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });
      await authClient.handler(loginReq);

      const loginEvents = [...events];
      events.length = 0;

      // Logout flow
      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          scope: "openid profile email",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const cookieValue = await createSessionCookie(session, secret);
      const logoutReq = new NextRequest(`${DEFAULT.appBaseUrl}/auth/logout`, {
        method: "GET",
        headers: { cookie: `__session=${cookieValue}` }
      });
      await authClient.handler(logoutReq);

      const logoutEvents = events;

      // Login events should not contain logout events
      expect(loginEvents.some((e) => e.event.includes("logout"))).toBe(false);
      // Logout events should not contain login:redirect events
      expect(logoutEvents.some((e) => e.event === "auth:login:redirect")).toBe(
        false
      );
    });
  });

  // EC-9: Logger throwing during flow does not break auth
  describe("EC-9: Logger exception during flow", () => {
    it("auth flow completes even when logger throws on every call", async () => {
      let callCount = 0;
      const throwingLogger: InstrumentationLogger = () => {
        callCount++;
        throw new Error(`Logger error #${callCount}`);
      };

      const throwSetup = createTestSetup(throwingLogger);
      const { authClient } = await throwSetup();

      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });

      const res = await authClient.handler(req);
      // Should still redirect (302)
      expect(res.status).toBe(307);
      expect(callCount).toBeGreaterThan(0);
    });
  });

  // EC-10: Slow async logger does not block flow
  describe("EC-10: Slow async logger", () => {
    it("auth flow does not wait for slow logger", async () => {
      let resolveLogger: () => void;
      const slowLogger: InstrumentationLogger = () => {
        // Return a promise that resolves after 5 seconds (but we don't await it)
        return new Promise((resolve) =>
          setTimeout(() => {
            resolve(undefined);
            resolveLogger!();
          }, 5000)
        ) as any;
      };

      const slowSetup = createTestSetup(slowLogger);
      const { authClient } = await slowSetup();

      const start = Date.now();
      const req = new NextRequest(`${DEFAULT.appBaseUrl}/auth/login`, {
        method: "GET"
      });

      const res = await authClient.handler(req);
      const elapsed = Date.now() - start;

      // Should complete in well under 5 seconds
      expect(elapsed).toBeLessThan(2000);
      expect(res.status).toBe(307);
    });
  });

  // EC-11: Callback start has correct boolean data
  describe("EC-11: Callback event data accuracy", () => {
    it("auth:callback:start has accurate boolean fields", async () => {
      const { authClient } = await setup();

      // Callback with error param
      const req = new NextRequest(
        `${DEFAULT.appBaseUrl}/auth/callback?error=access_denied&state=abc`,
        { method: "GET" }
      );

      await authClient.handler(req);

      const callbackStart = events.find(
        (e) => e.event === "auth:callback:start"
      );
      expect(callbackStart).toBeDefined();
      expect(callbackStart!.data.hasError).toBe(true);
      expect(callbackStart!.data.hasState).toBe(true);
      expect(callbackStart!.data.hasCode).toBe(false);
    });
  });
});
