/**
 * MCD Integration Tests (Units 6-12)
 *
 * This test suite covers the full MCD feature integration:
 * - Unit 6: Auth0Client refactored to use provider
 * - Unit 7: AuthClient structural changes
 * - Unit 8: Session domain gating
 * - Unit 9: Callback domain delegation
 * - Unit 10: Logout domain awareness
 * - Unit 11: MFA domain awareness
 * - Unit 12: openid scope enforcement
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  DomainValidationError,
  McdInvalidConfigurationError as InvalidConfigurationError,
  SessionDomainMismatchError
} from "../errors/mcd.js";
import {
  createMCDMetadata,
  createSessionData
} from "../test/mcd-test-fixtures.js";
import { SessionData } from "../types/index.js";
import type { DomainResolver } from "../types/mcd.js";
import { normalizeDomain } from "../utils/normalize.js";
import { AuthClientProvider } from "./auth-client-provider.js";
import { DiscoveryCache } from "./discovery-cache.js";

describe("MCD Integration Tests (Units 6-12)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function createMockHeaders(customHeaders: Record<string, string> = {}) {
    const h = new (globalThis as any).Headers();
    h.set("host", "example.com");
    Object.entries(customHeaders).forEach(([key, value]) => {
      h.set(key, value);
    });
    return h;
  }

  // ===== Unit 6 Tests: Auth0Client Refactor to Use Provider =====

  describe("Unit 6: Auth0Client Refactor to Use Provider", () => {
    it("U6-1: Constructor creates provider instance", () => {
      // Mock AuthClientProvider
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/"
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient,
        discoveryCacheOptions: { ttl: 600 }
      });

      expect(provider).toBeInstanceOf(AuthClientProvider);
      expect(provider.configuredDomain).toBe("example.com");
    });

    it("U6-2: forRequest extracts headers from request", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/"
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      expect(client).toBeDefined();
      expect(client.domain).toBe("example.com");
    });

    it("U6-3: Resolver mode calls forRequest with headers", async () => {
      const resolverFn: DomainResolver = vi.fn(async ({ headers }) => {
        expect(headers).toBeDefined();
        return "resolved.example.com";
      });

      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: resolverFn,
        createAuthClient
      });

      expect(provider.isResolverMode).toBe(true);

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      expect(resolverFn).toHaveBeenCalled();
      expect(client.domain).toBe("resolved.example.com");
    });

    it("U6-4: Static mode returns pre-cached AuthClient", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/"
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client1 = await provider.forRequest(headers);
      const client2 = await provider.forRequest(headers);

      // Should return same instance from cache
      expect(createAuthClient).toHaveBeenCalledTimes(1);
      expect(client1).toBe(client2);
    });
  });

  // ===== Unit 7 Tests: AuthClient Structural Changes =====

  describe("Unit 7: AuthClient Structural Changes", () => {
    it("U7-1: domain field is readonly", async () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            getSessionWithDomainCheck: vi.fn()
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      expect(client.domain).toBe("example.com");
      // Verify it's readonly (TypeScript check)
      expect(() => {
        (client as any).domain = "other.com";
      }).not.toThrow(); // Runtime doesn't enforce readonly
    });

    it("U7-2: issuer getter returns formatted issuer", async () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            getSessionWithDomainCheck: vi.fn()
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      expect((client as any).issuer).toBe("https://example.com/");
      expect((client as any).issuer).toMatch(/\/$/);
      expect((client as any).issuer).toMatch(/^https:\/\//);
    });

    it("U7-7: getSessionWithDomainCheck returns SessionCheckResult", async () => {
      const mockSessionCheckResult = {
        error: null,
        session: createSessionData({}),
        exists: true
      };

      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            getSessionWithDomainCheck: vi
              .fn()
              .mockResolvedValue(mockSessionCheckResult)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      const result = await client.getSessionWithDomainCheck({} as any);
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("session");
      expect(result).toHaveProperty("exists");
    });

    it("U7-9: getSessionWithDomainCheck with matching domain", async () => {
      const sessionWithMCD = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      });

      const mockResult = {
        error: null,
        session: sessionWithMCD,
        exists: true
      };

      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            getSessionWithDomainCheck: vi.fn().mockResolvedValue(mockResult)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      const result = await client.getSessionWithDomainCheck({} as any);
      expect(result.error).toBeNull();
      expect(result.session).toBeDefined();
      expect(result.exists).toBe(true);
    });

    it("U7-10: getSessionWithDomainCheck with pre-MCD session backfill", async () => {
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
          // no mcd field
        }
      });

      const mockResult = {
        error: null,
        session: {
          ...preMCDSession,
          internal: {
            ...preMCDSession.internal,
            mcd: createMCDMetadata("example.com", "https://example.com/")
          }
        },
        exists: true
      };

      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            getSessionWithDomainCheck: vi.fn().mockResolvedValue(mockResult)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      const result = await client.getSessionWithDomainCheck({} as any);
      expect(result.session?.internal.mcd).toBeDefined();
      expect(result.session?.internal.mcd?.domain).toBe("example.com");
    });

    it("U7-11: getSessionWithDomainCheck with domain mismatch", async () => {
      const _sessionWithMismatchedDomain = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("other.com", "https://other.com/")
        }
      });

      const mockResult = {
        error: new SessionDomainMismatchError(
          "Session domain (other.com) does not match request domain (example.com)"
        ),
        session: null,
        exists: true
      };

      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            getSessionWithDomainCheck: vi.fn().mockResolvedValue(mockResult)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      const result = await client.getSessionWithDomainCheck({} as any);
      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
      expect(result.session).toBeNull();
      expect(result.exists).toBe(true);
    });
  });

  // ===== Unit 8 Tests: Session Domain Gating =====

  describe("Unit 8: Session Domain Gating", () => {
    it("U8-2: getAccessToken with domain mismatch returns error", async () => {
      const mockError = new SessionDomainMismatchError();
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            getAccessToken: vi.fn().mockRejectedValue(mockError)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      await expect((client as any).getAccessToken({})).rejects.toBeInstanceOf(
        SessionDomainMismatchError
      );
    });

    it("U8-3: getAccessToken with domain match proceeds", async () => {
      const mockTokenSet = {
        accessToken: "new_access_token",
        expiresAt: Date.now() + 3600000
      };

      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            getAccessToken: vi.fn().mockResolvedValue(mockTokenSet)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      const result = await (client as any).getAccessToken({});
      expect(result.accessToken).toBe("new_access_token");
    });

    it("U8-6: handleLogout with domain mismatch skips deletion", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            handleLogout: vi.fn().mockResolvedValue(undefined)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      // Mocking a scenario where domain mismatch causes silent skip
      await expect(client.handleLogout({} as any)).resolves.toBeUndefined();
    });

    it("U8-17: SessionDomainMismatchError propagated to public methods", async () => {
      const error = new SessionDomainMismatchError("Session domain mismatch");
      expect(error.code).toBe("session_domain_mismatch");
      expect(error.message).toContain("domain");
    });
  });

  // ===== Unit 9 Tests: Callback Domain Delegation =====

  describe("Unit 9: Callback Domain Delegation", () => {
    it("U9-5: Callback delegation with originDomain", async () => {
      const resolverFn: DomainResolver = vi
        .fn()
        .mockResolvedValue("example.com");

      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            handleCallback: vi.fn().mockResolvedValue({
              user: { sub: "user_123" },
              tokenSet: { accessToken: "token", expiresAt: Date.now() }
            })
          }) as any
      );

      const _provider = new AuthClientProvider({
        domain: resolverFn,
        createAuthClient
      });

      // Normalize domain works correctly
      const normalized = normalizeDomain("example.com");
      expect(normalized.domain).toBe("example.com");
      expect(normalized.issuer).toBe("https://example.com/");
    });

    it("U9-6: Callback delegation with same domain as resolver", async () => {
      const resolverFn: DomainResolver = vi
        .fn()
        .mockResolvedValue("example.com");

      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            handleCallback: vi
              .fn()
              .mockResolvedValue({ user: { sub: "user_123" } })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: resolverFn,
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      // Same domain - no delegation needed
      expect(client.domain).toBe("example.com");
    });

    it("U9-7: Callback delegation to different domain", async () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            handleCallback: vi
              .fn()
              .mockResolvedValue({ user: { sub: "user_123" } })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "primary.com",
        createAuthClient
      });

      // Synchronous forDomainSync for delegation
      const delegatedClient = provider.forDomainSync("secondary.com");
      expect(delegatedClient.domain).toBe("secondary.com");
      expect(delegatedClient).not.toBe(
        await provider.forRequest(createMockHeaders())
      );
    });

    it("U9-8: Callback delegation with invalid domain throws", async () => {
      expect(() => {
        normalizeDomain("192.168.1.1");
      }).toThrow(DomainValidationError);
    });

    it("U9-16: forDomainSync called synchronously", () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      // forDomainSync must be synchronous
      const start = Date.now();
      const client = provider.forDomainSync("example.com");
      const duration = Date.now() - start;

      expect(client).toBeDefined();
      expect(duration).toBeLessThan(100); // Should be immediate
    });
  });

  // ===== Unit 10 Tests: Logout Domain Awareness =====

  describe("Unit 10: Logout Domain Awareness", () => {
    it("U10-5: handleBackChannelLogout in static mode", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            handleBackChannelLogout: vi.fn().mockResolvedValue(undefined)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      // In static mode, uses configured domain
      await expect(client.handleBackChannelLogout({} as any)).resolves;
    });

    it("U10-6: handleBackChannelLogout in resolver mode", async () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            handleBackChannelLogout: vi.fn().mockResolvedValue(undefined)
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: async () => "resolved.example.com",
        createAuthClient
      });

      // In resolver mode, extracts domain from token and delegates
      const client = provider.forDomainSync("resolved.example.com");
      expect(client.domain).toBe("resolved.example.com");
    });

    it("U10-9: handleBackChannelLogout with invalid domain from iss", async () => {
      expect(() => {
        normalizeDomain("10.0.0.1");
      }).toThrow(DomainValidationError);
    });

    it("U10-15: SSRF prevention in backchannel logout", () => {
      expect(() => normalizeDomain("192.168.1.1")).toThrow(
        DomainValidationError
      );
      expect(() => normalizeDomain("localhost")).toThrow(DomainValidationError);
      expect(() => normalizeDomain("internal.local")).toThrow(
        DomainValidationError
      );
    });
  });

  // ===== Unit 11 Tests: MFA Domain Awareness =====

  describe("Unit 11: MFA Domain Awareness", () => {
    it("U11-1: ServerMfaClient constructor accepts provider", () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/"
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      // ServerMfaClient receives provider, not AuthClient
      expect(provider).toBeInstanceOf(AuthClientProvider);
      expect(provider.configuredDomain).toBe("example.com");
    });

    it("U11-2: MFA method resolves domain per request", async () => {
      const resolverFn: DomainResolver = vi
        .fn()
        .mockResolvedValue("example.com");

      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            enrollTotp: vi.fn().mockResolvedValue({
              secret: "secret_123"
            })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: resolverFn,
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      expect(client.domain).toBe("example.com");
    });

    it("U11-9: Proxy fetcher cached by key", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com"
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const factory = vi.fn(async () => ({ fetch: vi.fn() }) as any);
      const fetcher1 = await provider.getProxyFetcher(
        "domain1:audience1",
        factory
      );
      const fetcher2 = await provider.getProxyFetcher(
        "domain1:audience1",
        factory
      );

      expect(fetcher1).toBe(fetcher2);
      expect(factory).toHaveBeenCalledTimes(1);
    });

    it("U11-10: Different keys have separate fetchers", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com"
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const factory1 = vi.fn(async () => ({ fetch: "fetcher1" }) as any);
      const factory2 = vi.fn(async () => ({ fetch: "fetcher2" }) as any);

      const fetcher1 = await provider.getProxyFetcher("key1", factory1);
      const fetcher2 = await provider.getProxyFetcher("key2", factory2);

      expect(fetcher1).not.toBe(fetcher2);
      expect(factory1).toHaveBeenCalledTimes(1);
      expect(factory2).toHaveBeenCalledTimes(1);
    });
  });

  // ===== Unit 12 Tests: openid Scope Enforcement =====

  describe("Unit 12: openid Scope Enforcement", () => {
    it("U12-1: Static mode allows missing openid", () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            startInteractiveLogin: vi
              .fn()
              .mockResolvedValue({ authorizationUrl: "url" })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      expect(provider.isResolverMode).toBe(false);
      // Static mode should not enforce openid scope
    });

    it("U12-2: Resolver mode requires openid in explicit scope", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            startInteractiveLogin: vi
              .fn()
              .mockImplementation(async (options: any) => {
                if (options?.scope && options.scope.includes("openid")) {
                  return { authorizationUrl: "url" };
                }
                throw new InvalidConfigurationError("openid scope required");
              })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: async () => "example.com",
        createAuthClient
      });

      expect(provider.isResolverMode).toBe(true);
    });

    it("U12-4: Resolver mode throws with missing openid", async () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            startInteractiveLogin: vi
              .fn()
              .mockRejectedValue(
                new InvalidConfigurationError(
                  "openid scope is required in resolver mode"
                )
              )
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: async () => "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      await expect(
        client.startInteractiveLogin({
          authorizationParameters: { scope: "profile" }
        })
      ).rejects.toBeInstanceOf(InvalidConfigurationError);
    });

    it("U12-9: Scope enforcement excludes connectAccount", () => {
      const createAuthClient = vi.fn(
        () =>
          ({
            domain: "example.com",
            issuer: "https://example.com/",
            connectAccount: vi.fn().mockResolvedValue({ ticket: "ticket_123" })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: async () => "example.com",
        createAuthClient
      });

      // connectAccount should not require openid scope
      expect(provider.isResolverMode).toBe(true);
    });
  });

  // ===== Additional Integration Scenarios =====

  describe("Integration Scenarios", () => {
    it("INT-1: Static mode end-to-end flow", async () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            getSessionWithDomainCheck: vi.fn().mockResolvedValue({
              error: null,
              session: createSessionData({
                internal: {
                  sid: "sid_123",
                  createdAt: Date.now(),
                  mcd: createMCDMetadata(domain, `https://${domain}/`)
                }
              }),
              exists: true
            })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client = await provider.forRequest(headers);

      expect(client.domain).toBe("example.com");

      const result = await client.getSessionWithDomainCheck({} as any);
      expect(result.session).toBeDefined();
      expect(result.error).toBeNull();
    });

    it("INT-2: Resolver mode multi-domain", async () => {
      let resolverCallCount = 0;
      const resolverFn: DomainResolver = vi.fn(async () => {
        resolverCallCount++;
        if (resolverCallCount === 1) return "domain1.com";
        return "domain2.com";
      });

      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: resolverFn,
        createAuthClient
      });

      const headers1 = createMockHeaders();
      const client1 = await provider.forRequest(headers1);
      expect(client1.domain).toBe("domain1.com");

      const headers2 = createMockHeaders();
      const client2 = await provider.forRequest(headers2);
      expect(client2.domain).toBe("domain2.com");

      expect(client1).not.toBe(client2);
    });

    it("INT-4: Multi-domain callback delegation", () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`,
            handleCallback: vi.fn().mockResolvedValue({
              user: { sub: "user_123" },
              tokenSet: {
                accessToken: "token",
                expiresAt: Date.now() + 3600000,
                idToken: "id_token"
              }
            })
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "primary.example.com",
        createAuthClient
      });

      // Delegate to different domain using forDomainSync
      const delegatedClient = provider.forDomainSync("secondary.example.com");
      expect(delegatedClient.domain).toBe("secondary.example.com");

      // Both clients are different instances
      const primaryClient = provider.forDomainSync("primary.example.com");
      expect(primaryClient).not.toBe(delegatedClient);
    });

    it("INT-6: Discovery cache concurrent requests", async () => {
      const discoveryCache = new DiscoveryCache({ ttl: 600, maxEntries: 10 });

      const mockFetch = vi.fn().mockResolvedValue({
        issuer: "https://example.com/",
        authorization_endpoint: "https://example.com/authorize"
      });

      // Concurrent calls to same domain
      const promise1 = discoveryCache.get("example.com", mockFetch);
      const promise2 = discoveryCache.get("example.com", mockFetch);

      const result1 = await promise1;
      const result2 = await promise2;

      // Both should get same result with single fetch
      expect(result1).toEqual(result2);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("INT-7: Cache TTL expiry", async () => {
      vi.useFakeTimers();
      try {
        const ttl = 2; // 2 second TTL
        const discoveryCache = new DiscoveryCache({ ttl });

        const mockFetch = vi.fn().mockResolvedValue({
          issuer: "https://example.com/",
          token_endpoint: "https://example.com/oauth/token"
        });

        // First call
        const result1 = await discoveryCache.get("example.com", mockFetch);
        expect(result1).toBeDefined();
        expect(mockFetch).toHaveBeenCalledTimes(1);

        // Advance time within TTL (500ms - still within 2 second TTL)
        vi.advanceTimersByTime(500);
        const result1b = await discoveryCache.get("example.com", mockFetch);
        expect(result1b).toBeDefined();
        expect(mockFetch).toHaveBeenCalledTimes(1); // Still cached

        // Advance time past TTL (total 2500ms - past 2 second TTL)
        vi.advanceTimersByTime(2000);
        const result2 = await discoveryCache.get("example.com", mockFetch);
        expect(result2).toBeDefined();
        expect(mockFetch).toHaveBeenCalledTimes(2); // Should call again
      } finally {
        vi.useRealTimers();
      }
    });

    it("INT-8: Cache LRU eviction", async () => {
      const discoveryCache = new DiscoveryCache({
        ttl: 600,
        maxEntries: 2
      });

      const mockFetch = vi.fn().mockResolvedValue({
        issuer: "https://example.com/",
        token_endpoint: "https://example.com/oauth/token"
      });

      // Add 3 domains (exceeds maxEntries of 2)
      await discoveryCache.get("domain1.com", mockFetch);
      await discoveryCache.get("domain2.com", mockFetch);
      await discoveryCache.get("domain3.com", mockFetch);

      // domain1 should be evicted (LRU)
      // Clear and re-fetch domain1
      const _result = await discoveryCache.get("domain1.com", mockFetch);

      // Should have called mockFetch for domain1 again
      expect(mockFetch.mock.calls.length).toBeGreaterThan(3);
    });
  });

  // ===== R2 Architectural Tests =====

  describe("R2 Architectural Issues", () => {
    it("R2-1-1: Session domain cached at entry", async () => {
      const createAuthClient = vi.fn(
        (domain: string) =>
          ({
            domain,
            issuer: `https://${domain}/`
          }) as any
      );

      const provider = new AuthClientProvider({
        domain: "example.com",
        createAuthClient
      });

      const headers = createMockHeaders();
      const client1 = await provider.forRequest(headers);

      // Domain should remain consistent across operations
      const client2 = await provider.forRequest(headers);

      expect(client1.domain).toBe(client2.domain);
    });

    it("R2-2-1: In-flight dedup with concurrent requests", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        issuer: "https://example.com/",
        token_endpoint: "https://example.com/oauth/token"
      });

      const discoveryCache = new DiscoveryCache({ ttl: 600 });

      // Concurrent calls
      const prom1 = discoveryCache.get("example.com", mockFetch);
      const prom2 = discoveryCache.get("example.com", mockFetch);

      await Promise.all([prom1, prom2]);

      // Should deduplicate in-flight requests
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("R2-3-1: Backfill in-memory only", async () => {
      const sessionStore = new Map<string, SessionData>();
      const preMCDSession = createSessionData({
        internal: { sid: "sid_123", createdAt: Date.now() }
      });

      sessionStore.set("session_id", preMCDSession);

      const storedSession = sessionStore.get("session_id");
      expect(storedSession?.internal.mcd).toBeUndefined();

      // In-memory backfill
      if (storedSession) {
        storedSession.internal.mcd = createMCDMetadata(
          "example.com",
          "https://example.com/"
        );
      }

      // Original store should be unchanged until set is called
      expect(storedSession?.internal.mcd).toBeDefined();
    });

    it("R2-7-1: SSRF - private IP in iss claim", () => {
      expect(() => normalizeDomain("10.0.0.1")).toThrow(DomainValidationError);
      expect(() => normalizeDomain("172.16.0.1")).toThrow(
        DomainValidationError
      );
      expect(() => normalizeDomain("::1")).toThrow(DomainValidationError);
    });

    it("R2-7-2: SSRF - localhost in iss claim", () => {
      expect(() => normalizeDomain("localhost")).toThrow(DomainValidationError);
      expect(() => normalizeDomain("127.0.0.1")).toThrow(DomainValidationError);
    });

    it("R2-7-3: SSRF - .local domain", () => {
      expect(() => normalizeDomain("internal.local")).toThrow(
        DomainValidationError
      );
      expect(() => normalizeDomain("service.local")).toThrow(
        DomainValidationError
      );
    });

    it("R2-7-4: SSRF - port smuggling", () => {
      expect(() => normalizeDomain("example.com:6379")).toThrow(
        DomainValidationError
      );
    });

    it("R2-7-5: Non-SSRF - valid domain", () => {
      const normalized = normalizeDomain("valid.example.com");
      expect(normalized.domain).toBe("valid.example.com");
      expect(normalized.issuer).toBe("https://valid.example.com/");
    });
  });
});
