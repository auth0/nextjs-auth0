/**
 * Tests for the AuthClientProvider class
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import { DomainResolutionError } from "../errors/mcd.js";
import { AuthClientProvider } from "./auth-client-provider.js";
import type { AuthClient } from "./auth-client.js";

describe("AuthClientProvider", () => {
  let mockAuthClient: AuthClient;
  let createAuthClientMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthClient = {} as AuthClient;
    createAuthClientMock = vi.fn().mockReturnValue(mockAuthClient);
  });

  describe("constructor - static mode", () => {
    it("should initialize in static mode with string domain", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      expect(provider.isResolverMode).toBe(false);
      expect(provider.configuredDomain).toBe("example.auth0.com");
      expect(createAuthClientMock).toHaveBeenCalledWith("example.auth0.com");
    });

    it("should normalize domain in static mode", () => {
      const provider = new AuthClientProvider({
        domain: "https://example.auth0.com/",
        createAuthClient: createAuthClientMock
      });

      expect(provider.configuredDomain).toBe("example.auth0.com");
      expect(createAuthClientMock).toHaveBeenCalledWith("example.auth0.com");
    });

    it("should validate domain in static mode", () => {
      expect(
        () =>
          new AuthClientProvider({
            domain: "example.local", // .local domains not allowed
            createAuthClient: createAuthClientMock
          })
      ).toThrow("not supported");
    });

    it("should throw on invalid domain", () => {
      expect(
        () =>
          new AuthClientProvider({
            domain: "192.168.1.1", // IP addresses not allowed
            createAuthClient: createAuthClientMock
          })
      ).toThrow();
    });
  });

  describe("constructor - resolver mode", () => {
    it("should initialize in resolver mode with resolver function", () => {
      const resolver = vi.fn();
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      expect(provider.isResolverMode).toBe(true);
      expect(provider.configuredDomain).toBeUndefined();
      // Should not call createAuthClient in constructor for resolver mode
      expect(createAuthClientMock).not.toHaveBeenCalled();
    });
  });

  describe("constructor - invalid config", () => {
    it("should throw if neither domain nor resolver is provided", () => {
      expect(
        () =>
          new AuthClientProvider({
            domain: undefined as any,
            createAuthClient: createAuthClientMock
          })
      ).toThrow(InvalidConfigurationError);
    });

    it("should throw if domain is neither string nor function", () => {
      expect(
        () =>
          new AuthClientProvider({
            domain: 123 as any,
            createAuthClient: createAuthClientMock
          })
      ).toThrow(InvalidConfigurationError);
    });

    it("should throw with helpful error message", () => {
      expect(
        () =>
          new AuthClientProvider({
            domain: null as any,
            createAuthClient: createAuthClientMock
          })
      ).toThrow(
        "You must provide either a domain string or a DomainResolver function"
      );
    });
  });

  describe("forRequest - static mode", () => {
    it("should return pre-cached client in static mode", async () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      const client = await provider.forRequest(headers);

      expect(client).toBe(mockAuthClient);
      // createAuthClient should only be called once (in constructor)
      expect(createAuthClientMock).toHaveBeenCalledTimes(1);
    });

    it("should return same client for multiple requests in static mode", async () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      const client1 = await provider.forRequest(headers);
      const client2 = await provider.forRequest(headers);
      const client3 = await provider.forRequest(headers);

      expect(client1).toBe(client2);
      expect(client2).toBe(client3);
      expect(createAuthClientMock).toHaveBeenCalledTimes(1);
    });

    it("should ignore resolver function if domain is string", async () => {
      const resolver = vi.fn();
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      await provider.forRequest(headers);

      expect(resolver).not.toHaveBeenCalled();
    });
  });

  describe("forRequest - resolver mode", () => {
    it("should call resolver and return domain-specific client", async () => {
      const resolver = vi.fn().mockResolvedValue("example.auth0.com");
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      const client = await provider.forRequest(headers);

      expect(resolver).toHaveBeenCalledWith({ headers });
      expect(createAuthClientMock).toHaveBeenCalledWith("example.auth0.com");
      expect(client).toBe(mockAuthClient);
    });

    it("should cache client for resolved domain", async () => {
      const resolver = vi.fn().mockResolvedValue("example.auth0.com");
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      const client1 = await provider.forRequest(headers);
      const client2 = await provider.forRequest(headers);

      expect(resolver).toHaveBeenCalledTimes(2); // Called each time
      expect(createAuthClientMock).toHaveBeenCalledTimes(1); // But client only created once
      expect(client1).toBe(client2);
    });

    it("should handle different domains from resolver", async () => {
      let callCount = 0;
      const resolver = vi.fn().mockImplementation(async () => {
        callCount++;
        return callCount === 1 ? "domain1.auth0.com" : "domain2.auth0.com";
      });

      const authClient1 = { id: "client1" } as any;
      const authClient2 = { id: "client2" } as any;

      const createAuthClientFn = vi
        .fn()
        .mockImplementation((domain) =>
          domain === "domain1.auth0.com" ? authClient1 : authClient2
        );

      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientFn
      });

      const headers = new Headers();
      const client1 = await provider.forRequest(headers);
      const client2 = await provider.forRequest(headers);

      expect(client1).toBe(authClient1);
      expect(client2).toBe(authClient2);
      expect(createAuthClientFn).toHaveBeenCalledTimes(2);
    });

    it("should throw if resolver returns null", async () => {
      const resolver = vi.fn().mockResolvedValue(null);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      await expect(provider.forRequest(headers)).rejects.toThrow(
        "Domain resolver returned an empty string"
      );
    });

    it("should throw if resolver returns undefined", async () => {
      const resolver = vi.fn().mockResolvedValue(undefined);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      await expect(provider.forRequest(headers)).rejects.toThrow(
        "Domain resolver returned an empty string"
      );
    });

    it("should propagate resolver errors", async () => {
      const resolverError = new Error("Resolver failed");
      const resolver = vi.fn().mockRejectedValue(resolverError);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).cause?.message).toBe("Resolver failed");
      }
    });

    it("should validate resolved domain", async () => {
      const resolver = vi.fn().mockResolvedValue("invalid.local");
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();
      await expect(provider.forRequest(headers)).rejects.toThrow(
        ".local domains are not supported"
      );
    });
  });

  describe("forRequest - resolver error wrapping (CRITICAL-1)", () => {
    it("should wrap resolver exceptions in DomainResolutionError with cause", async () => {
      const resolverError = new Error("Network timeout from resolver");
      const resolver = vi.fn().mockRejectedValue(resolverError);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();

      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).code).toBe("domain_resolution_error");
        expect((error as any).cause).toBe(resolverError);
        expect((error as any).cause?.message).toBe(
          "Network timeout from resolver"
        );
      }
    });

    it("should wrap non-Error thrown values in Error before wrapping in DomainResolutionError", async () => {
      const resolver = vi.fn().mockRejectedValue("String error message");
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();

      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).cause).toBeInstanceOf(Error);
        expect((error as any).cause?.message).toContain("String error message");
      }
    });

    it("should preserve resolver error message in cause.message", async () => {
      const resolverError = new Error(
        "Custom resolver validation failed: invalid tenant"
      );
      const resolver = vi.fn().mockRejectedValue(resolverError);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();

      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).cause?.message).toBe(
          "Custom resolver validation failed: invalid tenant"
        );
      }
    });

    it("should wrap null thrown value in Error before wrapping in DomainResolutionError", async () => {
      const resolver = vi.fn().mockRejectedValue(null);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();

      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).cause).toBeInstanceOf(Error);
        expect((error as any).cause?.message).toBe("null");
      }
    });

    it("should wrap undefined thrown value in Error before wrapping in DomainResolutionError", async () => {
      const resolver = vi.fn().mockRejectedValue(undefined);
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();

      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).cause).toBeInstanceOf(Error);
        expect((error as any).cause?.message).toBe("undefined");
      }
    });

    it("should catch synchronous throws from async resolver function", async () => {
      const resolver = vi.fn().mockImplementation(async () => {
        throw new Error("Sync error in async resolver");
      });
      const provider = new AuthClientProvider({
        domain: resolver,
        createAuthClient: createAuthClientMock
      });

      const headers = new Headers();

      try {
        await provider.forRequest(headers);
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(DomainResolutionError);
        expect((error as any).cause?.message).toBe(
          "Sync error in async resolver"
        );
      }
    });
  });

  describe("forDomainSync", () => {
    it("should create and cache client for domain", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      const client1 = provider.forDomainSync("domain1.auth0.com");
      expect(createAuthClientMock).toHaveBeenCalledWith("domain1.auth0.com");
      expect(client1).toBe(mockAuthClient);

      // Call again - should use cached
      const client2 = provider.forDomainSync("domain1.auth0.com");
      expect(client2).toBe(client1);
      // Still only 2 calls total (1 from constructor, 1 from forDomainSync)
      expect(createAuthClientMock).toHaveBeenCalledTimes(2);
    });

    it("should handle multiple domains with LRU eviction", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      // Create 101 clients (MAX_DOMAIN_CLIENTS is 100)
      const clients = [];
      for (let i = 0; i < 101; i++) {
        const domain = `domain${i}.auth0.com`;
        const client = provider.forDomainSync(domain);
        clients.push({ domain, client });
      }

      // First domain should be evicted
      const evictedDomain = "domain0.auth0.com";
      createAuthClientMock.mockClear();
      createAuthClientMock.mockReturnValue(mockAuthClient);

      const _client = provider.forDomainSync(evictedDomain);
      expect(createAuthClientMock).toHaveBeenCalledWith(evictedDomain);
    });

    it("should validate domain in forDomainSync", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      expect(() => provider.forDomainSync("invalid.local")).toThrow();
    });

    it("should use LRU behavior: access promotes to end", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      // Fill cache to near capacity (MAX_DOMAIN_CLIENTS is 100, 1 from constructor)
      // Create 99 domains to nearly fill the cache
      const clients: { [key: string]: any } = {};
      for (let i = 0; i < 99; i++) {
        const domain = `domain${i}.auth0.com`;
        clients[domain] = provider.forDomainSync(domain);
      }

      const lastCallCount = createAuthClientMock.mock.calls.length;

      // Now we have 100 clients (1 from constructor + 99 added)
      // Add client A (should be oldest, and will be candidate for eviction)
      const clientA = provider.forDomainSync("domain-a.auth0.com");
      // This should evict the oldest (constructor domain)
      expect(createAuthClientMock).toHaveBeenCalledTimes(lastCallCount + 1);

      // Access A - should promote it to end
      const clientAAgain = provider.forDomainSync("domain-a.auth0.com");
      expect(clientAAgain).toBe(clientA);
      // No new creation
      expect(createAuthClientMock).toHaveBeenCalledTimes(lastCallCount + 1);

      // Access first added domain (domain0) - check if still cached
      createAuthClientMock.mockClear();
      createAuthClientMock.mockReturnValue(mockAuthClient);
      const _client0Again = provider.forDomainSync("domain0.auth0.com");
      // domain0 should still be cached (not yet evicted)
      expect(createAuthClientMock).not.toHaveBeenCalled();

      // Now add more domains to trigger eviction
      // Add 101 more domains to evict everything older than current
      for (let i = 99; i < 200; i++) {
        provider.forDomainSync(`domainNew${i}.auth0.com`);
      }

      // Now domainA should be evicted (was promoted but is now very old)
      createAuthClientMock.mockClear();
      createAuthClientMock.mockReturnValue(mockAuthClient);
      const _clientAEvicted = provider.forDomainSync("domain-a.auth0.com");
      // Since A was evicted, should need recreation
      expect(createAuthClientMock).toHaveBeenCalledWith("domain-a.auth0.com");
    });
  });

  describe("mode detection", () => {
    it("should detect static mode", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      expect(provider.isResolverMode).toBe(false);
    });

    it("should detect resolver mode", () => {
      const provider = new AuthClientProvider({
        domain: () => Promise.resolve("example.auth0.com"),
        createAuthClient: createAuthClientMock
      });

      expect(provider.isResolverMode).toBe(true);
    });
  });

  describe("getters", () => {
    it("should return configuredDomain in static mode", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      expect(provider.configuredDomain).toBe("example.auth0.com");
    });

    it("should return undefined for configuredDomain in resolver mode", () => {
      const provider = new AuthClientProvider({
        domain: () => Promise.resolve("example.auth0.com"),
        createAuthClient: createAuthClientMock
      });

      expect(provider.configuredDomain).toBeUndefined();
    });

    it("should return isResolverMode as true in resolver mode", () => {
      const provider = new AuthClientProvider({
        domain: () => Promise.resolve("example.auth0.com"),
        createAuthClient: createAuthClientMock
      });

      expect(provider.isResolverMode).toBe(true);
    });

    it("should return isResolverMode as false in static mode", () => {
      const provider = new AuthClientProvider({
        domain: "example.auth0.com",
        createAuthClient: createAuthClientMock
      });

      expect(provider.isResolverMode).toBe(false);
    });
  });
});
