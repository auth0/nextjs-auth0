import { describe, expect, it, vi } from "vitest";

import { BackchannelLogoutError } from "../errors/index.js";
import { createSizeLimitedFetch } from "../utils/fetchUtils.js";
import { AuthClientProvider } from "./auth-client-provider.js";
import { AuthClient } from "./auth-client.js";

describe("BCLO Trust Validation", () => {
  describe("AuthClientProvider — Trust Configuration", () => {
    it("hasTrustedDomains is true when trustedDomains configured", () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(provider.hasTrustedDomains).toEqual(true);
    });

    it("hasTrustedDomains is false when trustedDomains not configured", () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(provider.hasTrustedDomains).toEqual(false);
    });
  });

  describe("AuthClientProvider — isTrustedDomain", () => {
    it("returns true for domain in static array", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com", "brand1.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(true);
      expect(await provider.isTrustedDomain("brand1.com")).toEqual(true);
    });

    it("returns false for domain not in static array", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("attacker.com")).toEqual(false);
    });

    it("case-insensitive domain comparison", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["AUTH.EXAMPLE.COM"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(true);
    });

    it("handles resolver function that returns domains", async () => {
      const resolverSpy = vi.fn(async () => ["auth.example.com", "brand1.com"]);
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: resolverSpy
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(true);
      expect(resolverSpy).toHaveBeenCalled();
    });

    it("handles resolver function returning empty array", async () => {
      const resolverSpy = vi.fn(async () => []);
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: resolverSpy
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(false);
    });

    it("handles resolver function that throws", async () => {
      const consoleWarnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => {});
      const resolverSpy = vi.fn(async () => {
        throw new Error("Database error");
      });
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: resolverSpy
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(false);
      expect(consoleWarnSpy).toHaveBeenCalled();

      consoleWarnSpy.mockRestore();
    });

    it("returns false when not configured", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(false);
    });

    it("returns false for invalid domain format", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      // Invalid formats should return false
      expect(await provider.isTrustedDomain("192.168.1.1")).toEqual(false);
      expect(await provider.isTrustedDomain("localhost")).toEqual(false);
    });

    it("skips invalid entries in static array", async () => {
      const consoleWarnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com", "localhost", "brand1.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      // Valid entries should work
      expect(await provider.isTrustedDomain("auth.example.com")).toEqual(true);
      expect(await provider.isTrustedDomain("brand1.com")).toEqual(true);
      // Invalid entries were skipped
      expect(await provider.isTrustedDomain("localhost")).toEqual(false);

      consoleWarnSpy.mockRestore();
    });
  });

  describe("AuthClientProvider — resolveClientForBclo", () => {
    it("returns ok with client for trusted domain", async () => {
      const mockClient = {} as AuthClient;
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com"]
        },
        createAuthClient: () => mockClient
      });

      const result = await provider.resolveClientForBclo("auth.example.com");
      expect(result.ok).toEqual(true);
      if (result.ok) {
        expect(result.client).toBeDefined();
      }
    });

    it("returns not_configured when trustedDomains missing", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      const result = await provider.resolveClientForBclo("auth.example.com");
      expect(result).toEqual({ ok: false, reason: "not_configured" });
    });

    it("returns untrusted for domain not in trust list", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      const result = await provider.resolveClientForBclo("attacker.com");
      expect(result).toEqual({ ok: false, reason: "untrusted" });
    });

    it("returns untrusted for invalid domain format", async () => {
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: ["auth.example.com"]
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });

      const result = await provider.resolveClientForBclo("192.168.1.1");
      expect(result).toEqual({ ok: false, reason: "untrusted" });
    });

    it("works with resolver function for trusted domains", async () => {
      const mockClient = {} as AuthClient;
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains: async () => ["auth.example.com", "brand1.com"]
        },
        createAuthClient: () => mockClient
      });

      const result = await provider.resolveClientForBclo("brand1.com");
      expect(result.ok).toEqual(true);
    });
  });

  describe("BackchannelLogoutError", () => {
    it("uses default code and custom message", () => {
      const error = new BackchannelLogoutError("custom message");
      expect(error.code).toEqual("backchannel_logout_error");
      expect(error.message).toEqual("custom message");
      expect(error.name).toEqual("BackchannelLogoutError");
    });

    it("uses default message when none provided", () => {
      const error = new BackchannelLogoutError();
      expect(error.code).toEqual("backchannel_logout_error");
      expect(error.message).toContain("backchannel logout request");
      expect(error.name).toEqual("BackchannelLogoutError");
    });
  });

  describe("TrustedDomainsResolver Types", () => {
    it("accepts static array of domains", () => {
      const trustedDomains: string[] = ["auth.example.com", "brand1.com"];
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });
      expect(provider.hasTrustedDomains).toEqual(true);
    });

    it("accepts resolver function returning domains", () => {
      const trustedDomains = async () => ["auth.example.com"];
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });
      expect(provider.hasTrustedDomains).toEqual(true);
    });

    it("accepts sync resolver returning domains", () => {
      const trustedDomains = () => ["auth.example.com"];
      const provider = new AuthClientProvider({
        domain: () => "auth.example.com",
        backchannelLogout: {
          trustedDomains
        },
        createAuthClient: () => {
          throw new Error("should not be called");
        }
      });
      expect(provider.hasTrustedDomains).toEqual(true);
    });
  });

  describe("Response Body Size Limit", () => {
    const maxBodySize = AuthClient.MAX_RESPONSE_BODY_SIZE;

    it("rejects responses with Content-Length exceeding limit", async () => {
      const oversizedLength = maxBodySize + 1;
      const mockFetch = vi.fn().mockResolvedValue(
        new Response("x", {
          headers: { "content-length": String(oversizedLength) }
        })
      );

      const wrappedFetch = createSizeLimitedFetch(mockFetch, maxBodySize);
      await expect(wrappedFetch("https://example.com")).rejects.toThrow(
        /Response body too large/
      );
    });

    it("allows responses within size limit", async () => {
      const body = "small response";
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(body, {
          headers: { "content-length": String(body.length) }
        })
      );

      const wrappedFetch = createSizeLimitedFetch(mockFetch, maxBodySize);
      const response = await wrappedFetch("https://example.com");
      expect(response.status).toEqual(200);
      expect(await response.text()).toEqual(body);
    });

    it("rejects chunked responses exceeding limit during streaming", async () => {
      const oversizedBody = "x".repeat(maxBodySize + 1);
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(oversizedBody) // No content-length header
      );

      const wrappedFetch = createSizeLimitedFetch(mockFetch, maxBodySize);
      const response = await wrappedFetch("https://example.com");
      await expect(response.text()).rejects.toThrow(/Response body too large/);
    });
  });
});
