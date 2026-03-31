import { describe, expect, it, vi } from "vitest";

import { BackchannelLogoutError } from "../errors/index.js";
import { AuthClientProvider } from "./auth-client-provider.js";

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

    it("hasTrustedDomains is false in resolver mode without trustedDomains", () => {
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

  describe("BackchannelLogoutError", () => {
    it("backward compat: message-only form uses default code", () => {
      const error = new BackchannelLogoutError("custom message");
      expect(error.code).toEqual("backchannel_logout_error");
      expect(error.message).toEqual("custom message");
      expect(error.name).toEqual("BackchannelLogoutError");
    });

    it("backward compat: no args uses default message and code", () => {
      const error = new BackchannelLogoutError();
      expect(error.code).toEqual("backchannel_logout_error");
      expect(error.message).toContain("backchannel logout request");
      expect(error.name).toEqual("BackchannelLogoutError");
    });

    it("new form: code and message", () => {
      const error = new BackchannelLogoutError(
        "untrusted_issuer",
        "Issuer not in whitelist"
      );
      expect(error.code).toEqual("untrusted_issuer");
      expect(error.message).toEqual("Issuer not in whitelist");
    });

    it("new form: missing_trust_config code", () => {
      const error = new BackchannelLogoutError(
        "missing_trust_config",
        "trustedDomains not configured in resolver mode"
      );
      expect(error.code).toEqual("missing_trust_config");
    });

    it("new form: missing_iss_claim code", () => {
      const error = new BackchannelLogoutError(
        "missing_iss_claim",
        "iss claim required"
      );
      expect(error.code).toEqual("missing_iss_claim");
    });

    it("backward compat: empty string first arg still uses message form", () => {
      // Empty string should not be treated as code
      const error = new BackchannelLogoutError("", "message");
      expect(error.code).toEqual("backchannel_logout_error");
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
});
