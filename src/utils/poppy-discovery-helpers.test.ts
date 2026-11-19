import { afterEach, describe, expect, it, vi } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import type { PoppyConfig } from "../types/poppy.js";
import { buildPoppyDiscoveryDocuments } from "./poppy-discovery-helpers.js";

// The poppy.json written by `auth0 poppy config`.
const validConfig: PoppyConfig = {
  protocol_version: "1.0",
  organization: { name: "Fernway", domain: "fernway.com" },
  auth: {
    issuer: "https://auth.fernway.com/",
    scopes: {
      "orders:write": "Place orders",
      "returns:write": "Start a return"
    }
  },
  web: {
    browser_session_endpoint:
      "https://auth.fernway.com/poppy/web-client-id/browser-session"
  }
};

const withDomain = (domain: unknown): PoppyConfig =>
  ({
    ...validConfig,
    organization: { ...validConfig.organization, domain }
  }) as PoppyConfig;

const withIssuer = (issuer: unknown): PoppyConfig =>
  ({ ...validConfig, auth: { ...validConfig.auth, issuer } }) as PoppyConfig;

function expectInvalid(config: unknown, message: RegExp) {
  let error: unknown;
  try {
    buildPoppyDiscoveryDocuments(config as PoppyConfig);
  } catch (e) {
    error = e;
  }
  expect(error).toBeInstanceOf(InvalidConfigurationError);
  expect((error as InvalidConfigurationError).code).toBe(
    "invalid_configuration"
  );
  expect((error as Error).message).toMatch(message);
}

describe("buildPoppyDiscoveryDocuments", () => {
  it("serves poppy.json exactly as written, including fields the SDK doesn't know", () => {
    const config = {
      ...validConfig,
      apis: [{ type: "openapi", url: "x", description: "Carts" }],
      tasks: { endpoint: "https://fernway.com/poppy/tasks" },
      future_field: { anything: true }
    };

    const { poppy } = buildPoppyDiscoveryDocuments(config);

    expect(poppy).toEqual(config);
  });

  it("builds the protected resource metadata from organization.domain and auth.issuer", () => {
    const { protectedResource } = buildPoppyDiscoveryDocuments(validConfig);

    expect(protectedResource).toEqual({
      resource: "https://fernway.com",
      authorization_servers: ["https://auth.fernway.com/"]
    });
  });

  it("keeps a port other than 443 in the protected resource", () => {
    const { protectedResource } = buildPoppyDiscoveryDocuments(
      withDomain("fernway.com:8443")
    );

    expect(protectedResource.resource).toBe("https://fernway.com:8443");
  });

  describe("validation", () => {
    it.each([
      ["no config", undefined],
      ["a config without organization", { auth: validConfig.auth }],
      ["a config without auth", { organization: validConfig.organization }]
    ])("rejects %s", (_case, config) => {
      expectInvalid(
        config,
        /expected the poppy\.json written by auth0 poppy config/
      );
    });

    it.each([
      ["a scheme", "https://fernway.com"],
      ["a path", "fernway.com/shop"],
      ["a trailing slash", "fernway.com/"],
      ["credentials", "user@fernway.com"],
      ["an empty string", ""],
      ["a missing domain", undefined]
    ])("rejects an organization.domain with %s", (_case, domain) => {
      expectInvalid(withDomain(domain), /organization\.domain must/);
    });

    it("rejects a domain that isn't lowercase, and suggests the fix", () => {
      expectInvalid(
        withDomain("Fernway.COM"),
        /organization\.domain must be lowercase: use "fernway\.com"/
      );
    });

    it("rejects an internationalized domain that isn't in punycode, and suggests the fix", () => {
      expectInvalid(
        withDomain("bücher.de"),
        /ASCII \(punycode\) form: use "xn--bcher-kva\.de"/
      );
    });

    it.each([
      ["with an uppercase host", "https://AUTH.fernway.com/"],
      ["with the default port", "https://auth.fernway.com:443/"],
      ["with a path", "https://auth.fernway.com//"],
      ["with a longer path", "https://auth.fernway.com/tenant/"]
    ])("rejects an issuer %s", (_case, issuer) => {
      expectInvalid(
        withIssuer(issuer),
        /auth\.issuer must match Auth0's issuer exactly, such as "https:\/\/auth\.fernway\.com\/"/
      );
    });

    it("rejects the default port 443, and suggests the fix", () => {
      expectInvalid(
        withDomain("fernway.com:443"),
        /must not include the default port 443: use "fernway\.com"/
      );
    });

    it("rejects an issuer without the trailing slash, and suggests the fix", () => {
      expectInvalid(
        withIssuer("https://auth.fernway.com"),
        /including the trailing slash: use "https:\/\/auth\.fernway\.com\/"/
      );
    });

    it.each([
      ["not https", "http://auth.fernway.com/", /auth\.issuer must use https/],
      [
        "with a query or fragment",
        "https://auth.fernway.com/?x=1",
        /query or fragment/
      ],
      ["not a URL", "auth.fernway.com/", /auth\.issuer must be a valid URL/],
      ["missing", undefined, /auth\.issuer must be a non-empty string/]
    ])("rejects an auth.issuer %s", (_case, issuer, message) => {
      expectInvalid(withIssuer(issuer), message);
    });
  });

  describe("local mode", () => {
    afterEach(() => {
      vi.restoreAllMocks();
      vi.unstubAllEnvs();
    });

    it.each([
      ["localhost:3000", "http://localhost:3000"],
      ["127.0.0.1:3000", "http://127.0.0.1:3000"],
      ["[::1]:3000", "http://[::1]:3000"],
      ["shop.localhost", "http://shop.localhost"],
      ["localhost", "http://localhost"]
    ])(
      "allows %s outside production, with an http resource",
      (domain, resource) => {
        vi.spyOn(console, "warn").mockImplementation(() => {});

        const { protectedResource } = buildPoppyDiscoveryDocuments(
          withDomain(domain),
          { production: false }
        );

        expect(protectedResource.resource).toBe(resource);
      }
    );

    it("warns that local mode is for testing only", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

      buildPoppyDiscoveryDocuments(withDomain("localhost:3000"), {
        production: false
      });

      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0][0]).toMatch(/Poppy local mode/);
    });

    it("does not warn or relax anything for a public host", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

      const { protectedResource } = buildPoppyDiscoveryDocuments(validConfig, {
        production: false
      });

      expect(warn).not.toHaveBeenCalled();
      expect(protectedResource.resource).toBe("https://fernway.com");
    });

    it.each(["localhost:3000", "127.0.0.1", "shop.localhost"])(
      "rejects the local host %s in production",
      (domain) => {
        let error: unknown;
        try {
          buildPoppyDiscoveryDocuments(withDomain(domain), {
            production: true
          });
        } catch (e) {
          error = e;
        }
        expect(error).toBeInstanceOf(InvalidConfigurationError);
        expect((error as Error).message).toMatch(
          /is a local host, which is only allowed outside production/
        );
      }
    );

    it("defaults to NODE_ENV to decide whether it is production", () => {
      vi.stubEnv("NODE_ENV", "production");

      expect(() =>
        buildPoppyDiscoveryDocuments(withDomain("localhost"))
      ).toThrow(InvalidConfigurationError);
    });

    it("still rejects a path on a local host", () => {
      expectInvalid(
        withDomain("localhost:3000/shop"),
        /organization\.domain must be a bare host/
      );
    });
  });
});
