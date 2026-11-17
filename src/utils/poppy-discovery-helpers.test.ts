import { afterEach, describe, expect, it, vi } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import type { PoppyConfig } from "../types/poppy.js";
import { buildPoppyDiscoveryDocuments } from "./poppy-discovery-helpers.js";

const validConfig: PoppyConfig = {
  protocolVersion: "0.3",
  domain: "fernway.com",
  issuer: "https://auth.fernway.com/",
  browserSessionEndpoint:
    "https://auth.fernway.com/poppy/web-client-id/browser-session",
  scopes: {
    "orders:write": "Place orders",
    "returns:write": "Start a return"
  },
  organizationName: "Fernway"
};

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
  it("builds poppy.json from the config", () => {
    const { poppy } = buildPoppyDiscoveryDocuments(validConfig);

    expect(poppy).toEqual({
      protocol_version: "0.3",
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
    });
  });

  it("builds the protected resource metadata from the config", () => {
    const { protectedResource } = buildPoppyDiscoveryDocuments(validConfig);

    expect(protectedResource).toEqual({
      resource: "https://fernway.com",
      authorization_servers: ["https://auth.fernway.com/"]
    });
  });

  it("includes the organization name and logo when set", () => {
    const { poppy } = buildPoppyDiscoveryDocuments({
      ...validConfig,
      organizationName: "Fernway",
      logoUri: "https://fernway.com/logo.png"
    });

    expect(poppy.organization).toEqual({
      name: "Fernway",
      domain: "fernway.com",
      logo_uri: "https://fernway.com/logo.png"
    });
  });

  it("serves scope hints, apis and unscoped when set", () => {
    const { poppy } = buildPoppyDiscoveryDocuments({
      ...validConfig,
      scopeHints: {
        "orders:write": { changes: "irreversible", personalData: true }
      },
      apis: [
        {
          type: "openapi",
          url: "https://api.fernway.com/openapi.json",
          description: "Orders and returns"
        }
      ],
      unscoped: true
    });

    expect(poppy.auth).toMatchObject({
      scope_hints: {
        "orders:write": { changes: "irreversible", personal_data: true }
      }
    });
    expect(poppy.apis).toEqual([
      {
        type: "openapi",
        url: "https://api.fernway.com/openapi.json",
        description: "Orders and returns"
      }
    ]);
    expect(poppy.web).toEqual({
      browser_session_endpoint:
        "https://auth.fernway.com/poppy/web-client-id/browser-session",
      unscoped: true
    });
  });

  it("omits auth.scopes when the config has none", () => {
    const { scopes: _scopes, ...withoutScopes } = validConfig;
    const { poppy } = buildPoppyDiscoveryDocuments(withoutScopes);

    expect(poppy.auth).toEqual({ issuer: "https://auth.fernway.com/" });
  });

  it("lowercases the domain in both documents", () => {
    const { poppy, protectedResource } = buildPoppyDiscoveryDocuments({
      ...validConfig,
      domain: "Fernway.COM"
    });

    expect((poppy.organization as { domain: string }).domain).toBe(
      "fernway.com"
    );
    expect(protectedResource.resource).toBe("https://fernway.com");
  });

  it("keeps URLs exactly as written", () => {
    const endpoint = "https://auth.fernway.com/poppy/id/browser-session";
    const { poppy } = buildPoppyDiscoveryDocuments({
      ...validConfig,
      browserSessionEndpoint: endpoint
    });

    expect(
      (poppy.web as { browser_session_endpoint: string })
        .browser_session_endpoint
    ).toBe(endpoint);
  });

  describe("validation", () => {
    it("rejects a missing config", () => {
      expectInvalid(undefined, /contents of auth0-poppy\.json/);
      expectInvalid(null, /contents of auth0-poppy\.json/);
    });

    it.each(["0.4", "1.0", "1.12"])(
      "serves protocol version %s as written",
      (protocolVersion) => {
        expect(
          buildPoppyDiscoveryDocuments(
            { ...validConfig, protocolVersion },
            { production: true }
          ).poppy.protocol_version
        ).toBe(protocolVersion);
      }
    );

    it.each([
      ["a patch number", "0.4.1"],
      ["a prefix", "v0.4"],
      ["no minor version", "1"],
      ["an empty string", ""]
    ])("rejects a protocol version with %s", (_case, protocolVersion) => {
      expectInvalid(
        { ...validConfig, protocolVersion },
        /protocolVersion must be a major\.minor version/
      );
    });

    it("rejects a protocol version that is not a string", () => {
      expectInvalid(
        { ...validConfig, protocolVersion: 0.4 },
        /protocolVersion must be .*, got number\./
      );
    });

    it.each([
      ["a scheme", "https://fernway.com"],
      ["a path", "fernway.com/shop"],
      ["a trailing slash", "fernway.com/"],
      ["credentials", "user@fernway.com"],
      ["an empty string", ""]
    ])("rejects a domain with %s", (_case, domain) => {
      expectInvalid({ ...validConfig, domain }, /domain must be/);
    });

    it("keeps a port other than 443 in domain and resource", () => {
      const { poppy, protectedResource } = buildPoppyDiscoveryDocuments({
        ...validConfig,
        domain: "fernway.com:8443"
      });

      expect(poppy.organization).toMatchObject({ domain: "fernway.com:8443" });
      expect(protectedResource.resource).toBe("https://fernway.com:8443");
    });

    it("rejects the default port 443, and suggests the fix", () => {
      expectInvalid(
        { ...validConfig, domain: "fernway.com:443" },
        /must not include the default port 443: use "fernway\.com"/
      );
    });

    it("rejects scope hints without both fields, or with an unknown change", () => {
      expectInvalid(
        { ...validConfig, scopeHints: { "orders:write": { changes: "none" } } },
        /scope hint "orders:write" must have changes/
      );
      expectInvalid(
        {
          ...validConfig,
          scopeHints: {
            "orders:write": { changes: "sometimes", personalData: true }
          }
        },
        /scope hint "orders:write" must have changes/
      );
      expectInvalid(
        { ...validConfig, scopeHints: ["orders:write"] },
        /scopeHints must be an object/
      );
    });

    it("rejects invalid apis and a non-boolean unscoped", () => {
      expectInvalid({ ...validConfig, apis: {} }, /apis must be an array/);
      expectInvalid(
        {
          ...validConfig,
          apis: [
            { type: "openapi", url: "https://api.fernway.com/openapi.json" }
          ]
        },
        /apis\[0\] must have a non-empty type and description/
      );
      expectInvalid(
        {
          ...validConfig,
          apis: [
            {
              type: "openapi",
              url: "http://api.fernway.com/openapi.json",
              description: "Orders"
            }
          ]
        },
        /apis\[0\]\.url must use https/
      );
      expectInvalid(
        { ...validConfig, unscoped: "yes" },
        /unscoped must be a boolean/
      );
    });

    it("rejects an issuer without the trailing slash, and suggests the fix", () => {
      expectInvalid(
        { ...validConfig, issuer: "https://auth.fernway.com" },
        /including the trailing slash: use "https:\/\/auth\.fernway\.com\/"/
      );
    });

    it("rejects an issuer that is not https", () => {
      expectInvalid(
        { ...validConfig, issuer: "http://auth.fernway.com/" },
        /issuer must use https/
      );
    });

    it("rejects an issuer with a query or fragment", () => {
      expectInvalid(
        { ...validConfig, issuer: "https://auth.fernway.com/?x=1" },
        /query or fragment/
      );
    });

    it("rejects an issuer that is not a URL", () => {
      expectInvalid(
        { ...validConfig, issuer: "auth.fernway.com/" },
        /issuer must be a valid URL/
      );
    });

    it("rejects a missing or non-https browserSessionEndpoint", () => {
      expectInvalid(
        { ...validConfig, browserSessionEndpoint: undefined },
        /browserSessionEndpoint must be a non-empty string/
      );
      expectInvalid(
        {
          ...validConfig,
          browserSessionEndpoint: "http://auth.fernway.com/poppy/id"
        },
        /browserSessionEndpoint must use https/
      );
    });

    it("rejects a scope without a description", () => {
      expectInvalid(
        { ...validConfig, scopes: { "orders:write": " " } },
        /scope "orders:write" must have a non-empty description/
      );
    });

    it("rejects scopes that are not an object", () => {
      expectInvalid(
        { ...validConfig, scopes: ["orders:write"] },
        /scopes must be an object/
      );
    });

    it("rejects a missing or empty organizationName and a non-https logoUri", () => {
      expectInvalid(
        { ...validConfig, organizationName: undefined },
        /organizationName must be a non-empty string/
      );
      expectInvalid(
        { ...validConfig, organizationName: "" },
        /organizationName must be a non-empty string/
      );
      expectInvalid(
        { ...validConfig, logoUri: "http://fernway.com/logo.png" },
        /logoUri must use https/
      );
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

        const { poppy, protectedResource } = buildPoppyDiscoveryDocuments(
          { ...validConfig, domain },
          { production: false }
        );

        expect((poppy.organization as { domain: string }).domain).toBe(domain);
        expect(protectedResource.resource).toBe(resource);
      }
    );

    it("warns that local mode is for testing only", () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

      buildPoppyDiscoveryDocuments(
        { ...validConfig, domain: "localhost:3000" },
        { production: false }
      );

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
          buildPoppyDiscoveryDocuments(
            { ...validConfig, domain },
            { production: true }
          );
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
        buildPoppyDiscoveryDocuments({ ...validConfig, domain: "localhost" })
      ).toThrow(InvalidConfigurationError);
    });

    it("still rejects a path on a local host", () => {
      expectInvalid(
        { ...validConfig, domain: "localhost:3000/shop" },
        /domain must be a bare host/
      );
    });
  });
});
